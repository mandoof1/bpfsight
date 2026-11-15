//! bpfsight: eBPF host sensor. Loads the CO-RE object, streams events from
//! the ring buffer to JSONL + SQLite, and runs the detection engine live.

pub mod detect;
pub mod events;
pub mod store;

pub use detect::Detection;
pub use events::{Event, RawEvent};

use detect::{builtins, load_yaml_rules, Iocs, Matcher};
use rusqlite::Connection;
use std::collections::BTreeMap;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub const BPF_OBJECT: &[u8] = include_bytes!("../bpf/bpfsight.bpf.o");

#[derive(Default)]
pub struct Options {
    pub db: PathBuf,
    pub jsonl: Option<PathBuf>,
    pub alerts_jsonl: Option<PathBuf>,
    pub rules_dir: Option<PathBuf>,
    pub iocs: Option<PathBuf>,
    pub quiet: bool,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub events: u64,
    pub kernel_submitted: u64,
    pub ring_full: u64,
    pub seq_drops: u64,
    pub alerts: u64,
    pub by_kind: BTreeMap<String, u64>,
}

fn boot_realtime_ns() -> u64 {
    unsafe {
        let mut rt = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let mut mt = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut rt);
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mt);
        (rt.tv_sec as i64 - mt.tv_sec as i64) as u64 * 1_000_000_000
            + (rt.tv_nsec - mt.tv_nsec).rem_euclid(1_000_000_000) as u64
    }
}

pub fn btf_path() -> PathBuf {
    // override for the documented no-BTF failure path (also usable as a
    // diagnostic on odd kernels); defaults to the standard location
    match std::env::var("BPFSIGHT_BTF_PATH") {
        Ok(p) => PathBuf::from(p),
        Err(_) => PathBuf::from("/sys/kernel/btf/vmlinux"),
    }
}

pub fn btf_available() -> bool {
    btf_path().exists()
}

fn load_and_attach() -> Result<aya::Ebpf, String> {
    let mut bpf = aya::Ebpf::load(BPF_OBJECT).map_err(|e| format!("bpf load failed: {e:?}"))?;
    let btf = aya::Btf::from_sys_fs().map_err(|e| format!("btf parse: {e}"))?;

    for (name, tp) in [
        ("handle_exec", "sched_process_exec"),
        ("handle_fork", "sched_process_fork"),
        ("handle_modload", "module_load"),
    ] {
        let p: &mut aya::programs::RawTracePoint = bpf
            .program_mut(name)
            .ok_or(format!("program {name} missing"))?
            .try_into()
            .map_err(|e| format!("{name}: {e}"))?;
        p.load().map_err(|e| format!("{name} load: {e}"))?;
        p.attach(tp).map_err(|e| format!("{name} attach {tp}: {e}"))?;
    }
    for (name, class, tp) in [
        ("tp_enter_connect", "syscalls", "sys_enter_connect"),
        ("tp_exit_connect", "syscalls", "sys_exit_connect"),
        ("tp_enter_accept", "syscalls", "sys_enter_accept"),
        ("tp_exit_accept", "syscalls", "sys_exit_accept"),
        ("tp_enter_accept4", "syscalls", "sys_enter_accept4"),
        ("tp_exit_accept4", "syscalls", "sys_exit_accept4"),
    ] {
        let p: &mut aya::programs::TracePoint = bpf
            .program_mut(name)
            .ok_or(format!("program {name} missing"))?
            .try_into()
            .map_err(|e| format!("{name}: {e}"))?;
        p.load().map_err(|e| format!("{name} load: {e}"))?;
        p.attach(class, tp)
            .map_err(|e| format!("{name} attach {class}:{tp}: {e}"))?;
    }
    for (name, target) in [
        ("path_openat_exit", "path_openat"),
    ] {
        let p: &mut aya::programs::fexit::FExit = bpf
            .program_mut(name)
            .ok_or(format!("program {name} missing"))?
            .try_into()
            .map_err(|e| format!("{name}: {e}"))?;
        p.load(target, &btf).map_err(|e| format!("{name} load {target}: {e}"))?;
        p.attach().map_err(|e| format!("{name} attach: {e}"))?;
    }
    for (name, target) in [
        ("path_openat_enter", "path_openat"),
        ("cred_enter", "commit_creds"),
        ("execve_enter", "__x64_sys_execve"),
        ("execveat_enter", "__x64_sys_execveat"),
    ] {
        let p: &mut aya::programs::fentry::FEntry = bpf
            .program_mut(name)
            .ok_or(format!("program {name} missing"))?
            .try_into()
            .map_err(|e| format!("{name}: {e}"))?;
        p.load(target, &btf).map_err(|e| format!("{name} load {target}: {e}"))?;
        p.attach().map_err(|e| format!("{name} attach: {e}"))?;
    }
    Ok(bpf)
}

/// Streams events until `stop` is set or `max` elapses, writing SQLite (+JSONL
/// when configured) and firing detections as they match.
pub fn run_until(
    opts: &Options,
    stop: &AtomicBool,
    max: Option<Duration>,
    mut on_alert: impl FnMut(&Detection),
) -> Result<Summary, String> {
    let bp = btf_path();
    if !btf_available() {
        return Err(format!(
            "no BTF at {} - bpfsight needs CONFIG_DEBUG_INFO_BTF; \
             rebuild the kernel with it, or run on a distro kernel that ships it",
            bp.display()
        ));
    }

    let mut store = store::Store::open(&opts.db.to_string_lossy()).map_err(|e| e.to_string())?;
    let mut jsonl = opts
        .jsonl
        .as_ref()
        .map(|p| std::fs::File::create(p))
        .transpose()
        .map_err(|e| format!("jsonl: {e}"))?
        .map(BufWriter::new);
    let mut alerts_jsonl = opts
        .alerts_jsonl
        .as_ref()
        .map(|p| std::fs::File::create(p))
        .transpose()
        .map_err(|e| format!("alerts: {e}"))?
        .map(BufWriter::new);

    let mut rules: Vec<Box<dyn Matcher>> =
        builtins().into_iter().map(|b| Box::new(b) as Box<dyn Matcher>).collect();
    if let Some(dir) = &opts.rules_dir {
        rules.extend(load_yaml_rules(dir).into_iter().map(|r| Box::new(r) as Box<dyn Matcher>));
    }
    if let Some(ioc) = &opts.iocs {
        rules.push(Box::new(Iocs::load(ioc).map_err(|e| format!("iocs: {e}"))?));
    }

    let mut bpf = load_and_attach()?;
    let mut out = Summary::default();

    {
        let map = bpf.map_mut("rb").ok_or("rb map missing")?;
        let mut rb = aya::maps::RingBuf::try_from(map).map_err(|e| format!("rb: {e}"))?;
        let boot_rt_ns = boot_realtime_ns();
        let mut next_seq: Option<u64> = None;

        let t0 = Instant::now();
        let mut last_flush = Instant::now();
        loop {
            let mut got = 0;
            while let Some(item) = rb.next() {
                let item: &[u8] = &item;
                let raw = match RawEvent::decode(item) {
                    Some(r) => r,
                    None => continue,
                };
                if let Some(ns) = next_seq {
                    if raw.seq > ns + 1 {
                        out.seq_drops += raw.seq - ns - 1;
                    }
                }
                next_seq = Some(raw.seq);
                let ev = Event::from_raw(&raw, boot_rt_ns + raw.ts);
                out.events += 1;
                *out.by_kind.entry(ev.kind.to_string()).or_insert(0) += 1;
                if let Some(w) = jsonl.as_mut() {
                    serde_json::to_writer(&mut *w, &ev).ok();
                    w.write_all(b"\n").ok();
                }
                store.event(&ev).map_err(|e| e.to_string())?;
                for d in detect::run_rules(&rules, &ev) {
                    out.alerts += 1;
                    let row = store::AlertRow {
                        ts: ev.ts.clone(),
                        rule: d.rule.clone(),
                        title: d.title.clone(),
                        severity: d.severity,
                        pid: ev.pid,
                        comm: ev.comm.clone(),
                        detail: d.detail.clone(),
                    };
                    store.alert(&row).map_err(|e| e.to_string())?;
                    if let Some(w) = alerts_jsonl.as_mut() {
                        serde_json::to_writer(&mut *w, &row).ok();
                        w.write_all(b"\n").ok();
                    }
                    on_alert(&d);
                }
                got += 1;
                if got >= 1024 {
                    break;
                }
            }
            if got == 0 {
                std::thread::sleep(Duration::from_millis(20));
            }
            if last_flush.elapsed() > Duration::from_millis(500) {
                if let Some(w) = jsonl.as_mut() {
                    w.flush().ok();
                }
                if let Some(w) = alerts_jsonl.as_mut() {
                    w.flush().ok();
                }
                store.commit().map_err(|e| e.to_string())?;
                last_flush = Instant::now();
            }
            if stop.load(Ordering::Relaxed) {
                break;
            }
            if let Some(m) = max {
                if t0.elapsed() >= m {
                    break;
                }
            }
        }
        if let Some(w) = jsonl.as_mut() {
            w.flush().ok();
        }
        if let Some(w) = alerts_jsonl.as_mut() {
            w.flush().ok();
        }
        store.commit().map_err(|e| e.to_string())?;
    }
    drop(store.con);

    if let Some(m) = bpf.map("stats") {
        if let Ok(arr) = aya::maps::Array::<_, u64>::try_from(m) {
            out.kernel_submitted = arr.get(&0u32, 0).unwrap_or(0);
            out.ring_full = arr.get(&1u32, 0).unwrap_or(0);
            out.seq_drops += out.kernel_submitted.saturating_sub(out.events);
        }
    }
    Ok(out)
}

pub fn db_conn(path: &Path) -> Result<Connection, String> {
    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("open {}: {e}", path.display()))
}

pub fn db_stats(path: &Path) -> Result<String, String> {
    let con = db_conn(path)?;
    store::stats(&con).map_err(|e| e.to_string())
}

/// Blocks SIGINT on a helper thread: first Ctrl-C sets `stop`, second exits.
pub fn install_ctrlc(stop: &std::sync::Arc<AtomicBool>) {
    // block SIGINT on the calling thread first so no thread takes the default
    // action; threads spawned afterwards inherit the mask.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let stop = stop.clone();
    let handle = std::thread::spawn(move || {
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGINT);
            let mut n = 0u32;
            let mut info: libc::siginfo_t = std::mem::zeroed();
            while libc::sigwaitinfo(&set, &mut info) > 0 {
                n += 1;
                if n >= 2 {
                    std::process::exit(130);
                }
                stop.store(true, Ordering::Relaxed);
            }
        }
    });
    let _ = handle;
}
