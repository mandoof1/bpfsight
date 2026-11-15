//! Live eBPF tests: each built-in detection is triggered on the real host and
//! asserted via the alerts table. Requires root and kernel BTF; skipped
//! (explicitly reported, not silently) otherwise.
//!
//! Run: sudo cargo test --test live_detect -- --nocapture

use bpfsight::{db_conn, run_until, Options};
use std::os::unix::fs::PermissionsExt;
use rusqlite::Connection;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn have_btf() -> bool {
    std::path::Path::new("/sys/kernel/btf/vmlinux").exists()
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[derive(Debug)]
struct Trig {
    rule: &'static str,
    detail_needle: &'static str,
}

#[test]
fn all_builtin_detections_fire() {
    if !have_btf() || !is_root() {
        eprintln!("SKIP live_detect: needs root + /sys/kernel/btf/vmlinux");
        return;
    }
    let dir = std::env::temp_dir().join(format!("bpfsight-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let payload = dir.join("bpfsight-test-payload");
    std::fs::copy("/bin/true", &payload).unwrap();
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o755)).unwrap();
    let nc = dir.join("nc");
    std::fs::copy("/bin/true", &nc).unwrap();
    std::fs::set_permissions(&nc, std::fs::Permissions::from_mode(0o755)).unwrap();

    let db = dir.join("live.sqlite");
    let opts = Options {
        db: db.clone(),
        jsonl: Some(dir.join("events.jsonl")),
        alerts_jsonl: Some(dir.join("alerts.jsonl")),
        ..Default::default()
    };

    // background trigger thread while the sensor captures
    let dir2 = dir.clone();
    let payload2 = payload.clone();
    let nc2 = nc.clone();
    let trig_script = format!(
        r#"
sleep 1.2
bash -i -c true 2>/dev/null &
sleep 0.2
bash -c 'true <> /dev/tcp/127.0.0.1/4455' 2>/dev/null
sleep 0.2
{nc} -e /bin/sh 127.0.0.1 4456 2>/dev/null
sleep 0.2
sh -c 'curl -s http://127.0.0.1:1/ | sh' 2>/dev/null
sleep 0.2
echo QQ | base64 -d 2>/dev/null
sleep 0.2
echo '*/5 * * * * root true' > /etc/cron.d/bpfsight-test
sleep 0.2
printf '[Service]\nExecStart=/bin/true\n' > /etc/systemd/system/bpfsight-test.service
sleep 0.2
cp /root/.bashrc /tmp/bpfsight-bashrc.bak 2>/dev/null || : > /tmp/bpfsight-bashrc.bak
printf '%s\n# bpfsight-test\n' "$(cat /root/.bashrc 2>/dev/null)" > /root/.bashrc
sleep 0.2
python3 -c 'import os;os.setresuid(65534,65534,-1);os.setresuid(0,0,0)' 
sleep 0.2
python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",31337));s.listen(1);c=socket.socket();c.connect(("127.0.0.1",31337));a,lr=c.accept();c.send(b"hi");a.recv(9)'
sleep 0.2
dig 0123456789abcdef0123456789abcdef.t.bpfsight.test +tries=1 +timeout=1 >/dev/null 2>&1
sleep 0.2
MOD=$(find /lib/modules/$(uname -r) -name '*.ko*' 2>/dev/null | head -1)
MOD=$(basename "$MOD" | sed 's/\.ko.*//')
if ! lsmod | grep -qw "$MOD"; then modprobe "$MOD" && modprobe -r "$MOD"; else modprobe -f "$MOD" && modprobe -r "$MOD"; fi
sleep 0.2
id >/dev/null
sleep 0.2
{payload}
sleep 0.8
"#,
        nc = nc2.display(),
        payload = payload2.display()
    );
    std::fs::write(dir2.join("trig.sh"), &trig_script).unwrap();
    let trigger = std::process::Command::new("bash")
        .arg(dir2.join("trig.sh"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let stop = AtomicBool::new(false);
    let summary = run_until(&opts, &stop, Some(Duration::from_secs(8)), |_| {}).unwrap();
    let _ = trigger.wait_with_output();
    assert!(summary.events > 50, "expected a busy capture, got {}", summary.events);

    std::thread::sleep(Duration::from_millis(300)); // final WAL flush

    let con = db_conn(&db).unwrap();
    let mut missing = Vec::new();
    for t in TRIGGERS {
        let n: i64 = con
            .query_row("SELECT COUNT(*) FROM alerts WHERE rule=?1", [t.rule], |r| r.get(0))
            .unwrap();
        if n == 0 {
            missing.push(t.rule);
            continue;
        }
        let hit: i64 = con
            .query_row(
                "SELECT COUNT(*) FROM alerts WHERE rule=?1 AND detail LIKE ?",
                rusqlite::params![t.rule, format!("%{}%", t.detail_needle)],
                |r| r.get(0),
            )
            .unwrap();
        if hit == 0 {
            missing.push(t.rule);
        }
    }
    assert!(missing.is_empty(), "detections that did not fire correctly: {missing:?}");

    // sanity: alerts JSONL mirrors the DB
    let alerts_lines = std::fs::read_to_string(dir.join("alerts.jsonl")).unwrap();
    let db_alerts: i64 = con.query_row("SELECT COUNT(*) FROM alerts", [], |r| r.get(0)).unwrap();
    assert_eq!(alerts_lines.lines().count() as i64, db_alerts);

    // cleanup
    for f in [
        "/etc/cron.d/bpfsight-test",
        "/etc/systemd/system/bpfsight-test.service",
    ] {
        let _ = std::fs::remove_file(f);
    }
    if let Ok(bak) = std::fs::read("/tmp/bpfsight-bashrc.bak") {
        let _ = std::fs::write("/root/.bashrc", bak);
    }
    let _ = std::fs::remove_dir_all(&dir);
    eprintln!("live capture ok: {} events, {} alerts", summary.events, summary.alerts);
}

// detail needles double as the assertion on captured fields
static TRIGGERS: &[Trig] = &[
    Trig { rule: "revshell-shell-i", detail_needle: "bash" },
    Trig { rule: "revshell-devtcp", detail_needle: "/dev/tcp" },
    Trig { rule: "revshell-nc-exec", detail_needle: "-e" },
    Trig { rule: "download-pipe-shell", detail_needle: "curl" },
    Trig { rule: "base64-decode-exec", detail_needle: "base64" },
    Trig { rule: "persist-cron", detail_needle: "/etc/cron.d/bpfsight-test" },
    Trig { rule: "persist-systemd-unit", detail_needle: "bpfsight-test.service" },
    Trig { rule: "persist-shellrc", detail_needle: ".bashrc" },
    Trig { rule: "priv-escalation", detail_needle: "-> 0" },
    Trig { rule: "unusual-outbound-port", detail_needle: "31337" },
    Trig { rule: "dns-long-name", detail_needle: "bpfsight.test" },
    Trig { rule: "module-load", detail_needle: "" },
    Trig { rule: "recon-tools", detail_needle: "/usr/bin/id" },
    Trig { rule: "exec-from-temp", detail_needle: "bpfsight-test-payload" },
];

#[test]
fn connect_event_has_port_and_addr() {
    // covered by unusual-outbound-port trigger above, but assert event fields directly
    if !have_btf() || !is_root() {
        eprintln!("SKIP connect field test");
        return;
    }
    let dir = std::env::temp_dir().join(format!("bpfsight-conn-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("c.sqlite");
    let opts = Options { db: db.clone(), ..Default::default() };
    let mut trigger = Command::new("python3")
        .arg("-c")
        .arg("import socket,time;time.sleep(1.2);s=socket.socket();s.bind(('127.0.0.1',41337));s.listen(1);c=socket.socket();c.connect(('127.0.0.1',41337));a,l=c.accept();c.send(b'x');a.recv(4)")
        .spawn()
        .unwrap();
    let stop = AtomicBool::new(false);
    run_until(&opts, &stop, Some(Duration::from_secs(4)), |_| {}).unwrap();
    let _ = trigger.wait();
    let con = db_conn(&db).unwrap();
    let row = con.query_row(
        "SELECT comm,daddr,dport,ret FROM events WHERE kind='connect' AND dport=41337",
        [],
        |r| -> rusqlite::Result<(String, String, i64, i64)> {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        },
    );
    match row {
        Ok((comm, daddr, dport, ret)) => {
            assert_eq!(daddr, "127.0.0.1");
            assert_eq!(dport, 41337);
            assert_eq!(comm, "python3");
            assert!(ret >= 0); // loopback connect succeeded
        }
        Err(e) => panic!("connect event with port 41337 not captured: {e}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exec_event_carries_path_args_pid() {
    if !have_btf() || !is_root() {
        eprintln!("SKIP exec field test");
        return;
    }
    let dir = std::env::temp_dir().join(format!("bpfsight-exec-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("e.sqlite");
    let opts = Options { db: db.clone(), ..Default::default() };
    let marker = format!("bpfsight-marker-{}", std::process::id());
    let mut _t = Command::new("bash").arg("-c").arg(format!("sleep 1.2; /usr/bin/true {marker}")).spawn().unwrap();
    let stop = AtomicBool::new(false);
    run_until(&opts, &stop, Some(Duration::from_secs(4)), |_| {}).unwrap();
    let _ = _t.wait();
    let con = db_conn(&db).unwrap();
    let (path, args, pid): (String, String, i64) = con
        .query_row(
            "SELECT path,args,pid FROM events WHERE kind='exec' AND args LIKE ?",
            [format!("%{marker}%")],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("exec event with marker args not captured");
    assert!(path.ends_with("/bin/true") || path.ends_with("true"), "path={path}");
    assert!(args.contains(&marker));
    assert!(pid > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn no_btf_graceful_error() {
    // the documented failure mode: point the BTF path at a missing file and
    // run_until must refuse cleanly (exit-2 class error, no panic, no stub).
    std::env::set_var("BPFSIGHT_BTF_PATH", "/nonexistent-btf-for-test");
    let dir = std::env::temp_dir().join(format!("bpfsight-nobtf-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let opts = Options { db: dir.join("x.sqlite"), ..Default::default() };
    let stop = AtomicBool::new(false);
    let r = run_until(&opts, &stop, Some(Duration::from_millis(100)), |_| {});
    std::env::remove_var("BPFSIGHT_BTF_PATH");
    let err = r.expect_err("run_until must fail without BTF");
    assert!(err.contains("CONFIG_DEBUG_INFO_BTF"), "unhelpful error: {err}");
    assert!(err.contains("/nonexistent-btf-for-test"), "must name the path: {err}");
    let _ = std::fs::remove_dir_all(&dir);
}
