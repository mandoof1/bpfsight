// Minimal aya loader for probe.bpf.o — the pairing smoke test.
use aya::maps::RingBuf;
use aya::programs::RawTracePoint;
use aya::Bpf;

fn main() -> anyhow::Result<()> {
    let mut bpf = Bpf::load(include_bytes!("../probe.bpf.o"))?;
    let prog: &mut RawTracePoint = bpf.program_mut("handle_exec").unwrap().try_into()?;
    prog.load()?;
    prog.attach("sched_process_exec")?;
    println!("probe attached to sched_process_exec; run /bin/true elsewhere");
    let mut rb = RingBuf::try_from(bpf.map_mut("rb").unwrap())?;
    let mut got = 0;
    while got < 3 {
        while let Some(item) = rb.next() {
            let e: &[u8] = &item;
            let pid = u32::from_le_bytes(e[8..12].try_into().unwrap());
            let comm = String::from_utf8_lossy(&e[12..28])
                .trim_matches('\0')
                .to_string();
            println!("exec: pid={pid} comm={comm}");
            got += 1;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!("PROBE-OK");
    Ok(())
}
