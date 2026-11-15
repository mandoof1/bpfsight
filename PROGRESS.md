# bpfsight - PROGRESS

## State: DONE (2026-11-15) - shipped as https://github.com/mandoof1/bpfsight

Everything in the card's Definition of Done is implemented and evidenced;
nothing is stubbed.

## What was built
- CO-RE eBPF sensor (aya + Rust, single binary): exec(+argv)/fork/connect/
  accept/open(full flags)/cred/module -> ring buffer -> JSONL + SQLite.
- 14 built-in detections, sigma-style YAML rules, IOC lists (comm/ip/path).
- Drop accounting: kernel ring-full counter + userspace seq-gap check;
  visible in the `run` summary and in `stats`.
- `rules` inventory, `stats` accounting, graceful Ctrl-C (1st = stop, 2nd = exit).
- probe/ smoke test proving raw-tracepoint+ringbuf pairing on kernel
  7.3.3-1-cachyos before the main object was written.

## Hard-won kernel facts (recorded so future kernels get checked, not assumed)
- `__x64_sys_openat`/`do_sys_openat2` fentry trampolines ATTACH but never run
  on this LTO'd CachyOS kernel (bpftool run count = 0 while opens fly);
  the sensor hooks `path_openat` fentry/fexit instead - it is the one function
  every open variant calls, and `op->open_flag` there carries the full raw
  flags (`file->f_flags` at fexit already has O_CREAT/O_TRUNC/O_APPEND stripped).
- exec argv comes from an fentry/__x64_sys_execve{,at} argument stash joined
  at sched_process_exec (tracepoint confirms real execs only).
- `sudo cargo test` fails on CI (rustup shim sees no default toolchain under
  sudo) - CI runs `sudo $(rustup which cargo) test`.

## Evidence (all reproducible)
- `cargo test` (17 tests): 13 unit + 4 live integration; as root:
  `live capture ok: 4289 events, 16 alerts` - all 14 detections assert
  rule id + field needle on real syscall triggers.
- `tools/bench.sh` -> `bench-out.txt`: idle cpu=0.13% rss=11.8 MB;
  6x cc -O2 burst cpu=0.20% (targets were <2% / <1%).
- assets/: events/detection/stats/overhead/demo - real `vhs` recordings
  (.tape), GIF + PNG frames.
- Fresh-clone verification: `gh repo clone` -> `cargo build` -> 3 s run
  captured 63 events, 0 drops, stats clean.
- No-BTF failure: `nobtf_bpf` test (BPFSIGHT_BTF_PATH=invalid -> clear
  CONFIG_DEBUG_INFO_BTF error, no load).

## Next queue item
Project 6: `malleable` (~/projects/malleable) per ~/CYBER-PROJECTS-PLAN.md.
