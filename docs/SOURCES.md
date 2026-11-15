# Sources and provenance

Everything in this repository is generated or written locally; nothing is
downloaded.

- `bpf/vmlinux.h` - generated from the running kernel by
  `make -C bpf` (`bpftool btf dump file /sys/kernel/btf/vmlinux format c`).
  Gitignored: it is machine-specific by design and CO-RE relocations run
  against the target kernel's BTF at load time.
- `bpf/bpfsight.bpf.o` - compiled from `bpfsight.bpf.c` on `7.3.3-1-cachyos`
  with clang 23.1.5; committed so a fresh clone builds without clang.
- `bench-out.txt` - actual `tools/bench.sh` output on that machine
  (Arch, CachyOS kernel 7.3.3-1, 6-core Ryzen, 15 GB RAM, 2026-11-15).
- `assets/*.png`, `assets/*.gif` - `vhs` recordings of real terminal runs
  (`assets/*.tape`), PNGs extracted from the final GIF frames with ffmpeg.
  No hand-edited screenshots.
- `probe/` - the kernel-pairing smoke test written first; its BPF object is
  gitignored (rebuilt with the Makefile-less one-liner in probe/README.md).

Build toolchain used (all distro packages, no vendored sources):
clang 23.1.5, llvm 23.1.5, bpftool 7.6, rustc 1.99.1, aya 0.16, rusqlite 0.37
(bundled SQLite), clap 4, serde/serde_json/serde_yaml, libc, vhs v0.12.1,
ffmpeg. No external datasets, no network fetches at runtime.
