# probe: kernel pairing smoke test

Verifies that eBPF raw tracepoints + ring buffers compile, load and emit on
this machine before trusting the main object.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
clang -target bpf -O2 -g -c probe.bpf.c -o probe.bpf.o
cargo run            # as root
```

Expected: exec events for any commands you start elsewhere, then `PROBE-OK`.
