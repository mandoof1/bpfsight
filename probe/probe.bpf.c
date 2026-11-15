// Probe: does eBPF ringbuf + raw tracepoints work on this kernel/BTF pair?
// Build: clang -target bpf -O2 -g -c probe.bpf.c -o probe.bpf.o
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096);
} rb SEC(".maps");

struct ev {
    __u64 ts;
    __u32 pid;
    char comm[16];
};

SEC("raw_tracepoint/sched_process_exec")
int handle_exec(struct bpf_raw_tracepoint_args *ctx) {
    struct ev *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;
    e->ts = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "MIT";
