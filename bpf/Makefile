BPFOBJ = bpfsight.bpf.o
BPFCC ?= clang

all: $(BPFOBJ)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPFOBJ): bpfsight.bpf.c vmlinux.h
	$(BPFCC) -target bpf -O2 -g -Wall -Wno-missing-declarations -c $< -o $@

clean:
	rm -f $(BPFOBJ)
