fn main() {
    println!("cargo:rerun-if-changed=bpf/bpfsight.bpf.o");
}
