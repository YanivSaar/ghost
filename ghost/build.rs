//! Compiles the `ghost-ebpf` crate to BPF bytecode at host build time via
//! aya-build + bpf-linker, so the final binary embeds the BPF object with no
//! runtime toolchain dependency (ARCHITECTURE §5, §19).
fn main() {
    // TODO(phase 0): wire aya_build::build_ebpf against the ghost-ebpf package.
    // aya_build::build_ebpf([Package { name: "ghost-ebpf", .. }]).unwrap();
    println!("cargo:rerun-if-changed=../ghost-ebpf");
}
