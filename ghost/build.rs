use aya_build::{Package, Toolchain};

fn main() {
    aya_build::build_ebpf(
        [Package {
            name:                "ghost-ebpf",
            root_dir:            "../ghost-ebpf",
            no_default_features: false,
            features:            &[],
        }],
        Toolchain::Nightly,
    )
    .expect("failed to build eBPF programs");
}
