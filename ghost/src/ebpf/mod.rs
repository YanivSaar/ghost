//! eBPF load + attach + drain (ARCHITECTURE §5, §6).
pub mod consumer;
pub mod loader;

#[cfg(test)]
mod tests {
    //! RFC 0005 smoke-coverage: the submodules are reachable via this
    //! parent mod and expose the public items the supervisor depends on.
    use super::*;
    #[test]
    fn submodules_resolve() {
        let _ = core::any::type_name::<consumer::RecordSink>();
        let _ = core::any::type_name::<loader::GhostEbpf>();
    }
}
