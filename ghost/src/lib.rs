//! ghost — a process observatory for Linux (library target).
//!
//! The binary (`src/main.rs`) is a thin CLI shell. Everything else lives
//! here so integration tests, benchmarks, and future tooling can reach
//! the internals.

// Clippy relaxations: cosmetic lints that don't reflect bugs and would
// churn a lot of unrelated code to silence. We'll revisit during the
// stability pass.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::uninlined_format_args)]
// Descending sort via sort_by reads clearer than sort_by_key(Reverse(_)).
#![allow(clippy::unnecessary_sort_by)]
// `x / y` with a guarded `if y > 0` is intentional and clearer than
// `x.checked_div(y).unwrap_or(0)` when the guard already conveys intent.
#![allow(clippy::manual_checked_ops)]

pub mod analyze;
pub mod caps;
pub mod ebpf;
pub mod modes;
pub mod panic_hook;
pub mod proc;
pub mod session;
pub mod signals;
pub mod state;
pub mod supervisor;
pub mod target;
pub mod tui;

#[cfg(test)]
mod lib_smoke_tests {
    //! RFC 0005: smoke-coverage for pub mod re-exports so every
    //! top-level module path appears in at least one test.
    use crate::{analyze, caps, ebpf, modes, panic_hook, proc, session, signals, state, supervisor, target, tui};
    #[test]
    fn every_top_level_module_is_reachable() {
        // Opaque reference. The resolution itself is the check.
        let _ = (
            core::any::type_name::<analyze::Mode>(),
            core::any::type_name::<caps::CapCheck>(),
            core::any::type_name::<ebpf::consumer::RecordSink>(),
            core::any::type_name::<modes::mode::ModeId>(),
            core::any::type_name::<proc::ProcSnapshot>(),
            core::any::type_name::<session::format::SessionMeta>(),
            core::any::type_name::<state::AppState>(),
            core::any::type_name::<target::pid::PidTarget>(),
            core::any::type_name::<tui::app::Tui>(),
        );
        panic_hook::install();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _ = signals::install_shutdown(&stop);
        // supervisor::run_diff(_, _) requires real session files; just
        // reference a public fn pointer so the mod is linked here too.
        let _f: fn(String, String) -> anyhow::Result<()> = supervisor::run_diff;
    }
}
