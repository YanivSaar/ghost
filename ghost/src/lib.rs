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
