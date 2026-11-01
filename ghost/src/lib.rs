//! ghost — a process observatory for Linux (library target).
//!
//! The binary (`src/main.rs`) is a thin CLI shell. Everything else lives
//! here so integration tests, benchmarks, and future tooling can reach
//! the internals.

pub mod supervisor;
pub mod state;
pub mod target;
pub mod ebpf;
pub mod proc;
pub mod modes;
pub mod session;
pub mod tui;
