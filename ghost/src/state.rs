//! Shared application state (ARCHITECTURE §3, §12).
//!
//! One `Arc<RwLock<AppState>>` is passed to every thread.
//! The render thread takes a brief read lock each frame; writer threads
//! hold the write lock only long enough to update aggregates.

use std::collections::VecDeque;
use ghost_common::{SyscallKey, SyscallStat};
use crate::proc::ProcSnapshot;

/// System-clock name captured at session start.
pub const HISTORY_DEPTH: usize = 60;   // seconds of CPU% history

#[derive(Debug)]
pub struct AppState {
    pub pid:        u32,
    pub comm:       String,
    pub mode:       ActiveMode,
    pub ebpf_ok:    bool,
    pub ebpf_error: Option<String>,

    pub watch:      WatchState,
    pub snap:       Option<ProcSnapshot>,

    /// Set to true when the target process exits.
    pub target_gone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveMode {
    Watch,
    Snap,
}

/// Live aggregates for watch mode.
#[derive(Debug, Default)]
pub struct WatchState {
    /// Top-N syscalls sorted by total_ns descending; rebuilt each poll tick.
    pub top_syscalls:    Vec<(SyscallKey, SyscallStat)>,
    pub total_syscalls:  u64,
    pub total_cpu_ns:    u64,
    pub voluntary_ctx:   u64,
    pub involuntary_ctx: u64,
    pub events_dropped:  u64,

    /// Per-second CPU% samples (utime+stime delta / wall-second × 100).
    pub cpu_history:     VecDeque<f32>,

    /// Snapshot of /proc utime+stime from the previous poll, for delta calc.
    pub prev_cpu_ticks:  Option<u64>,
}

impl AppState {
    pub fn new(pid: u32, comm: String) -> Self {
        Self {
            pid,
            comm,
            mode: ActiveMode::Watch,
            ebpf_ok: false,
            ebpf_error: None,
            watch: WatchState::default(),
            snap: None,
            target_gone: false,
        }
    }
}
