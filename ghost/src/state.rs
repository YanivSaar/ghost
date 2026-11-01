//! Shared application state (ARCHITECTURE §3, §12).
//!
//! One `Arc<RwLock<AppState>>` is passed to every thread.
//! The render thread takes a brief read lock each frame; writer threads
//! hold the write lock only long enough to update aggregates.

use std::collections::VecDeque;
use ghost_common::{ColdStat, LockStat, SyscallKey, SyscallStat};
use crate::proc::ProcSnapshot;

/// Max hits retained in CatchLensState.recent_hits (newest first).
pub const CATCH_RING_CAP: usize = 200;

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
    pub lock:       LockLensState,
    pub catch:      CatchLensState,
    pub cold:       ColdLensState,
    pub snap:       Option<ProcSnapshot>,

    /// Set to true when the target process exits.
    pub target_gone: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveMode {
    Watch,
    Snap,
    Lock,
    Catch,
    Cold,
}

/// Live state for the `cold` lens. `launch_ts_ns` is captured in the same
/// clock domain as bpf_ktime_get_ns (CLOCK_MONOTONIC), so timeline rows can
/// render first-syscall deltas as "+X µs since launch". `exit_status` is set
/// by the reaper thread when the child terminates.
#[derive(Debug, Default)]
pub struct ColdLensState {
    pub cmdline:       String,
    pub launch_ts_ns:  u64,
    /// (nr, first_ts_ns, count), sorted by first_ts_ns ascending.
    pub timeline:      Vec<(u32, u64, u64)>,
    pub exit_status:   Option<i32>,
    pub done:          bool,
}

/// Live aggregates for lock mode. Populated from the LOCK_STAT eBPF map.
#[derive(Debug, Default)]
pub struct LockLensState {
    /// Top-N futex addresses sorted by total_wait_ns descending.
    pub top_locks:       Vec<(u64, LockStat)>,
    pub total_waits:     u64,
    pub total_wait_ns:   u64,
}

/// One tripwire breach as surfaced to the TUI.
#[derive(Debug, Clone, Copy)]
pub struct CatchHit {
    pub ts_ns:    u64,
    pub tid:      u32,
    pub nr:       u32,
    pub delta_ns: u64,
}

/// Live state for the `catch` lens. The consumer drains the CAPTURE ring and
/// pushes a bounded VecDeque of the newest hits; the TUI renders them.
#[derive(Debug, Default)]
pub struct CatchLensState {
    /// Threshold (ns) armed on the CFG map. Shown in the header.
    pub threshold_ns: u64,
    /// Lifetime hit count, including hits dropped from recent_hits.
    pub total_hits:   u64,
    /// Max delta observed across the whole run (ns).
    pub max_delta_ns: u64,
    /// Newest first, bounded by CATCH_RING_CAP.
    pub recent_hits:  VecDeque<CatchHit>,
}

impl CatchLensState {
    pub fn push(&mut self, hit: CatchHit) {
        self.total_hits += 1;
        if hit.delta_ns > self.max_delta_ns { self.max_delta_ns = hit.delta_ns; }
        self.recent_hits.push_front(hit);
        while self.recent_hits.len() > CATCH_RING_CAP {
            self.recent_hits.pop_back();
        }
    }
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
            lock:  LockLensState::default(),
            catch: CatchLensState::default(),
            cold:  ColdLensState::default(),
            snap: None,
            target_gone: false,
        }
    }
}

/// Suppress unused-import warning when ColdStat lands here only as a type
/// reference in future consumer code.
#[allow(dead_code)]
fn _cold_stat_type_check(_s: ColdStat) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_sets_defaults() {
        let st = AppState::new(1234, "nginx".into());
        assert_eq!(st.pid,            1234);
        assert_eq!(st.comm,           "nginx");
        assert_eq!(st.mode,           ActiveMode::Watch);
        assert!(!st.ebpf_ok);
        assert!(st.ebpf_error.is_none());
        assert!(!st.target_gone);
        assert!(st.snap.is_none());
    }

    #[test]
    fn lock_lens_state_defaults() {
        let l = LockLensState::default();
        assert_eq!(l.total_waits,   0);
        assert_eq!(l.total_wait_ns, 0);
        assert!(l.top_locks.is_empty());
    }

    #[test]
    fn watch_state_default_zeros() {
        let w = WatchState::default();
        assert_eq!(w.total_syscalls,  0);
        assert_eq!(w.voluntary_ctx,   0);
        assert_eq!(w.involuntary_ctx, 0);
        assert_eq!(w.events_dropped,  0);
        assert!(w.cpu_history.is_empty());
        assert!(w.prev_cpu_ticks.is_none());
    }

    #[test]
    fn catch_lens_state_defaults() {
        let c = CatchLensState::default();
        assert_eq!(c.total_hits, 0);
        assert_eq!(c.max_delta_ns, 0);
        assert_eq!(c.threshold_ns, 0);
        assert!(c.recent_hits.is_empty());
    }

    #[test]
    fn catch_push_updates_totals_and_bounds_ring() {
        let mut c = CatchLensState::default();
        for i in 0..(CATCH_RING_CAP + 50) {
            c.push(CatchHit { ts_ns: i as u64, tid: 1, nr: 0, delta_ns: i as u64 });
        }
        assert_eq!(c.total_hits as usize, CATCH_RING_CAP + 50);
        assert_eq!(c.recent_hits.len(), CATCH_RING_CAP);
        // newest first
        assert_eq!(c.recent_hits.front().unwrap().ts_ns, (CATCH_RING_CAP + 49) as u64);
        assert_eq!(c.max_delta_ns, (CATCH_RING_CAP + 49) as u64);
    }

    #[test]
    fn cold_lens_state_defaults() {
        let c = ColdLensState::default();
        assert_eq!(c.launch_ts_ns, 0);
        assert!(c.cmdline.is_empty());
        assert!(c.timeline.is_empty());
        assert!(c.exit_status.is_none());
        assert!(!c.done);
    }

    #[test]
    fn cpu_history_bounded_by_history_depth() {
        let mut w = WatchState::default();
        for i in 0..HISTORY_DEPTH + 10 {
            w.cpu_history.push_back(i as f32);
            if w.cpu_history.len() > HISTORY_DEPTH {
                w.cpu_history.pop_front();
            }
        }
        assert_eq!(w.cpu_history.len(), HISTORY_DEPTH);
        // Oldest sample should be 10 (first 10 were popped).
        assert_eq!(w.cpu_history[0] as usize, 10);
    }
}
