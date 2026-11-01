//! watch: live syscall dashboard — distribution by time, scheduler behavior (ARCHITECTURE §9.2).

use ghost_common::{EventKind, SchedSwitchRecord};

use super::mode::{Mode, ModeId, ModeView, Probe};

static WATCH_PROBES: &[Probe] = &[
    Probe::Tracepoint("raw_syscalls", "sys_enter"),
    Probe::Tracepoint("raw_syscalls", "sys_exit"),
    Probe::Tracepoint("sched", "sched_switch"),
];

/// Per-mode in-process state for the watch lens.
/// Heavy aggregation lives in the eBPF SYSCALL_STAT map (read by consumer);
/// we track sched events here as they arrive from the ring buffer.
#[derive(Debug, Default)]
pub struct WatchMode {
    pub voluntary_ctx: u64,
    pub involuntary_ctx: u64,
    pub events_seen: u64,
}

impl WatchMode {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Mode for WatchMode {
    fn id(&self) -> ModeId {
        ModeId::Watch
    }

    fn probes(&self) -> &'static [Probe] {
        WATCH_PROBES
    }

    fn on_event(&mut self, kind: EventKind, bytes: &[u8], _now: u64) {
        if kind != EventKind::SchedSwitch {
            return;
        }
        if bytes.len() < core::mem::size_of::<SchedSwitchRecord>() {
            return;
        }

        let rec: SchedSwitchRecord =
            unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const SchedSwitchRecord) };
        self.events_seen += 1;
        if rec.involuntary == 1 {
            self.involuntary_ctx += 1;
        } else {
            self.voluntary_ctx += 1;
        }
    }

    fn tick(&mut self, _now: u64) {
        // Future: decay per-second buckets for sparkline data.
    }

    fn view(&self) -> ModeView {
        ModeView { id: ModeId::Watch }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_common::SchedSwitchRecord;

    fn make_sched_event(involuntary: u8) -> Vec<u8> {
        let rec = SchedSwitchRecord {
            kind: EventKind::SchedSwitch as u8,
            involuntary,
            _pad: [0; 2],
            pid: 1234,
            tid: 1234,
            _pad2: 0,
            ts_ns: 1_000_000,
            next_pid: 5678,
            _pad3: 0,
            next_comm: *b"bash\0\0\0\0\0\0\0\0\0\0\0\0",
        };
        let mut v = vec![0u8; core::mem::size_of::<SchedSwitchRecord>()];
        unsafe { core::ptr::write(v.as_mut_ptr() as *mut SchedSwitchRecord, rec) };
        v
    }

    #[test]
    fn probes_are_watch_tracepoints() {
        let m = WatchMode::new();
        let probes = m.probes();
        assert_eq!(probes.len(), 3);
        assert!(matches!(
            probes[0],
            Probe::Tracepoint("raw_syscalls", "sys_enter")
        ));
        assert!(matches!(
            probes[2],
            Probe::Tracepoint("sched", "sched_switch")
        ));
    }

    #[test]
    fn on_event_voluntary_switch() {
        let mut m = WatchMode::new();
        let ev = make_sched_event(0);
        m.on_event(EventKind::SchedSwitch, &ev, 0);
        assert_eq!(m.voluntary_ctx, 1);
        assert_eq!(m.involuntary_ctx, 0);
        assert_eq!(m.events_seen, 1);
    }

    #[test]
    fn on_event_involuntary_switch() {
        let mut m = WatchMode::new();
        let ev = make_sched_event(1);
        m.on_event(EventKind::SchedSwitch, &ev, 0);
        assert_eq!(m.voluntary_ctx, 0);
        assert_eq!(m.involuntary_ctx, 1);
    }

    #[test]
    fn on_event_wrong_kind_ignored() {
        let mut m = WatchMode::new();
        let ev = make_sched_event(0);
        m.on_event(EventKind::SyscallExit, &ev, 0);
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn on_event_short_bytes_ignored() {
        let mut m = WatchMode::new();
        m.on_event(EventKind::SchedSwitch, &[2u8, 0, 0], 0);
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn reset_clears_all_counters() {
        let mut m = WatchMode::new();
        let ev = make_sched_event(1);
        m.on_event(EventKind::SchedSwitch, &ev, 0);
        m.reset();
        assert_eq!(m.voluntary_ctx, 0);
        assert_eq!(m.involuntary_ctx, 0);
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn view_returns_watch_id() {
        let m = WatchMode::new();
        assert_eq!(m.view().id, ModeId::Watch);
    }
}
