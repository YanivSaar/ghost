//! catch (wire): always-armed tripwire; log every syscall whose elapsed time
//! exceeded the configured threshold (ARCHITECTURE §9.4).
//!
//! The kernel-side catch programs push CatchRecord values onto the CAPTURE
//! ring; the userspace consumer drains that ring into AppState.catch. This
//! Mode impl exists for the uniform mode trait and the eventual per-hit
//! histogramming — today it just counts events seen.

use ghost_common::EventKind;

use super::mode::{Mode, ModeId, ModeView, Probe};

static CATCH_PROBES: &[Probe] = &[
    Probe::Tracepoint("raw_syscalls", "sys_enter"),
    Probe::Tracepoint("raw_syscalls", "sys_exit"),
];

#[derive(Debug, Default)]
pub struct CatchMode {
    pub events_seen: u64,
}

impl CatchMode {
    pub fn new() -> Self { Self::default() }
}

impl Mode for CatchMode {
    fn id(&self) -> ModeId { ModeId::Catch }

    fn probes(&self) -> &'static [Probe] { CATCH_PROBES }

    fn on_event(&mut self, kind: EventKind, _bytes: &[u8], _now: u64) {
        if kind == EventKind::CatchHit {
            self.events_seen += 1;
        }
    }

    fn tick(&mut self, _now: u64) {}

    fn view(&self) -> ModeView {
        ModeView { id: ModeId::Catch }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_raw_syscalls() {
        let m = CatchMode::new();
        let probes = m.probes();
        assert_eq!(probes.len(), 2);
        assert!(matches!(probes[0], Probe::Tracepoint("raw_syscalls", "sys_enter")));
        assert!(matches!(probes[1], Probe::Tracepoint("raw_syscalls", "sys_exit")));
    }

    #[test]
    fn id_is_catch() {
        assert!(matches!(CatchMode::new().id(), ModeId::Catch));
    }

    #[test]
    fn on_event_counts_only_catch_hits() {
        let mut m = CatchMode::new();
        m.on_event(EventKind::CatchHit, &[], 0);
        m.on_event(EventKind::SchedSwitch, &[], 0);
        m.on_event(EventKind::CatchHit, &[], 0);
        assert_eq!(m.events_seen, 2);
    }

    #[test]
    fn reset_clears_counters() {
        let mut m = CatchMode::new();
        m.events_seen = 7;
        m.reset();
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn view_returns_catch_id() {
        assert!(matches!(CatchMode::new().view().id, ModeId::Catch));
    }
}
