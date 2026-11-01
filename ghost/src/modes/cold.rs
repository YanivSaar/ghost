//! cold: startup flame — execve → first work, incl. pre-main ld.so cost
//! (ARCHITECTURE §9.5).
//!
//! Aggregation lives in the eBPF COLD_STAT map, polled by the consumer thread
//! into AppState.cold.timeline. This Mode impl exists for the uniform mode
//! trait: cold declares its probe (raw_syscalls/sys_enter) and owns reset.

use ghost_common::EventKind;

use super::mode::{Mode, ModeId, ModeView, Probe};

static COLD_PROBES: &[Probe] = &[
    Probe::Tracepoint("raw_syscalls", "sys_enter"),
];

#[derive(Debug, Default)]
pub struct ColdMode {
    pub events_seen: u64,
}

impl ColdMode {
    pub fn new() -> Self { Self::default() }
}

impl Mode for ColdMode {
    fn id(&self) -> ModeId { ModeId::Cold }

    fn probes(&self) -> &'static [Probe] { COLD_PROBES }

    fn on_event(&mut self, _kind: EventKind, _bytes: &[u8], _now: u64) {
        self.events_seen += 1;
    }

    fn tick(&mut self, _now: u64) {}

    fn view(&self) -> ModeView {
        ModeView { id: ModeId::Cold }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_raw_syscalls_enter() {
        let m = ColdMode::new();
        let probes = m.probes();
        assert_eq!(probes.len(), 1);
        assert!(matches!(probes[0], Probe::Tracepoint("raw_syscalls", "sys_enter")));
    }

    #[test]
    fn id_is_cold() {
        assert!(matches!(ColdMode::new().id(), ModeId::Cold));
    }

    #[test]
    fn reset_clears_counters() {
        let mut m = ColdMode::new();
        m.events_seen = 42;
        m.reset();
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn view_returns_cold_id() {
        assert!(matches!(ColdMode::new().view().id, ModeId::Cold));
    }
}
