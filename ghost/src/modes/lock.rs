//! lock (barrier): futex contention shape — top waits by address, rate,
//! max-wait distribution (ARCHITECTURE §9.3).
//!
//! Heavy aggregation lives in the eBPF LOCK_STAT map (polled by the consumer
//! thread into AppState.lock). This Mode impl exists for the uniform mode
//! trait: a Lock lens declares its probes and owns reset semantics.

use ghost_common::EventKind;

use super::mode::{Mode, ModeId, ModeView, Probe};

static LOCK_PROBES: &[Probe] = &[
    Probe::Tracepoint("syscalls", "sys_enter_futex"),
    Probe::Tracepoint("syscalls", "sys_exit_futex"),
];

#[derive(Debug, Default)]
pub struct LockMode {
    pub events_seen: u64,
}

impl LockMode {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Mode for LockMode {
    fn id(&self) -> ModeId {
        ModeId::Lock
    }

    fn probes(&self) -> &'static [Probe] {
        LOCK_PROBES
    }

    fn on_event(&mut self, _kind: EventKind, _bytes: &[u8], _now: u64) {
        // Lock lens aggregates via the LOCK_STAT map, not the EVENTS ring.
        // We still count events observed in case a future enhancement emits
        // per-wait records for a wait-time histogram.
        self.events_seen += 1;
    }

    fn tick(&mut self, _now: u64) {}

    fn view(&self) -> ModeView {
        ModeView { id: ModeId::Lock }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_futex_syscall_tracepoints() {
        let m = LockMode::new();
        let probes = m.probes();
        assert_eq!(probes.len(), 2);
        assert!(matches!(
            probes[0],
            Probe::Tracepoint("syscalls", "sys_enter_futex")
        ));
        assert!(matches!(
            probes[1],
            Probe::Tracepoint("syscalls", "sys_exit_futex")
        ));
    }

    #[test]
    fn id_is_lock() {
        let m = LockMode::new();
        assert!(matches!(m.id(), ModeId::Lock));
    }

    #[test]
    fn reset_clears_counters() {
        let mut m = LockMode::new();
        m.events_seen = 42;
        m.reset();
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn view_returns_lock_id() {
        let m = LockMode::new();
        assert!(matches!(m.view().id, ModeId::Lock));
    }
}
