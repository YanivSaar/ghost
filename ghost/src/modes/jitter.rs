//! jitter: attribute off-CPU jitter to its source — hardirq, softirq, or
//! preemption by another task (ARCHITECTURE §9.6).
//!
//! Heavy aggregation lives in the eBPF IRQ_STAT / SOFTIRQ_STAT maps, polled
//! by the consumer thread into AppState.jitter. This Mode impl exists for
//! the uniform mode trait.

use ghost_common::EventKind;

use super::mode::{Mode, ModeId, ModeView, Probe};

static JITTER_PROBES: &[Probe] = &[
    Probe::Tracepoint("sched", "sched_switch"),
    Probe::Tracepoint("irq",   "irq_handler_entry"),
    Probe::Tracepoint("irq",   "irq_handler_exit"),
    Probe::Tracepoint("irq",   "softirq_entry"),
    Probe::Tracepoint("irq",   "softirq_exit"),
];

#[derive(Debug, Default)]
pub struct JitterMode {
    pub events_seen: u64,
}

impl JitterMode {
    pub fn new() -> Self { Self::default() }
}

impl Mode for JitterMode {
    fn id(&self) -> ModeId { ModeId::Jitter }

    fn probes(&self) -> &'static [Probe] { JITTER_PROBES }

    fn on_event(&mut self, _kind: EventKind, _bytes: &[u8], _now: u64) {
        self.events_seen += 1;
    }

    fn tick(&mut self, _now: u64) {}

    fn view(&self) -> ModeView {
        ModeView { id: ModeId::Jitter }
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_sched_and_irq_set() {
        let m = JitterMode::new();
        let probes = m.probes();
        assert_eq!(probes.len(), 5);
        assert!(matches!(probes[0], Probe::Tracepoint("sched", "sched_switch")));
        assert!(matches!(probes[1], Probe::Tracepoint("irq", "irq_handler_entry")));
        assert!(matches!(probes[2], Probe::Tracepoint("irq", "irq_handler_exit")));
        assert!(matches!(probes[3], Probe::Tracepoint("irq", "softirq_entry")));
        assert!(matches!(probes[4], Probe::Tracepoint("irq", "softirq_exit")));
    }

    #[test]
    fn id_is_jitter() {
        assert!(matches!(JitterMode::new().id(), ModeId::Jitter));
    }

    #[test]
    fn reset_clears_counters() {
        let mut m = JitterMode::new();
        m.events_seen = 123;
        m.reset();
        assert_eq!(m.events_seen, 0);
    }

    #[test]
    fn view_returns_jitter_id() {
        assert!(matches!(JitterMode::new().view().id, ModeId::Jitter));
    }
}
