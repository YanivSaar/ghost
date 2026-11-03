//! Rule trait + registry. Each rule reads `AppState` + its thresholds +
//! the history ring and returns a `Diagnosis` when its pattern matches.

use crate::analyze::{
    config::RuleThresholds,
    engine::TickSnapshot,
    Diagnosis,
};
use crate::state::AppState;
use std::collections::VecDeque;

pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(
        &self,
        state: &AppState,
        thresholds: &RuleThresholds,
        history: &VecDeque<TickSnapshot>,
        tick: u64,
    ) -> Option<Diagnosis>;
}

/// Registry — order matters only for tie-breaking in display; the
/// engine sorts after collection.
pub fn all_rules() -> &'static [&'static dyn Rule] {
    use crate::analyze::scenarios::*;
    static RULES: &[&'static (dyn Rule + 'static)] = &[
        &CPU_BOUND_USER,
        &CPU_BOUND_KERNEL,
        &IO_BOUND,
        &FUTEX_CONTENTION,
        &POSSIBLE_DEADLOCK,
        &STARTUP_PHASE,
        &JITTER_FROM_IRQ,
        &FORK_STORM,
        &GC_LIKE_PAUSE,
        &SIGNAL_PRESSURE,
        &MMAP_THRASH,
        &ZOMBIE_REAP_DELAY,
    ];
    RULES
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_lists_twelve_rules() {
        assert_eq!(all_rules().len(), 12);
    }
    #[test]
    fn ids_are_unique() {
        let ids: Vec<_> = all_rules().iter().map(|r| r.id()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(ids.len(), sorted.len());
    }
}
