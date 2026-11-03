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
    static BASE: &[&'static (dyn Rule + 'static)] = &[
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
    static ALL: std::sync::OnceLock<Vec<&'static (dyn Rule + 'static)>> = std::sync::OnceLock::new();
    ALL.get_or_init(|| {
        let mut v: Vec<&'static (dyn Rule + 'static)> = BASE.to_vec();
        v.extend_from_slice(crate::analyze::scenarios::extra::registry());
        v.extend_from_slice(crate::analyze::scenarios::app::registry());
        v
    })
    .as_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registry_lists_fifty_rules() {
        assert_eq!(all_rules().len(), 12 + 38 + 210);
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
