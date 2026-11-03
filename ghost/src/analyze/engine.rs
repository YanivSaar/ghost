//! Analyzer engine: run each rule against `AppState` once per tick,
//! rank + dedupe, update history ring.

use crate::analyze::{
    config::{AnalyzerConfig, RuleThresholds},
    rules::all_rules,
    AnalyzerState, Confidence, Diagnosis, HistoryEntry, Mode,
};
use crate::state::AppState;
use std::collections::{HashMap, VecDeque};

/// 10 minutes @ 1 Hz.
pub const HISTORY_TICKS: usize = 600;

/// Dedupe window in quiet mode (ticks).
pub const QUIET_DEDUPE_WINDOW: u64 = 10;

/// Per-tick extracted snapshot kept in the ring so rules can reason
/// about rates (deltas over N ticks).
#[derive(Debug, Clone, Default)]
pub struct TickSnapshot {
    pub tick: u64,
    pub total_syscalls: u64,
    pub voluntary_ctx: u64,
    pub involuntary_ctx: u64,
    pub lock_total_waits: u64,
    pub cpu_pct: f32,
    pub per_syscall_counts: HashMap<u32, u64>,
    pub per_syscall_total_ns: HashMap<u32, u64>,
    pub per_syscall_max_ns: HashMap<u32, u64>,
    pub forks: u64,
    pub exits: u64,
    pub cold_entries: usize,
    // RFC 0002 additions sampled from ProcSnapshot.
    pub rss_kb: u64,
    pub majflt: u64,
    pub oom_score: u32,
    pub sched_run_ns: u64,
    pub sched_wait_ns: u64,
    pub lock_max_queue: u32,
}

/// Per-rule state across ticks: active diagnosis identity + first-seen
/// bookkeeping for dedupe + consecutive-tick counting.
#[derive(Debug, Default)]
struct RuleRuntime {
    first_seen_tick: u64,
    last_seen_tick: u64,
    consecutive: u32,
    last_emit_tick: u64,
    active: bool,
}

/// Shared history + rule-slot bookkeeping that outlives any single tick.
pub struct AnalyzerEngine {
    pub cfg: AnalyzerConfig,
    pub history: VecDeque<TickSnapshot>,
    pub tick: u64,
    pub mode: Mode,
    rule_state: HashMap<&'static str, RuleRuntime>,
    history_entries: VecDeque<HistoryEntry>,
    last_current: Vec<Diagnosis>,
    pub global_floor: Option<crate::analyze::Confidence>,
}

impl AnalyzerEngine {
    pub fn new(cfg: AnalyzerConfig) -> Self {
        let mode = cfg.default_mode;
        Self {
            cfg,
            history: VecDeque::with_capacity(HISTORY_TICKS),
            tick: 0,
            mode,
            rule_state: HashMap::new(),
            history_entries: VecDeque::with_capacity(HISTORY_TICKS),
            last_current: Vec::new(),
            global_floor: None,
        }
    }

    pub fn set_mode(&mut self, m: Mode) {
        self.mode = m;
    }

    /// Run every enabled rule against the current `AppState` snapshot
    /// and update the shared `AnalyzerState` block the TUI reads.
    pub fn tick(&mut self, st: &AppState, out: &mut AnalyzerState) {
        self.tick = self.tick.wrapping_add(1);

        // Build this tick's snapshot and push onto the ring.
        let snap = capture_snapshot(st, self.tick);
        if self.history.len() >= HISTORY_TICKS {
            self.history.pop_front();
        }
        self.history.push_back(snap);

        // Evaluate rules.
        let mut now: Vec<Diagnosis> = Vec::new();
        for rule in all_rules() {
            let thresholds = self.cfg.rules.get(rule.id());
            let default_thresholds = RuleThresholds::new();
            let th = thresholds.unwrap_or(&default_thresholds);
            if !th.enabled() {
                self.clear_slot(rule.id());
                continue;
            }
            let Some(diag) = rule.evaluate(st, th, &self.history, self.tick) else {
                self.clear_slot(rule.id());
                continue;
            };

            // Apply confidence floor (per-rule config OR session global).
            let effective_floor = match (th.confidence_floor(), self.global_floor) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            };
            if let Some(floor) = effective_floor {
                if diag.confidence < floor {
                    self.clear_slot(rule.id());
                    continue;
                }
            }

            // In quiet mode: suppress Low; dedupe within the window.
            let slot = self
                .rule_state
                .entry(rule.id())
                .or_default();
            if slot.active {
                slot.consecutive = slot.consecutive.saturating_add(1);
                slot.last_seen_tick = self.tick;
            } else {
                slot.first_seen_tick = self.tick;
                slot.last_seen_tick = self.tick;
                slot.consecutive = 1;
                slot.active = true;
            }

            if self.mode == Mode::Quiet {
                if diag.confidence == Confidence::Low {
                    continue;
                }
                if self.tick - slot.last_emit_tick < QUIET_DEDUPE_WINDOW && slot.last_emit_tick != 0
                {
                    continue;
                }
            }
            slot.last_emit_tick = self.tick;

            now.push(Diagnosis {
                first_seen_tick: slot.first_seen_tick,
                last_seen_tick: slot.last_seen_tick,
                consecutive_ticks: slot.consecutive,
                ..diag
            });
        }

        // Any slot that was active last tick but didn't fire this tick
        // is resolved → append a history row.
        let active_ids: std::collections::HashSet<&'static str> =
            now.iter().map(|d| d.id).collect();
        let mut resolved: Vec<&'static str> = Vec::new();
        for (id, slot) in self.rule_state.iter() {
            if slot.active && !active_ids.contains(*id) {
                resolved.push(*id);
            }
        }
        for id in resolved {
            if let Some(slot) = self.rule_state.get_mut(id) {
                if let Some(last) = self.last_current.iter().find(|d| d.id == id) {
                    let entry = HistoryEntry {
                        id,
                        headline: last.headline.clone(),
                        first_tick: slot.first_seen_tick,
                        last_tick: slot.last_seen_tick,
                        severity: last.severity,
                        confidence: last.confidence,
                    };
                    if self.history_entries.len() >= HISTORY_TICKS {
                        self.history_entries.pop_front();
                    }
                    self.history_entries.push_back(entry);
                }
                slot.active = false;
                slot.consecutive = 0;
            }
        }

        // Rank by severity (Warning > Notice > Info), then confidence desc.
        now.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then(b.confidence.cmp(&a.confidence))
        });

        self.last_current = now.clone();
        out.current = now;
        out.history = self.history_entries.clone();
        out.mode = self.mode;
        out.config_source = self.cfg.source.clone();
        out.tick = self.tick;
    }

    fn clear_slot(&mut self, id: &'static str) {
        if let Some(slot) = self.rule_state.get_mut(id) {
            slot.active = false;
        }
    }
}

/// Pull a tick snapshot out of an `AppState` read.
fn capture_snapshot(st: &AppState, tick: u64) -> TickSnapshot {
    let mut per_syscall_counts = HashMap::new();
    let mut per_syscall_total_ns = HashMap::new();
    let mut per_syscall_max_ns = HashMap::new();
    for (k, v) in &st.watch.top_syscalls {
        per_syscall_counts.insert(k.nr, v.count);
        per_syscall_total_ns.insert(k.nr, v.total_ns);
        per_syscall_max_ns.insert(k.nr, v.max_ns);
    }
    let cpu_pct = st
        .watch
        .cpu_history
        .back()
        .copied()
        .unwrap_or(0.0);
    let (rss_kb, majflt, oom_score, sched_run_ns, sched_wait_ns) = st
        .snap
        .as_ref()
        .map(|s| {
            (
                s.status.vm_rss_kb,
                s.stat.majflt,
                s.oom_score,
                s.sched_run_ns,
                s.sched_wait_ns,
            )
        })
        .unwrap_or_default();
    let lock_max_queue = st
        .lock
        .top_locks
        .iter()
        .map(|(_, s)| s.max_queue)
        .max()
        .unwrap_or(0);
    TickSnapshot {
        tick,
        total_syscalls: st.watch.total_syscalls,
        voluntary_ctx: st.watch.voluntary_ctx,
        involuntary_ctx: st.watch.involuntary_ctx,
        lock_total_waits: st.lock.total_waits,
        cpu_pct,
        per_syscall_counts,
        per_syscall_total_ns,
        per_syscall_max_ns,
        forks: 0,
        exits: 0,
        cold_entries: st.cold.timeline.len(),
        rss_kb,
        majflt,
        oom_score,
        sched_run_ns,
        sched_wait_ns,
        lock_max_queue,
    }
}

impl Ord for crate::analyze::Severity {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        rank(*self).cmp(&rank(*other))
    }
}
impl PartialOrd for crate::analyze::Severity {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

fn rank(s: crate::analyze::Severity) -> u8 {
    use crate::analyze::Severity::*;
    match s {
        Info => 0,
        Notice => 1,
        Warning => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::AnalyzerState;
    use crate::state::AppState;

    #[test]
    fn empty_tick_fires_nothing() {
        let st = AppState::new(1, "t".into());
        let mut eng = AnalyzerEngine::new(AnalyzerConfig::built_in());
        let mut out = AnalyzerState::default();
        eng.tick(&st, &mut out);
        assert!(out.current.is_empty());
        assert_eq!(out.tick, 1);
    }

    #[test]
    fn history_ring_bounded() {
        let st = AppState::new(1, "t".into());
        let mut eng = AnalyzerEngine::new(AnalyzerConfig::built_in());
        let mut out = AnalyzerState::default();
        for _ in 0..(HISTORY_TICKS + 20) {
            eng.tick(&st, &mut out);
        }
        assert_eq!(eng.history.len(), HISTORY_TICKS);
    }
}
