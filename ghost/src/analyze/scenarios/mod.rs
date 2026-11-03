//! The 12 scenario rules from RFC 0001.
//!
//! Each rule is a zero-sized unit type implementing `Rule`. Thresholds
//! come from the config (with compiled defaults for every missing key),
//! and history snapshots let a rule turn raw `AppState` totals into
//! per-second rates.

use crate::analyze::{
    config::RuleThresholds,
    engine::TickSnapshot,
    rules::Rule,
    Confidence, Diagnosis, Severity, SignalRef,
};
use crate::state::AppState;
use std::collections::VecDeque;

pub mod extra;

// ---- syscall-number constants (x86_64 ABI) ----
// Only the handful we read directly below. Full table lives in tui::syscalls.
pub(crate) mod nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const POLL: u32 = 7;
    pub const MMAP: u32 = 9;
    pub const MUNMAP: u32 = 11;
    pub const RT_SIGPROCMASK: u32 = 14;
    pub const PREAD64: u32 = 17;
    pub const PWRITE64: u32 = 18;
    pub const CLONE: u32 = 56;
    pub const CLONE3: u32 = 435;
    pub const KILL: u32 = 62;
    pub const WAIT4: u32 = 61;
    pub const EXIT: u32 = 60;
    pub const EXIT_GROUP: u32 = 231;
    pub const FUTEX: u32 = 202;
    pub const TGKILL: u32 = 234;
}

// Pull a per-second rate for syscall `nr` from the history ring.
fn per_sec_count(hist: &VecDeque<TickSnapshot>, nr: u32) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    let a = *last.per_syscall_counts.get(&nr).unwrap_or(&0);
    let b = *prev.per_syscall_counts.get(&nr).unwrap_or(&0);
    a.saturating_sub(b) as f64
}

fn per_sec_total_syscalls(hist: &VecDeque<TickSnapshot>) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.total_syscalls.saturating_sub(prev.total_syscalls) as f64
}

fn per_sec_invol(hist: &VecDeque<TickSnapshot>) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.involuntary_ctx.saturating_sub(prev.involuntary_ctx) as f64
}

fn per_sec_vol(hist: &VecDeque<TickSnapshot>) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.voluntary_ctx.saturating_sub(prev.voluntary_ctx) as f64
}

fn last_cpu(hist: &VecDeque<TickSnapshot>) -> f32 {
    hist.back().map(|s| s.cpu_pct).unwrap_or(0.0)
}

// -------- individual rules --------

pub struct CpuBoundUser;
pub static CPU_BOUND_USER: CpuBoundUser = CpuBoundUser;
impl Rule for CpuBoundUser {
    fn id(&self) -> &'static str {
        "cpu_bound_user"
    }
    fn evaluate(
        &self,
        _st: &AppState,
        th: &RuleThresholds,
        hist: &VecDeque<TickSnapshot>,
        _tick: u64,
    ) -> Option<Diagnosis> {
        let cpu_min = th.get_f("cpu_pct_min", 80.0) as f32;
        let sc_max = th.get_f("syscalls_per_sec_max", 50.0);
        let cpu = last_cpu(hist);
        let sc = per_sec_total_syscalls(hist);
        if cpu >= cpu_min && sc <= sc_max {
            Some(Diagnosis {
                id: self.id(),
                headline: "CPU-bound in user space".into(),
                detail: format!(
                    "{:.0}% CPU, {:.0} syscalls/s — compute loop or busy-wait",
                    cpu, sc
                ),
                signals: vec![
                    SignalRef { kind: "cpu_pct", value: cpu as f64, threshold: cpu_min as f64 },
                    SignalRef { kind: "syscalls_per_sec", value: sc, threshold: sc_max },
                ],
                severity: Severity::Notice,
                confidence: if sc < sc_max * 0.5 { Confidence::High } else { Confidence::Medium },
                suggestion: None,
                first_seen_tick: 0,
                last_seen_tick: 0,
                consecutive_ticks: 0,
            })
        } else {
            None
        }
    }
}

pub struct CpuBoundKernel;
pub static CPU_BOUND_KERNEL: CpuBoundKernel = CpuBoundKernel;
impl Rule for CpuBoundKernel {
    fn id(&self) -> &'static str { "cpu_bound_kernel" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let cpu_min = th.get_f("cpu_pct_min", 80.0) as f32;
        let invol_min = th.get_f("involuntary_ctx_per_sec_min", 100.0);
        let sc_min = th.get_f("syscalls_per_sec_min", 500.0);
        let cpu = last_cpu(hist);
        let invol = per_sec_invol(hist);
        let sc = per_sec_total_syscalls(hist);
        if cpu >= cpu_min && invol >= invol_min && sc >= sc_min {
            Some(Diagnosis {
                id: self.id(),
                headline: "CPU-bound in the kernel".into(),
                detail: format!("{:.0}% CPU, {:.0} invol-ctx/s, {:.0} syscalls/s", cpu, invol, sc),
                signals: vec![
                    SignalRef { kind: "cpu_pct", value: cpu as f64, threshold: cpu_min as f64 },
                    SignalRef { kind: "invol_ctx_per_sec", value: invol, threshold: invol_min },
                    SignalRef { kind: "syscalls_per_sec", value: sc, threshold: sc_min },
                ],
                severity: Severity::Notice,
                confidence: Confidence::Medium,
                suggestion: None,
                first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
            })
        } else { None }
    }
}

pub struct IoBound;
pub static IO_BOUND: IoBound = IoBound;
impl Rule for IoBound {
    fn id(&self) -> &'static str { "io_bound" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let ratio_min = th.get_f("vol_over_invol_ratio_min", 4.0);
        let share_min = th.get_f("io_syscalls_share_min", 0.5);
        let vol = per_sec_vol(hist);
        let invol = per_sec_invol(hist).max(1.0);
        let total = per_sec_total_syscalls(hist).max(1.0);
        let io_rate = per_sec_count(hist, nr::READ)
            + per_sec_count(hist, nr::WRITE)
            + per_sec_count(hist, nr::POLL)
            + per_sec_count(hist, nr::PREAD64)
            + per_sec_count(hist, nr::PWRITE64);
        let ratio = vol / invol;
        let share = io_rate / total;
        if ratio >= ratio_min && share >= share_min {
            Some(Diagnosis {
                id: self.id(),
                headline: "I/O-bound".into(),
                detail: format!("vol/invol={:.1}×, {:.0}% of syscalls are read/write/poll", ratio, share * 100.0),
                signals: vec![
                    SignalRef { kind: "vol_over_invol", value: ratio, threshold: ratio_min },
                    SignalRef { kind: "io_share", value: share, threshold: share_min },
                ],
                severity: Severity::Notice,
                confidence: Confidence::Medium,
                suggestion: None,
                first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
            })
        } else { None }
    }
}

pub struct FutexContention;
pub static FUTEX_CONTENTION: FutexContention = FutexContention;
impl Rule for FutexContention {
    fn id(&self) -> &'static str { "futex_contention" }
    fn evaluate(&self, st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let count_min = th.get_f("futex_count_min", 20.0);
        let p99_min_ms = th.get_f("wait_p99_ms_min", 10.0);
        let blockers_min = th.get_f("blocked_thread_count_min", 2.0) as usize;
        let count_rate = per_sec_count(hist, nr::FUTEX);
        if count_rate < count_min { return None; }
        // Approximate p99 with max_wait_ns of the top lock.
        let max_wait_ns = st.lock.top_locks.first().map(|(_, s)| s.max_wait_ns).unwrap_or(0);
        let p99_ms = max_wait_ns as f64 / 1_000_000.0;
        if p99_ms < p99_min_ms { return None; }
        let blockers = st.lock.top_locks.iter().filter(|(_, s)| s.waits > 0).count();
        if blockers < blockers_min { return None; }
        let top_addr = st.lock.top_locks.first().map(|(a, _)| *a).unwrap_or(0);
        Some(Diagnosis {
            id: "futex_contention",
            headline: format!("Futex contention on 0x{:x}", top_addr),
            detail: format!("{:.0} waits/s, p99≈{:.1} ms, {} blockers", count_rate, p99_ms, blockers),
            signals: vec![
                SignalRef { kind: "futex_per_sec", value: count_rate, threshold: count_min },
                SignalRef { kind: "p99_ms", value: p99_ms, threshold: p99_min_ms },
                SignalRef { kind: "blockers", value: blockers as f64, threshold: blockers_min as f64 },
            ],
            severity: Severity::Warning,
            confidence: Confidence::High,
            suggestion: Some(format!("ghost lock {}", st.pid)),
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct PossibleDeadlock;
pub static POSSIBLE_DEADLOCK: PossibleDeadlock = PossibleDeadlock;
impl Rule for PossibleDeadlock {
    fn id(&self) -> &'static str { "possible_deadlock" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, tick: u64) -> Option<Diagnosis> {
        let cpu_max = th.get_f("cpu_pct_max", 1.0) as f32;
        let waits_min = th.get_f("futex_wait_min", 2.0);
        let quiet_ticks_min = th.get_f("quiet_ticks_min", 3.0) as usize;
        // Look back `quiet_ticks_min` ticks: every one must be cpu <= cpu_max and have futex waits.
        if hist.len() < quiet_ticks_min + 1 { return None; }
        let start = hist.len() - quiet_ticks_min;
        for i in start..hist.len() {
            let s = &hist[i];
            if s.cpu_pct > cpu_max { return None; }
            let f = *s.per_syscall_counts.get(&nr::FUTEX).unwrap_or(&0);
            if (f as f64) < waits_min { return None; }
        }
        Some(Diagnosis {
            id: "possible_deadlock",
            headline: "Possible deadlock on futex".into(),
            detail: format!("CPU≈0% with futex waits for {} ticks — no progress", quiet_ticks_min),
            signals: vec![
                SignalRef { kind: "cpu_pct", value: last_cpu(hist) as f64, threshold: cpu_max as f64 },
                SignalRef { kind: "quiet_ticks", value: quiet_ticks_min as f64, threshold: quiet_ticks_min as f64 },
            ],
            severity: Severity::Warning,
            confidence: Confidence::High,
            suggestion: Some(format!("inspect threads: ghost lock on this pid at tick {}", tick)),
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct StartupPhase;
pub static STARTUP_PHASE: StartupPhase = StartupPhase;
impl Rule for StartupPhase {
    fn id(&self) -> &'static str { "startup_phase" }
    fn evaluate(&self, st: &AppState, th: &RuleThresholds, _hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let max_entries = th.get_f("cold_entries_max", 5.0) as usize;
        if st.cold.timeline.is_empty() || st.cold.timeline.len() > max_entries {
            return None;
        }
        if st.cold.done { return None; }
        Some(Diagnosis {
            id: "startup_phase",
            headline: "Startup phase — not steady state yet".into(),
            detail: format!("cold timeline has {} first-syscall entries", st.cold.timeline.len()),
            signals: vec![SignalRef { kind: "cold_entries", value: st.cold.timeline.len() as f64, threshold: max_entries as f64 }],
            severity: Severity::Info,
            confidence: Confidence::Medium,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct JitterFromIrq;
pub static JITTER_FROM_IRQ: JitterFromIrq = JitterFromIrq;
impl Rule for JitterFromIrq {
    fn id(&self) -> &'static str { "jitter_from_irq" }
    fn evaluate(&self, st: &AppState, th: &RuleThresholds, _hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let share_min = th.get_f("irq_share_min", 0.5);
        if st.jitter.total_irq_ns == 0 { return None; }
        let top = st.jitter.hard_irqs.first()?;
        let share = top.1.total_ns as f64 / st.jitter.total_irq_ns.max(1) as f64;
        if share < share_min { return None; }
        Some(Diagnosis {
            id: "jitter_from_irq",
            headline: format!("Jitter attributable to IRQ {}", top.0),
            detail: format!("{:.0}% of hard-IRQ samples ({} hits)", share * 100.0, top.1.count),
            signals: vec![SignalRef { kind: "irq_share", value: share, threshold: share_min }],
            severity: Severity::Notice,
            confidence: Confidence::Medium,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct ForkStorm;
pub static FORK_STORM: ForkStorm = ForkStorm;
impl Rule for ForkStorm {
    fn id(&self) -> &'static str { "fork_storm" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let clone_min = th.get_f("clones_per_sec_min", 5.0);
        let exit_min = th.get_f("exits_per_sec_min", 5.0);
        let clones = per_sec_count(hist, nr::CLONE) + per_sec_count(hist, nr::CLONE3);
        let exits = per_sec_count(hist, nr::EXIT) + per_sec_count(hist, nr::EXIT_GROUP);
        if clones < clone_min || exits < exit_min { return None; }
        Some(Diagnosis {
            id: "fork_storm",
            headline: "Fork storm".into(),
            detail: format!("{:.0} clones/s, {:.0} exits/s", clones, exits),
            signals: vec![
                SignalRef { kind: "clones_per_sec", value: clones, threshold: clone_min },
                SignalRef { kind: "exits_per_sec", value: exits, threshold: exit_min },
            ],
            severity: Severity::Warning,
            confidence: Confidence::High,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct GcLikePause;
pub static GC_LIKE_PAUSE: GcLikePause = GcLikePause;
impl Rule for GcLikePause {
    fn id(&self) -> &'static str { "gc_like_pause" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        // Opt-in: default disabled.
        if !th.enabled() { return None; }
        let cycles_min = th.get_f("cycles_min", 3.0) as usize;
        if hist.len() < cycles_min * 2 + 2 { return None; }
        // Count low-high transitions in cpu_pct across recent ticks.
        let mut cycles = 0usize;
        let mut last_low = true;
        let threshold = 10.0f32;
        for s in hist.iter().rev().take(cycles_min * 4) {
            let is_low = s.cpu_pct < threshold;
            if is_low != last_low {
                cycles += 1;
                last_low = is_low;
            }
        }
        if cycles < cycles_min { return None; }
        Some(Diagnosis {
            id: "gc_like_pause",
            headline: "GC-like pause pattern".into(),
            detail: format!("{} quiet/busy transitions in recent window", cycles),
            signals: vec![SignalRef { kind: "cycles", value: cycles as f64, threshold: cycles_min as f64 }],
            severity: Severity::Info,
            confidence: Confidence::Low,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct SignalPressure;
pub static SIGNAL_PRESSURE: SignalPressure = SignalPressure;
impl Rule for SignalPressure {
    fn id(&self) -> &'static str { "signal_pressure" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let min_rate = th.get_f("signal_syscalls_per_sec_min", 50.0);
        let rate = per_sec_count(hist, nr::RT_SIGPROCMASK) + per_sec_count(hist, nr::KILL) + per_sec_count(hist, nr::TGKILL);
        if rate < min_rate { return None; }
        Some(Diagnosis {
            id: "signal_pressure",
            headline: "Signal syscall pressure".into(),
            detail: format!("{:.0} rt_sigprocmask+kill+tgkill /s", rate),
            signals: vec![SignalRef { kind: "signal_per_sec", value: rate, threshold: min_rate }],
            severity: Severity::Info,
            confidence: Confidence::Medium,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct MmapThrash;
pub static MMAP_THRASH: MmapThrash = MmapThrash;
impl Rule for MmapThrash {
    fn id(&self) -> &'static str { "mmap_thrash" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let mm_min = th.get_f("mmap_per_sec_min", 20.0);
        let mu_min = th.get_f("munmap_per_sec_min", 20.0);
        let bal_pct = th.get_f("balance_pct_max", 20.0);
        let mm = per_sec_count(hist, nr::MMAP);
        let mu = per_sec_count(hist, nr::MUNMAP);
        if mm < mm_min || mu < mu_min { return None; }
        let avg = (mm + mu) / 2.0;
        let diff_pct = ((mm - mu).abs() / avg.max(1.0)) * 100.0;
        if diff_pct > bal_pct { return None; }
        Some(Diagnosis {
            id: "mmap_thrash",
            headline: "mmap/munmap thrash".into(),
            detail: format!("{:.0} mmap/s, {:.0} munmap/s (|Δ|={:.0}%)", mm, mu, diff_pct),
            signals: vec![
                SignalRef { kind: "mmap_per_sec", value: mm, threshold: mm_min },
                SignalRef { kind: "munmap_per_sec", value: mu, threshold: mu_min },
            ],
            severity: Severity::Notice,
            confidence: Confidence::Medium,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

pub struct ZombieReapDelay;
pub static ZOMBIE_REAP_DELAY: ZombieReapDelay = ZombieReapDelay;
impl Rule for ZombieReapDelay {
    fn id(&self) -> &'static str { "zombie_reap_delay" }
    fn evaluate(&self, _st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tick: u64) -> Option<Diagnosis> {
        let wait4_min = th.get_f("wait4_per_sec_min", 10.0);
        let exit_max = th.get_f("exits_per_sec_max", 2.0);
        let w = per_sec_count(hist, nr::WAIT4);
        let e = per_sec_count(hist, nr::EXIT) + per_sec_count(hist, nr::EXIT_GROUP);
        if w < wait4_min || e > exit_max { return None; }
        Some(Diagnosis {
            id: "zombie_reap_delay",
            headline: "wait4 pressure without matching exits".into(),
            detail: format!("{:.0} wait4/s, {:.0} exits/s", w, e),
            signals: vec![
                SignalRef { kind: "wait4_per_sec", value: w, threshold: wait4_min },
                SignalRef { kind: "exits_per_sec", value: e, threshold: exit_max },
            ],
            severity: Severity::Info,
            confidence: Confidence::Low,
            suggestion: None,
            first_seen_tick: 0, last_seen_tick: 0, consecutive_ticks: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{config::AnalyzerConfig, engine::AnalyzerEngine, AnalyzerState};
    use crate::state::AppState;

    fn tick_history(entries: Vec<TickSnapshot>) -> VecDeque<TickSnapshot> {
        entries.into_iter().collect()
    }

    #[test]
    fn cpu_bound_user_fires_on_high_cpu_low_syscalls() {
        let th = RuleThresholds::new().f("cpu_pct_min", 80.0).f("syscalls_per_sec_max", 50.0);
        let st = AppState::new(1, "x".into());
        let h = tick_history(vec![
            TickSnapshot { tick: 0, cpu_pct: 92.0, total_syscalls: 0, ..Default::default() },
            TickSnapshot { tick: 1, cpu_pct: 92.0, total_syscalls: 10, ..Default::default() },
        ]);
        assert!(CPU_BOUND_USER.evaluate(&st, &th, &h, 1).is_some());
    }

    #[test]
    fn cpu_bound_user_does_not_fire_on_high_syscalls() {
        let th = RuleThresholds::new().f("cpu_pct_min", 80.0).f("syscalls_per_sec_max", 50.0);
        let st = AppState::new(1, "x".into());
        let h = tick_history(vec![
            TickSnapshot { tick: 0, cpu_pct: 92.0, total_syscalls: 0, ..Default::default() },
            TickSnapshot { tick: 1, cpu_pct: 92.0, total_syscalls: 1000, ..Default::default() },
        ]);
        assert!(CPU_BOUND_USER.evaluate(&st, &th, &h, 1).is_none());
    }

    #[test]
    fn cpu_bound_user_boundary() {
        let th = RuleThresholds::new().f("cpu_pct_min", 80.0).f("syscalls_per_sec_max", 50.0);
        let st = AppState::new(1, "x".into());
        // exactly at threshold → fires (`>=`)
        let h = tick_history(vec![
            TickSnapshot { tick: 0, cpu_pct: 80.0, total_syscalls: 0, ..Default::default() },
            TickSnapshot { tick: 1, cpu_pct: 80.0, total_syscalls: 50, ..Default::default() },
        ]);
        assert!(CPU_BOUND_USER.evaluate(&st, &th, &h, 1).is_some());
    }

    #[test]
    fn fork_storm_fires_on_clone_and_exit_rate() {
        let th = RuleThresholds::new().f("clones_per_sec_min", 5.0).f("exits_per_sec_min", 5.0);
        let st = AppState::new(1, "x".into());
        let mut prev: std::collections::HashMap<u32, u64> = Default::default();
        prev.insert(nr::CLONE, 0);
        prev.insert(nr::EXIT_GROUP, 0);
        let mut now = prev.clone();
        now.insert(nr::CLONE, 10);
        now.insert(nr::EXIT_GROUP, 10);
        let h = tick_history(vec![
            TickSnapshot { tick: 0, per_syscall_counts: prev, ..Default::default() },
            TickSnapshot { tick: 1, per_syscall_counts: now, ..Default::default() },
        ]);
        assert!(FORK_STORM.evaluate(&st, &th, &h, 1).is_some());
    }

    #[test]
    fn startup_phase_requires_small_timeline() {
        let th = RuleThresholds::new().f("cold_entries_max", 5.0);
        let mut st = AppState::new(1, "x".into());
        st.cold.timeline = vec![(0, 0, 1), (1, 0, 1)];
        assert!(STARTUP_PHASE.evaluate(&st, &th, &VecDeque::new(), 1).is_some());
        st.cold.timeline = (0..10).map(|i| (i, 0, 1)).collect();
        assert!(STARTUP_PHASE.evaluate(&st, &th, &VecDeque::new(), 1).is_none());
    }

    #[test]
    fn engine_tick_runs_and_fires_cpu_bound_user() {
        let mut cfg = AnalyzerConfig::built_in();
        // Noisy so Confidence::Low findings also surface, defaults are fine.
        cfg.default_mode = crate::analyze::Mode::Noisy;
        let mut eng = AnalyzerEngine::new(cfg);
        let mut st = AppState::new(1, "x".into());
        st.watch.cpu_history.push_back(95.0);
        let mut out = AnalyzerState::default();
        eng.tick(&st, &mut out);
        eng.tick(&st, &mut out);
        assert!(out.current.iter().any(|d| d.id == "cpu_bound_user"));
    }
}
