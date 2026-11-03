//! RFC 0002 — the 38 additional scenario rules.
//!
//! Where a rule needs a signal the current samplers don't surface (e.g.
//! per-syscall errno, sched_switch next_cpu, cgroup cpu.stat), the
//! predicate is defined but short-circuits to `None` until that sampler
//! lands. Doing it this way reserves the rule-id and keeps the catalogue
//! size visible, with the per-rule rustdoc naming the missing input.

#![allow(clippy::collapsible_if)]

use crate::analyze::{
    config::RuleThresholds, engine::TickSnapshot, rules::Rule, Confidence, Diagnosis, Severity,
    SignalRef,
};
use crate::state::AppState;
use std::collections::VecDeque;

use super::nr;

fn delta(hist: &VecDeque<TickSnapshot>, nr: u32) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.per_syscall_counts
        .get(&nr)
        .copied()
        .unwrap_or(0)
        .saturating_sub(prev.per_syscall_counts.get(&nr).copied().unwrap_or(0)) as f64
}

fn total_ns_share(hist: &VecDeque<TickSnapshot>, nrs: &[u32]) -> f64 {
    let Some(last) = hist.back() else {
        return 0.0;
    };
    let mut top: u64 = 0;
    for n in nrs {
        top = top.saturating_add(last.per_syscall_total_ns.get(n).copied().unwrap_or(0));
    }
    let all: u64 = last.per_syscall_total_ns.values().sum();
    if all == 0 {
        0.0
    } else {
        top as f64 / all as f64
    }
}

fn invol_rate(hist: &VecDeque<TickSnapshot>) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.involuntary_ctx.saturating_sub(prev.involuntary_ctx) as f64
}

fn majflt_rate(hist: &VecDeque<TickSnapshot>) -> f64 {
    if hist.len() < 2 {
        return 0.0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.majflt.saturating_sub(prev.majflt) as f64
}

#[allow(dead_code)]
fn rss_kb_delta(hist: &VecDeque<TickSnapshot>) -> i64 {
    if hist.len() < 2 {
        return 0;
    }
    let last = hist.back().unwrap();
    let prev = &hist[hist.len() - 2];
    last.rss_kb as i64 - prev.rss_kb as i64
}

fn blank_diag(
    id: &'static str,
    headline: &str,
    detail: String,
    sev: Severity,
    conf: Confidence,
) -> Diagnosis {
    Diagnosis {
        id,
        headline: headline.into(),
        detail,
        signals: vec![],
        severity: sev,
        confidence: conf,
        suggestion: None,
        first_seen_tick: 0,
        last_seen_tick: 0,
        consecutive_ticks: 0,
    }
}

// macro to shorten rule unit boilerplate. Produces `${Name}Rule` as the
// zero-sized struct and `$name` as a static of that type so the slice
// registry can hold `&'static dyn Rule` references.
macro_rules! rule {
    ($name:ident, $ty:ident, $id:literal, $imp:expr) => {
        pub struct $ty;
        #[allow(non_upper_case_globals)]
        pub static $name: $ty = $ty;
        impl Rule for $ty {
            fn id(&self) -> &'static str {
                $id
            }
            fn evaluate(
                &self,
                state: &AppState,
                th: &RuleThresholds,
                hist: &VecDeque<TickSnapshot>,
                tick: u64,
            ) -> Option<Diagnosis> {
                let f: fn(
                    &AppState,
                    &RuleThresholds,
                    &VecDeque<TickSnapshot>,
                    u64,
                ) -> Option<Diagnosis> = $imp;
                f(state, th, hist, tick)
            }
        }
    };
}

// -------- CPU / scheduler (8) --------

rule!(
    preemption_storm,
    PreemptionStormRule,
    "preemption_storm",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min = th.get_f("invol_per_sec_min", 500.0);
        let rate = invol_rate(hist);
        if hist.len() < 4 {
            return None;
        }
        let r1 = invol_rate(hist);
        if r1 < min {
            return None;
        }
        Some(Diagnosis {
            signals: vec![SignalRef {
                kind: "invol_per_sec",
                value: rate,
                threshold: min,
            }],
            ..blank_diag(
                "preemption_storm",
                "Preemption storm",
                format!("{:.0} involuntary ctx/s", r1),
                Severity::Warning,
                Confidence::Medium,
            )
        })
    }
);

// cpu_migration_thrash: needs sched_switch next_cpu attribution.
rule!(
    cpu_migration_thrash,
    CpuMigrationThrashRule,
    "cpu_migration_thrash",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    cpu_affinity_mismatch,
    CpuAffinityMismatchRule,
    "cpu_affinity_mismatch",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);
rule!(
    priority_inversion,
    PriorityInversionRule,
    "priority_inversion",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

// cpu_starvation: schedstat gives run/wait. runnable ratio = run/(run+wait).
rule!(
    cpu_starvation,
    CpuStarvationRule,
    "cpu_starvation",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let ratio_max = th.get_f("run_ratio_max", 0.1);
        let min_ticks = th.get_f("ticks_min", 5.0) as usize;
        if hist.len() < min_ticks + 1 {
            return None;
        }
        for s in hist.iter().rev().take(min_ticks) {
            let total = (s.sched_run_ns as i128 + s.sched_wait_ns as i128).max(1);
            let ratio = s.sched_run_ns as f64 / total as f64;
            if ratio > ratio_max {
                return None;
            }
            if s.sched_run_ns == 0 && s.sched_wait_ns == 0 {
                return None;
            }
        }
        Some(blank_diag(
            "cpu_starvation",
            "CPU starvation (runnable but not scheduled)",
            "schedstat run/(run+wait) < 10% for N ticks".into(),
            Severity::Warning,
            Confidence::Medium,
        ))
    }
);

rule!(
    cgroup_throttled,
    CgroupThrottledRule,
    "cgroup_throttled",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);
rule!(
    rt_scheduling_pressure,
    RtSchedulingPressureRule,
    "rt_scheduling_pressure",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    nice_demotion_live,
    NiceDemotionLiveRule,
    "nice_demotion_live",
    |s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| {
        let snap = s.snap.as_ref()?;
        if snap.stat.nice >= 10 && snap.stat.priority >= 25 {
            Some(blank_diag(
                "nice_demotion_live",
                "Process niceness demoted at runtime",
                format!("priority={}, nice={}", snap.stat.priority, snap.stat.nice),
                Severity::Info,
                Confidence::Low,
            ))
        } else {
            None
        }
    }
);

// -------- Syscall / I/O (9) --------

rule!(
    read_heavy,
    ReadHeavyRule,
    "read_heavy",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min = th.get_f("share_min", 0.7);
        let s = total_ns_share(hist, &[nr::READ, nr::PREAD64]);
        if s < min {
            return None;
        }
        Some(blank_diag(
            "read_heavy",
            "Read-heavy workload",
            format!("read/pread64 = {:.0}% of syscall time", s * 100.0),
            Severity::Info,
            Confidence::Medium,
        ))
    }
);

rule!(
    write_heavy,
    WriteHeavyRule,
    "write_heavy",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min = th.get_f("share_min", 0.7);
        let s = total_ns_share(hist, &[nr::WRITE, nr::PWRITE64]);
        if s < min {
            return None;
        }
        Some(blank_diag(
            "write_heavy",
            "Write-heavy workload",
            format!("write/pwrite64 = {:.0}% of syscall time", s * 100.0),
            Severity::Info,
            Confidence::Medium,
        ))
    }
);

rule!(
    small_io_pattern,
    SmallIoPatternRule,
    "small_io_pattern",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    fsync_wall,
    FsyncWallRule,
    "fsync_wall",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const FSYNC: u32 = 74;
        const FDATASYNC: u32 = 75;
        let min_ms = th.get_f("p99_ms_min", 50.0);
        let last = hist.back()?;
        let max_ns = last
            .per_syscall_max_ns
            .get(&FSYNC)
            .copied()
            .unwrap_or(0)
            .max(
                last.per_syscall_max_ns
                    .get(&FDATASYNC)
                    .copied()
                    .unwrap_or(0),
            );
        let ms = max_ns as f64 / 1_000_000.0;
        if ms < min_ms {
            return None;
        }
        Some(blank_diag(
            "fsync_wall",
            "fsync/fdatasync wall",
            format!("max observed {:.1} ms", ms),
            Severity::Warning,
            Confidence::High,
        ))
    }
);

rule!(
    nonblocking_poll_loop,
    NonblockingPollLoopRule,
    "nonblocking_poll_loop",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);
rule!(
    epoll_hot_fd,
    EpollHotFdRule,
    "epoll_hot_fd",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);
rule!(
    select_vs_epoll_antipattern,
    SelectVsEpollAntipatternRule,
    "select_vs_epoll_antipattern",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const SELECT: u32 = 23;
        const PSELECT6: u32 = 270;
        let min = th.get_f("rate_min", 10.0);
        let r = delta(hist, SELECT) + delta(hist, PSELECT6);
        if r < min {
            return None;
        }
        Some(blank_diag(
            "select_vs_epoll_antipattern",
            "select/pselect6 used (prefer epoll)",
            format!("{:.0}/s", r),
            Severity::Info,
            Confidence::Low,
        ))
    }
);
rule!(
    getdents_crawl,
    GetdentsCrawlRule,
    "getdents_crawl",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const GETDENTS: u32 = 78;
        const GETDENTS64: u32 = 217;
        let min = th.get_f("rate_min", 50.0);
        let r = delta(hist, GETDENTS) + delta(hist, GETDENTS64);
        if r < min {
            return None;
        }
        Some(blank_diag(
            "getdents_crawl",
            "Sustained directory crawl",
            format!("{:.0} getdents/s", r),
            Severity::Notice,
            Confidence::Medium,
        ))
    }
);
rule!(
    splice_sendfile_opportunity,
    SpliceSendfileOpportunityRule,
    "splice_sendfile_opportunity",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

// -------- Memory (5) --------

rule!(
    brk_growth,
    BrkGrowthRule,
    "brk_growth",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const BRK: u32 = 12;
        let min = th.get_f("rate_min", 20.0);
        let r = delta(hist, BRK);
        if r < min {
            return None;
        }
        Some(blank_diag(
            "brk_growth",
            "brk growth",
            format!("{:.0} brk/s", r),
            Severity::Info,
            Confidence::Low,
        ))
    }
);

rule!(
    mmap_heap_fragmentation,
    MmapHeapFragmentationRule,
    "mmap_heap_fragmentation",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    page_fault_major_storm,
    PageFaultMajorStormRule,
    "page_fault_major_storm",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min = th.get_f("majflt_per_sec_min", 100.0);
        let r = majflt_rate(hist);
        if r < min {
            return None;
        }
        Some(blank_diag(
            "page_fault_major_storm",
            "Major page-fault storm",
            format!("{:.0} majflt/s — swapping or demand-load from disk", r),
            Severity::Warning,
            Confidence::High,
        ))
    }
);

rule!(
    madvise_dontneed_abuse,
    MadviseDontneedAbuseRule,
    "madvise_dontneed_abuse",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    rss_climb_steady,
    RssClimbSteadyRule,
    "rss_climb_steady",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min_kb_per_sec = th.get_f("rss_kb_per_sec_min", 10_000.0);
        let min_ticks = th.get_f("ticks_min", 5.0) as usize;
        if hist.len() < min_ticks + 1 {
            return None;
        }
        for i in (hist.len() - min_ticks)..hist.len() {
            if i == 0 {
                continue;
            }
            let d = hist[i].rss_kb as i64 - hist[i - 1].rss_kb as i64;
            if (d as f64) < min_kb_per_sec {
                return None;
            }
        }
        Some(blank_diag(
            "rss_climb_steady",
            "RSS climbing steadily",
            "≥ threshold per second for N ticks".into(),
            Severity::Warning,
            Confidence::Medium,
        ))
    }
);

// -------- Locking / concurrency (5) --------

rule!(
    reader_writer_imbalance,
    ReaderWriterImbalanceRule,
    "reader_writer_imbalance",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    spinlock_livelock_user,
    SpinlockLivelockUserRule,
    "spinlock_livelock_user",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let cpu_min = th.get_f("cpu_pct_min", 95.0) as f32;
        let waits_max = th.get_f("futex_waits_max", 1.0);
        if hist.len() < 3 {
            return None;
        }
        let last = hist.back().unwrap();
        let f = *last.per_syscall_counts.get(&nr::FUTEX).unwrap_or(&0) as f64;
        if last.cpu_pct < cpu_min {
            return None;
        }
        if f > waits_max {
            return None;
        }
        Some(blank_diag(
            "spinlock_livelock_user",
            "Possible user-space spinlock/livelock",
            format!(
                "{:.0}% CPU, {} futex waits in window",
                last.cpu_pct, f as u64
            ),
            Severity::Warning,
            Confidence::Low,
        ))
    }
);

rule!(
    convoying,
    ConvoyingRule,
    "convoying",
    |st: &AppState, th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| {
        let min_q = th.get_f("max_queue_min", 4.0) as u32;
        let longest = st
            .lock
            .top_locks
            .iter()
            .map(|(_, s)| s.max_queue)
            .max()
            .unwrap_or(0);
        if longest < min_q {
            return None;
        }
        Some(blank_diag(
            "convoying",
            "Convoying on a single futex",
            format!("longest observed queue = {}", longest),
            Severity::Warning,
            Confidence::Medium,
        ))
    }
);

rule!(
    yield_loop,
    YieldLoopRule,
    "yield_loop",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const SCHED_YIELD: u32 = 24;
        let min = th.get_f("rate_min", 100.0);
        let r = delta(hist, SCHED_YIELD);
        if r < min {
            return None;
        }
        Some(blank_diag(
            "yield_loop",
            "sched_yield spin loop",
            format!("{:.0} sched_yield/s", r),
            Severity::Notice,
            Confidence::Medium,
        ))
    }
);

rule!(
    many_short_locks,
    ManyShortLocksRule,
    "many_short_locks",
    |st: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min_rate = th.get_f("futex_rate_min", 200.0);
        let max_avg_us = th.get_f("avg_wait_us_max", 50.0);
        let r = delta(hist, nr::FUTEX);
        if r < min_rate {
            return None;
        }
        if st.lock.total_waits == 0 {
            return None;
        }
        let avg_us = (st.lock.total_wait_ns as f64 / st.lock.total_waits as f64) / 1000.0;
        if avg_us > max_avg_us {
            return None;
        }
        Some(blank_diag(
            "many_short_locks",
            "Many very short lock acquisitions",
            format!("{:.0} futex/s, avg {:.0} µs", r, avg_us),
            Severity::Info,
            Confidence::Medium,
        ))
    }
);

// -------- Networking (4) --------

rule!(
    connect_timeout_wall,
    ConnectTimeoutWallRule,
    "connect_timeout_wall",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);
rule!(
    connection_reset_storm,
    ConnectionResetStormRule,
    "connection_reset_storm",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    send_recv_imbalance,
    SendRecvImbalanceRule,
    "send_recv_imbalance",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        const SENDMSG: u32 = 46;
        const RECVMSG: u32 = 47;
        let min_ratio = th.get_f("ratio_min", 5.0);
        let s = delta(hist, SENDMSG);
        let r = delta(hist, RECVMSG);
        if s + r < 50.0 {
            return None;
        }
        let imbalance = if r > 0.0 { s / r } else { s };
        if imbalance < min_ratio && (if s > 0.0 { r / s } else { 0.0 }) < min_ratio {
            return None;
        }
        Some(blank_diag(
            "send_recv_imbalance",
            "sendmsg/recvmsg imbalance",
            format!("sendmsg={:.0}/s, recvmsg={:.0}/s", s, r),
            Severity::Info,
            Confidence::Low,
        ))
    }
);

rule!(
    tcp_small_segments,
    TcpSmallSegmentsRule,
    "tcp_small_segments",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

// -------- Process lifecycle (4) --------

rule!(
    respawn_loop,
    RespawnLoopRule,
    "respawn_loop",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let cycles_min = th.get_f("cycles_min", 3.0) as usize;
        if hist.len() < 10 {
            return None;
        }
        let mut clones = 0.0;
        let mut exits = 0.0;
        for i in (hist.len() - 10)..hist.len() {
            if i == 0 {
                continue;
            }
            let a = &hist[i - 1];
            let b = &hist[i];
            clones += b
                .per_syscall_counts
                .get(&nr::CLONE)
                .copied()
                .unwrap_or(0)
                .saturating_sub(a.per_syscall_counts.get(&nr::CLONE).copied().unwrap_or(0))
                as f64;
            exits += b
                .per_syscall_counts
                .get(&nr::EXIT_GROUP)
                .copied()
                .unwrap_or(0)
                .saturating_sub(
                    a.per_syscall_counts
                        .get(&nr::EXIT_GROUP)
                        .copied()
                        .unwrap_or(0),
                ) as f64;
        }
        if (clones.min(exits) as usize) < cycles_min {
            return None;
        }
        Some(blank_diag(
            "respawn_loop",
            "Respawn loop",
            format!("{:.0} clone+exit cycles in last 10s", clones.min(exits)),
            Severity::Warning,
            Confidence::Medium,
        ))
    }
);

rule!(
    exec_chain_long,
    ExecChainLongRule,
    "exec_chain_long",
    |st: &AppState, th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| {
        const EXECVE: u32 = 59;
        const EXECVEAT: u32 = 322;
        let min = th.get_f("depth_min", 5.0);
        let n = st
            .watch
            .top_syscalls
            .iter()
            .filter(|(k, _)| k.nr == EXECVE || k.nr == EXECVEAT)
            .map(|(_, v)| v.count)
            .sum::<u64>() as f64;
        if n < min {
            return None;
        }
        Some(blank_diag(
            "exec_chain_long",
            "Long execve chain",
            format!("≥ {} execve calls observed", n as u64),
            Severity::Info,
            Confidence::Low,
        ))
    }
);

rule!(
    daemon_double_fork_detected,
    DaemonDoubleForkDetectedRule,
    "daemon_double_fork_detected",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    oom_killer_proximate,
    OomKillerProximateRule,
    "oom_killer_proximate",
    |_s: &AppState, th: &RuleThresholds, hist: &VecDeque<TickSnapshot>, _tk: u64| {
        let min_score = th.get_f("oom_score_min", 500.0);
        let last = hist.back()?;
        if (last.oom_score as f64) < min_score {
            return None;
        }
        Some(blank_diag(
            "oom_killer_proximate",
            "Near OOM-kill",
            format!("oom_score = {}", last.oom_score),
            Severity::Warning,
            Confidence::High,
        ))
    }
);

// -------- Signals / timers (3) --------

rule!(
    sigpipe_bleed,
    SigpipeBleedRule,
    "sigpipe_bleed",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    timer_wheel_wobble,
    TimerWheelWobbleRule,
    "timer_wheel_wobble",
    |_s: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| { None }
);

rule!(
    signal_blocked_handler_pending,
    SignalBlockedHandlerPendingRule,
    "signal_blocked_handler_pending",
    |st: &AppState, _th: &RuleThresholds, _h: &VecDeque<TickSnapshot>, _tk: u64| {
        let snap = st.snap.as_ref()?;
        let pnd = u64::from_str_radix(snap.status.sig_pending.trim(), 16).unwrap_or(0);
        let blk = u64::from_str_radix(snap.status.sig_blocked.trim(), 16).unwrap_or(0);
        if pnd & blk != 0 {
            Some(blank_diag(
                "signal_blocked_handler_pending",
                "Pending signal blocked by sigprocmask",
                format!("SigPnd={:016x} & SigBlk={:016x} != 0", pnd, blk),
                Severity::Notice,
                Confidence::High,
            ))
        } else {
            None
        }
    }
);

/// All 38 scenarios declared above.
pub fn registry() -> &'static [&'static (dyn Rule + 'static)] {
    static R: &[&'static (dyn Rule + 'static)] = &[
        &preemption_storm,
        &cpu_migration_thrash,
        &cpu_affinity_mismatch,
        &priority_inversion,
        &cpu_starvation,
        &cgroup_throttled,
        &rt_scheduling_pressure,
        &nice_demotion_live,
        &read_heavy,
        &write_heavy,
        &small_io_pattern,
        &fsync_wall,
        &nonblocking_poll_loop,
        &epoll_hot_fd,
        &select_vs_epoll_antipattern,
        &getdents_crawl,
        &splice_sendfile_opportunity,
        &brk_growth,
        &mmap_heap_fragmentation,
        &page_fault_major_storm,
        &madvise_dontneed_abuse,
        &rss_climb_steady,
        &reader_writer_imbalance,
        &spinlock_livelock_user,
        &convoying,
        &yield_loop,
        &many_short_locks,
        &connect_timeout_wall,
        &connection_reset_storm,
        &send_recv_imbalance,
        &tcp_small_segments,
        &respawn_loop,
        &exec_chain_long,
        &daemon_double_fork_detected,
        &oom_killer_proximate,
        &sigpipe_bleed,
        &timer_wheel_wobble,
        &signal_blocked_handler_pending,
    ];
    R
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn thirty_eight_rules_registered() {
        assert_eq!(registry().len(), 38);
    }
    #[test]
    fn ids_unique() {
        let ids: Vec<_> = registry().iter().map(|r| r.id()).collect();
        let mut s = ids.clone();
        s.sort();
        s.dedup();
        assert_eq!(ids.len(), s.len());
    }

    #[test]
    fn preemption_storm_fires_on_high_invol() {
        let st = AppState::new(1, "x".into());
        let th = RuleThresholds::new().f("invol_per_sec_min", 500.0);
        let mut h: VecDeque<TickSnapshot> = Default::default();
        h.push_back(TickSnapshot {
            involuntary_ctx: 0,
            ..Default::default()
        });
        h.push_back(TickSnapshot {
            involuntary_ctx: 10,
            ..Default::default()
        });
        h.push_back(TickSnapshot {
            involuntary_ctx: 100,
            ..Default::default()
        });
        h.push_back(TickSnapshot {
            involuntary_ctx: 700,
            ..Default::default()
        });
        assert!(preemption_storm.evaluate(&st, &th, &h, 4).is_some());
    }
}
