//! Compiled defaults for every rule. Used when the config file is
//! missing, empty, malformed, or has a specific key omitted.

use crate::analyze::config::RuleThresholds;
use std::collections::HashMap;

/// Build the default threshold table for all RFC-0001 rules.
pub fn defaults() -> HashMap<&'static str, RuleThresholds> {
    let mut m = HashMap::new();

    m.insert(
        "cpu_bound_user",
        RuleThresholds::new()
            .f("cpu_pct_min", 80.0)
            .f("syscalls_per_sec_max", 50.0),
    );
    m.insert(
        "cpu_bound_kernel",
        RuleThresholds::new()
            .f("cpu_pct_min", 80.0)
            .f("involuntary_ctx_per_sec_min", 100.0)
            .f("syscalls_per_sec_min", 500.0),
    );
    m.insert(
        "io_bound",
        RuleThresholds::new()
            .f("vol_over_invol_ratio_min", 4.0)
            .f("io_syscalls_share_min", 0.5),
    );
    m.insert(
        "futex_contention",
        RuleThresholds::new()
            .f("futex_count_min", 20.0)
            .f("wait_p99_ms_min", 10.0)
            .f("blocked_thread_count_min", 2.0),
    );
    m.insert(
        "possible_deadlock",
        RuleThresholds::new()
            .f("cpu_pct_max", 1.0)
            .f("futex_wait_min", 2.0)
            .f("quiet_ticks_min", 3.0),
    );
    m.insert(
        "startup_phase",
        RuleThresholds::new()
            .f("cold_entries_max", 5.0)
            .f("archetype_confidence_min", 0.6),
    );
    m.insert(
        "jitter_from_irq",
        RuleThresholds::new().f("irq_share_min", 0.5),
    );
    m.insert(
        "fork_storm",
        RuleThresholds::new()
            .f("clones_per_sec_min", 5.0)
            .f("exits_per_sec_min", 5.0),
    );
    m.insert(
        "gc_like_pause",
        RuleThresholds::new()
            .b("enabled", false)
            .f("period_ms_min", 10.0)
            .f("period_ms_max", 200.0)
            .f("cycles_min", 3.0),
    );
    m.insert(
        "signal_pressure",
        RuleThresholds::new().f("signal_syscalls_per_sec_min", 50.0),
    );
    m.insert(
        "mmap_thrash",
        RuleThresholds::new()
            .f("mmap_per_sec_min", 20.0)
            .f("munmap_per_sec_min", 20.0)
            .f("balance_pct_max", 20.0),
    );
    m.insert(
        "zombie_reap_delay",
        RuleThresholds::new()
            .f("wait4_per_sec_min", 10.0)
            .f("exits_per_sec_max", 2.0),
    );

    m
}
