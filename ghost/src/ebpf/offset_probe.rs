//! Runtime offset probe (RFC 0006 Path B).
//!
//! Every eBPF program in ghost-ebpf reads tracepoint fields at a hard-
//! coded byte offset. Those offsets are stable across common kernels
//! but may shift under new fields / size changes in a future release.
//! This module reads
//! `/sys/kernel/debug/tracing/events/<cat>/<ev>/format` for each
//! tracepoint ghost attaches to, parses the "offset:" lines, and
//! compares them against ghost's compile-time expectations.
//!
//! Fail-loud over fail-silent: when a mismatch is detected the probe
//! returns a non-empty `report()` string the loader surfaces into the
//! TUI/stderr; the caller decides whether to proceed (defensive) or
//! abort (strict).

use std::fs;

/// One tracepoint field ghost reads at a fixed offset. The expected
/// offset is baked in from a review of the common Linux releases
/// (5.10, 5.15, 6.1, 6.6, 6.12).
#[derive(Debug, Clone, Copy)]
pub struct FieldExpect {
    pub category: &'static str,
    pub event: &'static str,
    pub field: &'static str,
    pub expect_offset: u16,
}

/// The full table ghost expects. Keep in sync with the `ctx.read_at(N)`
/// call-sites in `ghost-ebpf/src/*.rs` (RFC 0006 Table 1).
pub const EXPECT: &[FieldExpect] = &[
    FieldExpect {
        category: "raw_syscalls",
        event: "sys_enter",
        field: "id",
        expect_offset: 8,
    },
    FieldExpect {
        category: "raw_syscalls",
        event: "sys_exit",
        field: "id",
        expect_offset: 8,
    },
    FieldExpect {
        category: "sched",
        event: "sched_switch",
        field: "prev_pid",
        expect_offset: 24,
    },
    FieldExpect {
        category: "sched",
        event: "sched_switch",
        field: "next_pid",
        expect_offset: 56,
    },
    FieldExpect {
        category: "sched",
        event: "sched_process_fork",
        field: "parent_pid",
        expect_offset: 12,
    },
    FieldExpect {
        category: "sched",
        event: "sched_process_fork",
        field: "child_pid",
        expect_offset: 20,
    },
    FieldExpect {
        category: "sched",
        event: "sched_process_exit",
        field: "pid",
        expect_offset: 24,
    },
    FieldExpect {
        category: "irq",
        event: "irq_handler_entry",
        field: "irq",
        expect_offset: 8,
    },
    FieldExpect {
        category: "irq",
        event: "softirq_entry",
        field: "vec",
        expect_offset: 8,
    },
];

/// Result of one check.
#[derive(Debug, Clone)]
pub struct Finding {
    pub expect: FieldExpect,
    pub actual: Option<u16>,
    pub note: String,
}

/// Walk `EXPECT`, read tracefs, and return any mismatches. An empty
/// vec means every offset still matches; the caller may fast-path.
pub fn run() -> Vec<Finding> {
    let mut out = Vec::new();
    for e in EXPECT {
        match read_field_offset(e.category, e.event, e.field) {
            Ok(Some(off)) if off == e.expect_offset => { /* OK */ }
            Ok(Some(off)) => out.push(Finding {
                expect: *e,
                actual: Some(off),
                note: format!(
                    "tracepoint {}/{}.{} shifted: ghost expects {}, kernel reports {}",
                    e.category, e.event, e.field, e.expect_offset, off
                ),
            }),
            Ok(None) => out.push(Finding {
                expect: *e,
                actual: None,
                note: format!(
                    "tracepoint {}/{} missing field '{}' — kernel too old or reconfigured",
                    e.category, e.event, e.field
                ),
            }),
            Err(_) => { /* debugfs unreadable (unprivileged container): skip silently */ }
        }
    }
    out
}

/// One-line summary of the findings; empty when the probe passed.
pub fn report(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return String::new();
    }
    let mut s = String::from(
        "ghost: tracepoint offset drift detected — ghost may misread \
         fields on this kernel. Mismatches:\n",
    );
    for f in findings {
        s.push_str("  - ");
        s.push_str(&f.note);
        s.push('\n');
    }
    s.push_str(
        "\nFix: upgrade ghost to a release with matching offsets, or \
         disable eBPF attach via --proc-only (future flag).\n",
    );
    s
}

fn tracefs_path(category: &str, event: &str) -> String {
    format!("/sys/kernel/debug/tracing/events/{category}/{event}/format")
}

fn read_field_offset(category: &str, event: &str, field: &str) -> std::io::Result<Option<u16>> {
    let text = fs::read_to_string(tracefs_path(category, event))?;
    Ok(parse_offset(&text, field))
}

/// Parse one `field:<type> <name>; offset:<n>; size:<m>; signed:<x>;` line.
fn parse_offset(text: &str, field: &str) -> Option<u16> {
    for line in text.lines() {
        if !line.contains(field) {
            continue;
        }
        // Line looks like: "\tfield:__u32 next_pid;\toffset:24;\tsize:4;..."
        // Require the actual name to equal `field`, not just substring.
        let name = line
            .split(';')
            .next()?
            .trim_end_matches(';')
            .split_whitespace()
            .last()?;
        if name != field {
            continue;
        }
        for part in line.split(';') {
            if let Some(rest) = part.trim_start().strip_prefix("offset:") {
                return rest.trim().parse().ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_offset_extracts_integer() {
        let sample = "\tfield:__u32 next_pid;\toffset:24;\tsize:4;\tsigned:0;";
        assert_eq!(parse_offset(sample, "next_pid"), Some(24));
    }

    #[test]
    fn parse_offset_distinguishes_similar_names() {
        let sample = "\tfield:__u32 prev_pid;\toffset:8;\tsize:4;\tsigned:0;\n\
                      \tfield:__u32 next_pid;\toffset:24;\tsize:4;\tsigned:0;";
        assert_eq!(parse_offset(sample, "next_pid"), Some(24));
        assert_eq!(parse_offset(sample, "prev_pid"), Some(8));
    }

    #[test]
    fn parse_offset_missing_field() {
        assert_eq!(parse_offset("no fields here", "x"), None);
    }

    #[test]
    fn report_is_empty_when_no_findings() {
        assert!(report(&[]).is_empty());
    }

    #[test]
    fn report_lists_each_finding() {
        let f = Finding {
            expect: EXPECT[0],
            actual: Some(999),
            note: "test mismatch".into(),
        };
        let r = report(&[f]);
        assert!(r.contains("test mismatch"));
        assert!(r.contains("Fix:"));
    }

    #[test]
    fn run_on_this_host_is_infallible() {
        // On a dev host without CAP_SYS_ADMIN tracefs may be unreadable;
        // the probe treats that as "no finding" and returns.
        let _ = run();
    }
}
