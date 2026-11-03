//! Report helpers: render the TUI / CLI timeline from an `AnalyzerState`.

use crate::analyze::{AnalyzerState, Diagnosis};
use std::fmt::Write;

/// Format one diagnosis as a plain-text line (tick-aligned "mm:ss.sss id SEV ...").
pub fn format_plain(d: &Diagnosis, ts_ms: u64) -> String {
    let min = ts_ms / 60_000;
    let sec = (ts_ms % 60_000) / 1000;
    let ms = ts_ms % 1000;
    format!(
        "{:02}:{:02}.{:03}  {:<22} {:<7} {}",
        min,
        sec,
        ms,
        d.id,
        d.confidence.label(),
        d.headline
    )
}

/// Render the current + history pane as a flat multi-line string.
/// Used by `w` in the TUI to write a plain-text report.
pub fn plain_report(st: &AnalyzerState) -> String {
    let mut out = String::new();
    writeln!(
        &mut out,
        "ghost analyze — tick {}, mode {:?}",
        st.tick, st.mode
    )
    .ok();
    writeln!(&mut out, "{}", st.config_source.status_line()).ok();
    writeln!(&mut out, "-- Current --").ok();
    for d in &st.current {
        writeln!(&mut out, "  {} [{}]  {}", d.id, d.confidence.label(), d.headline).ok();
        if !d.detail.is_empty() {
            writeln!(&mut out, "    {}", d.detail).ok();
        }
    }
    writeln!(&mut out, "-- History ({} rows) --", st.history.len()).ok();
    for h in &st.history {
        writeln!(
            &mut out,
            "  tick {}..{}  {} [{}]  {}",
            h.first_tick,
            h.last_tick,
            h.id,
            h.confidence.label(),
            h.headline
        )
        .ok();
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{Confidence, Severity};

    fn mk_diag() -> Diagnosis {
        Diagnosis {
            id: "cpu_bound_user",
            headline: "CPU-bound".into(),
            detail: "det".into(),
            signals: vec![],
            severity: Severity::Notice,
            confidence: Confidence::High,
            suggestion: None,
            first_seen_tick: 0,
            last_seen_tick: 0,
            consecutive_ticks: 1,
        }
    }

    #[test]
    fn format_plain_shapes_timestamp() {
        let s = format_plain(&mk_diag(), 65432);
        assert!(s.starts_with("01:05.432"), "unexpected: {s}");
        assert!(s.contains("cpu_bound_user"));
        assert!(s.contains("HIGH"));
    }
}
