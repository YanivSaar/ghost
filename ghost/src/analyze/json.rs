//! JSON array + JSONL emitters for `ghost analyze`.

use crate::analyze::Diagnosis;
use serde::Serialize;

#[derive(Serialize)]
pub struct JsonEvent<'a> {
    pub ts_ms: u64,
    pub event: &'a str,
    pub id: &'static str,
    pub severity: crate::analyze::Severity,
    pub confidence: crate::analyze::Confidence,
    pub headline: &'a str,
    pub detail: &'a str,
    pub signals: &'a [crate::analyze::SignalRef],
}

/// Build the `begin` event for a diagnosis.
pub fn begin_event<'a>(ts_ms: u64, d: &'a Diagnosis) -> JsonEvent<'a> {
    JsonEvent {
        ts_ms,
        event: "begin",
        id: d.id,
        severity: d.severity,
        confidence: d.confidence,
        headline: &d.headline,
        detail: &d.detail,
        signals: &d.signals,
    }
}

#[derive(Serialize)]
pub struct EndEvent {
    pub ts_ms: u64,
    pub event: &'static str,
    pub id: &'static str,
}

pub fn end_event(ts_ms: u64, id: &'static str) -> EndEvent {
    EndEvent {
        ts_ms,
        event: "end",
        id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze::{Confidence, Severity};

    #[test]
    fn begin_event_serializes_as_json_object() {
        let d = Diagnosis {
            id: "cpu_bound_user",
            headline: "h".into(),
            detail: "d".into(),
            signals: vec![],
            severity: Severity::Notice,
            confidence: Confidence::Medium,
            suggestion: None,
            first_seen_tick: 0,
            last_seen_tick: 0,
            consecutive_ticks: 0,
        };
        let s = serde_json::to_string(&begin_event(123, &d)).unwrap();
        assert!(s.contains("\"ts_ms\":123"));
        assert!(s.contains("\"event\":\"begin\""));
        assert!(s.contains("\"id\":\"cpu_bound_user\""));
        assert!(s.contains("\"severity\":\"notice\""));
        assert!(s.contains("\"confidence\":\"medium\""));
    }

    #[test]
    fn end_event_serializes() {
        let s = serde_json::to_string(&end_event(99, "cpu_bound_user")).unwrap();
        assert!(s.contains("\"event\":\"end\""));
        assert!(s.contains("\"id\":\"cpu_bound_user\""));
    }
}
