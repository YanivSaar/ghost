//! Scenario analyzer — "what's happening" diagnoses on top of `AppState`.
//!
//! RFC 0001. Engine ticks once per /proc poll (1 Hz) and emits
//! `Diagnosis` values. The TUI's analyze screen renders the current set
//! + a 10-minute history; `ghost analyze` dumps a timeline / JSON / JSONL.

pub mod config;
pub mod defaults;
pub mod engine;
pub mod json;
pub mod report;
pub mod rules;
pub mod scenarios;

use std::collections::VecDeque;

pub use config::{AnalyzerConfig, ConfigSource, RuleThresholds};
pub use engine::{AnalyzerEngine, TickSnapshot};

/// How bad is this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Notice,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Quiet,
    Noisy,
}

/// A single signal that contributed to a `Diagnosis` firing.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SignalRef {
    pub kind: &'static str,
    pub value: f64,
    pub threshold: f64,
}

/// One finding emitted by a rule for a tick.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Diagnosis {
    pub id: &'static str,
    pub headline: String,
    pub detail: String,
    pub signals: Vec<SignalRef>,
    pub severity: Severity,
    pub confidence: Confidence,
    pub suggestion: Option<String>,
    pub first_seen_tick: u64,
    pub last_seen_tick: u64,
    pub consecutive_ticks: u32,
}

/// Public analyzer snapshot used by the TUI screen.
#[derive(Debug, Default)]
pub struct AnalyzerState {
    pub current: Vec<Diagnosis>,
    pub history: VecDeque<HistoryEntry>,
    pub mode: Mode,
    pub config_source: ConfigSource,
    pub last_status_line: Option<String>,
    pub tick: u64,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::Quiet
    }
}

/// One finding row for the history pane.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HistoryEntry {
    pub id: &'static str,
    pub headline: String,
    pub first_tick: u64,
    pub last_tick: u64,
    pub severity: Severity,
    pub confidence: Confidence,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::Warning => "WARNING",
        }
    }
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }
}
