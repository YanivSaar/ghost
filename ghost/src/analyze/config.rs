//! TOML config loading + merge semantics for analyzer thresholds.
//!
//! Everything is optional. Missing file / empty file / malformed TOML →
//! compiled defaults with a status-bar line. Partial file → merge
//! per-rule, with any missing key filled from defaults.

use crate::analyze::{defaults, Confidence, Mode};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A single rule's threshold table — mixed-typed (f64 / bool / string).
/// All lookups are infallible: a missing key returns a sensible fallback.
#[derive(Debug, Clone, Default)]
pub struct RuleThresholds {
    floats: HashMap<&'static str, f64>,
    bools: HashMap<&'static str, bool>,
    confidence_floor: Option<Confidence>,
    enabled_override: Option<bool>,
}

impl RuleThresholds {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn f(mut self, k: &'static str, v: f64) -> Self {
        self.floats.insert(k, v);
        self
    }
    pub fn b(mut self, k: &'static str, v: bool) -> Self {
        self.bools.insert(k, v);
        self
    }
    pub fn get_f(&self, k: &str, fallback: f64) -> f64 {
        self.floats
            .iter()
            .find(|(kk, _)| **kk == k)
            .map(|(_, v)| *v)
            .unwrap_or(fallback)
    }
    pub fn get_b(&self, k: &str, fallback: bool) -> bool {
        self.bools
            .iter()
            .find(|(kk, _)| **kk == k)
            .map(|(_, v)| *v)
            .unwrap_or(fallback)
    }
    pub fn enabled(&self) -> bool {
        // Rules default to enabled; the per-rule `enabled = false`
        // (either in `b()` or via config) suppresses the rule.
        self.enabled_override
            .unwrap_or_else(|| self.get_b("enabled", true))
    }
    pub fn set_enabled(&mut self, v: bool) {
        self.enabled_override = Some(v);
    }
    pub fn confidence_floor(&self) -> Option<Confidence> {
        self.confidence_floor
    }
    pub fn set_confidence_floor(&mut self, c: Option<Confidence>) {
        self.confidence_floor = c;
    }

    /// Overlay keys from `other` onto `self`. Any key present in `other`
    /// wins; keys absent from `other` keep `self`'s value.
    pub fn merge(&mut self, other: &RuleThresholds) {
        for (k, v) in &other.floats {
            self.floats.insert(*k, *v);
        }
        for (k, v) in &other.bools {
            self.bools.insert(*k, *v);
        }
        if other.confidence_floor.is_some() {
            self.confidence_floor = other.confidence_floor;
        }
        if other.enabled_override.is_some() {
            self.enabled_override = other.enabled_override;
        }
    }
}

/// Where the live threshold table came from — surfaced to the TUI as a
/// one-line status note.
#[derive(Debug, Clone)]
pub enum ConfigSource {
    UserFile(PathBuf),
    Defaults { reason: String },
}

impl Default for ConfigSource {
    fn default() -> Self {
        ConfigSource::Defaults {
            reason: "no config loaded".into(),
        }
    }
}

impl ConfigSource {
    pub fn status_line(&self) -> String {
        match self {
            ConfigSource::UserFile(p) => format!("analyze: using {}", p.display()),
            ConfigSource::Defaults { reason } => {
                format!("analyze: using built-in thresholds ({reason})")
            }
        }
    }
}

/// Merged threshold table for every rule + global defaults (mode,
/// toggles). Produced by `load_or_default`.
#[derive(Debug, Clone)]
pub struct AnalyzerConfig {
    pub rules: HashMap<&'static str, RuleThresholds>,
    pub default_mode: Mode,
    pub source: ConfigSource,
}

impl AnalyzerConfig {
    pub fn built_in() -> Self {
        AnalyzerConfig {
            rules: defaults::defaults(),
            default_mode: Mode::Quiet,
            source: ConfigSource::default(),
        }
    }
}

/// Resolve `$XDG_CONFIG_HOME/ghost/analyze.toml` or
/// `$HOME/.config/ghost/analyze.toml`.
pub fn default_config_path() -> Option<PathBuf> {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("ghost").join("analyze.toml"));
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.is_empty() {
            return Some(
                PathBuf::from(home)
                    .join(".config")
                    .join("ghost")
                    .join("analyze.toml"),
            );
        }
    }
    None
}

/// Load the config, falling back to defaults for every error. Never
/// returns Err — the engine is defensive on purpose.
pub fn load_or_default(explicit: Option<&Path>) -> AnalyzerConfig {
    let mut cfg = AnalyzerConfig::built_in();
    let path = match explicit {
        Some(p) => Some(p.to_path_buf()),
        None => default_config_path(),
    };

    let Some(path) = path else {
        cfg.source = ConfigSource::Defaults {
            reason: "no $XDG_CONFIG_HOME or $HOME".into(),
        };
        return cfg;
    };

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_e) => {
            cfg.source = ConfigSource::Defaults {
                reason: format!("config not found: {}", path.display()),
            };
            return cfg;
        }
    };

    if text.trim().is_empty() {
        cfg.source = ConfigSource::Defaults {
            reason: format!("empty config: {}", path.display()),
        };
        return cfg;
    }

    let parsed: toml::Value = match text.parse() {
        Ok(v) => v,
        Err(e) => {
            cfg.source = ConfigSource::Defaults {
                reason: format!("malformed TOML at {}: {}", path.display(), e),
            };
            return cfg;
        }
    };

    apply_toml(&mut cfg, &parsed);
    cfg.source = ConfigSource::UserFile(path);
    cfg
}

fn apply_toml(cfg: &mut AnalyzerConfig, root: &toml::Value) {
    if let Some(mode_tbl) = root.get("mode").and_then(|v| v.as_table()) {
        if let Some(s) = mode_tbl.get("default").and_then(|v| v.as_str()) {
            cfg.default_mode = match s {
                "noisy" => Mode::Noisy,
                _ => Mode::Quiet,
            };
        }
    }
    if let Some(rule_tbl) = root.get("rule").and_then(|v| v.as_table()) {
        for (rule_id, cfg_val) in rule_tbl {
            let Some(cfg_val) = cfg_val.as_table() else {
                continue;
            };
            // Find the slot by matching the dynamic key against our
            // static rule ids.
            let key_static: Option<&'static str> =
                cfg.rules.keys().find(|k| **k == rule_id.as_str()).copied();
            let Some(key_static) = key_static else {
                continue;
            };
            let slot = cfg.rules.get_mut(key_static).unwrap();
            for (k, v) in cfg_val {
                match k.as_str() {
                    "enabled" => {
                        if let Some(b) = v.as_bool() {
                            slot.set_enabled(b);
                        }
                    }
                    "confidence_floor" => {
                        if let Some(s) = v.as_str() {
                            slot.set_confidence_floor(parse_confidence(s));
                        }
                    }
                    other => {
                        if let Some(f) = v.as_float() {
                            slot.floats.insert(static_key_for(other).unwrap_or("_"), f);
                        } else if let Some(i) = v.as_integer() {
                            slot.floats
                                .insert(static_key_for(other).unwrap_or("_"), i as f64);
                        }
                    }
                }
            }
        }
    }
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    match s {
        "low" => Some(Confidence::Low),
        "medium" | "med" => Some(Confidence::Medium),
        "high" => Some(Confidence::High),
        _ => None,
    }
}

/// Intern a dynamic key into the `&'static str` space our tables use.
/// The known-key set is small enough that this is a boring match.
fn static_key_for(s: &str) -> Option<&'static str> {
    match s {
        "cpu_pct_min" => Some("cpu_pct_min"),
        "cpu_pct_max" => Some("cpu_pct_max"),
        "syscalls_per_sec_max" => Some("syscalls_per_sec_max"),
        "syscalls_per_sec_min" => Some("syscalls_per_sec_min"),
        "involuntary_ctx_per_sec_min" => Some("involuntary_ctx_per_sec_min"),
        "vol_over_invol_ratio_min" => Some("vol_over_invol_ratio_min"),
        "io_syscalls_share_min" => Some("io_syscalls_share_min"),
        "futex_count_min" => Some("futex_count_min"),
        "wait_p99_ms_min" => Some("wait_p99_ms_min"),
        "blocked_thread_count_min" => Some("blocked_thread_count_min"),
        "futex_wait_min" => Some("futex_wait_min"),
        "quiet_ticks_min" => Some("quiet_ticks_min"),
        "cold_entries_max" => Some("cold_entries_max"),
        "archetype_confidence_min" => Some("archetype_confidence_min"),
        "irq_share_min" => Some("irq_share_min"),
        "clones_per_sec_min" => Some("clones_per_sec_min"),
        "exits_per_sec_min" => Some("exits_per_sec_min"),
        "exits_per_sec_max" => Some("exits_per_sec_max"),
        "period_ms_min" => Some("period_ms_min"),
        "period_ms_max" => Some("period_ms_max"),
        "cycles_min" => Some("cycles_min"),
        "signal_syscalls_per_sec_min" => Some("signal_syscalls_per_sec_min"),
        "mmap_per_sec_min" => Some("mmap_per_sec_min"),
        "munmap_per_sec_min" => Some("munmap_per_sec_min"),
        "balance_pct_max" => Some("balance_pct_max"),
        "wait4_per_sec_min" => Some("wait4_per_sec_min"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_has_every_rule() {
        let cfg = AnalyzerConfig::built_in();
        for id in [
            "cpu_bound_user",
            "cpu_bound_kernel",
            "io_bound",
            "futex_contention",
            "possible_deadlock",
            "startup_phase",
            "jitter_from_irq",
            "fork_storm",
            "gc_like_pause",
            "signal_pressure",
            "mmap_thrash",
            "zombie_reap_delay",
        ] {
            assert!(cfg.rules.contains_key(id), "missing default for {id}");
        }
    }

    #[test]
    fn missing_file_yields_defaults_with_reason() {
        let cfg = load_or_default(Some(Path::new("/no/such/path/analyze.toml")));
        match &cfg.source {
            ConfigSource::Defaults { reason } => assert!(reason.contains("config not found")),
            _ => panic!("expected defaults"),
        }
    }

    #[test]
    fn malformed_toml_yields_defaults() {
        let path = std::env::temp_dir().join("ghost-analyze-bad.toml");
        std::fs::write(&path, "not = valid = toml").unwrap();
        let cfg = load_or_default(Some(&path));
        matches!(cfg.source, ConfigSource::Defaults { .. });
    }

    #[test]
    fn partial_toml_merges_onto_defaults() {
        let path = std::env::temp_dir().join("ghost-analyze-partial.toml");
        std::fs::write(
            &path,
            "[rule.cpu_bound_user]\ncpu_pct_min = 70.0\nenabled = true\n",
        )
        .unwrap();
        let cfg = load_or_default(Some(&path));
        let slot = cfg.rules.get("cpu_bound_user").unwrap();
        assert_eq!(slot.get_f("cpu_pct_min", 999.0), 70.0);
        // default kept:
        assert_eq!(slot.get_f("syscalls_per_sec_max", 999.0), 50.0);
    }

    #[test]
    fn mode_default_quiet_or_noisy() {
        let path = std::env::temp_dir().join("ghost-analyze-mode.toml");
        std::fs::write(&path, "[mode]\ndefault = \"noisy\"\n").unwrap();
        let cfg = load_or_default(Some(&path));
        assert_eq!(cfg.default_mode, Mode::Noisy);
    }

    #[test]
    fn empty_file_yields_defaults() {
        let path = std::env::temp_dir().join("ghost-analyze-empty.toml");
        std::fs::write(&path, "   \n\n").unwrap();
        let cfg = load_or_default(Some(&path));
        matches!(cfg.source, ConfigSource::Defaults { .. });
    }
}
