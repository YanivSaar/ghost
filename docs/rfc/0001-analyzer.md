# RFC 0001: Scenario analyzer + "what's happening" diagnosis

**Status:** Proposal (not yet implemented)
**Scope:** This PR tracks the proposal only. Implementation lands in a follow-up PR against this issue once the design is accepted.

## Motivation

Ghost today exposes raw signals (syscall histograms, lock waits, catch events, jitter attribution, cold-start timeline, ctx-switch rates) but leaves interpretation to the user. The user has to recognise, e.g., "500 futex_wait + near-zero CPU% + 20 threads blocked = classic contended-lock stall" by eye.

**Goal:** a pluggable scenario engine that watches the live `AppState` and surfaces a plain-English diagnosis — "process is CPU-bound in user space", "possible deadlock on futex 0x7f…", "startup phase, not steady state yet" — with the signals that triggered it.

## Decisions baked in

| Decision | Value |
|---|---|
| Catalog size (this PR) | **12 rules** |
| Surface | **Dedicated TUI screen** (not a strip); accessible via `a` key or `--screen=analyze` |
| CLI output | **Plain-text timeline by default**, `--json` emits a single JSON array, `--jsonl` streams JSON Lines |
| Thresholds | **Config-file driven**; defaults compiled in; missing / empty / malformed file → fall back to defaults silently with a line in the TUI status bar (`using built-in thresholds`) |
| Config path | **XDG-compliant**: `$XDG_CONFIG_HOME/ghost/analyze.toml`, falling back to `$HOME/.config/ghost/analyze.toml`. CLI `--config <path>` overrides. |
| Verbosity | **Runtime toggle `n` ↔ `q`** (noisy / quiet); `--mode=noisy\|quiet` CLI override; initial mode read from config |
| History depth | **10 minutes** at 1 Hz = **600 ticks** |
| Follow-up PR | **Yes**: `feat: expand analyzer to 50 scenarios` — proposal in RFC 0002 (listed below) |

## Shape

```
ghost/src/analyze/
├── mod.rs                 — Diagnosis, Severity, Confidence, Mode, EngineHandle
├── engine.rs              — fn tick(state, cfg, mode) -> Vec<Diagnosis>; history ring (600 slots)
├── rules.rs               — trait Rule { fn id, fn evaluate }
├── config.rs              — TOML schema; serde_derive; load_or_default()
├── report.rs              — rank/dedupe/filter-by-mode
├── json.rs                — JSON (array) + JSONL serializers for `ghost analyze`
├── defaults.rs            — baked thresholds, used when config missing/empty/malformed
└── scenarios/             (12 rules this PR; see §Appendix A)
    ├── cpu_bound_user.rs
    ├── cpu_bound_kernel.rs
    ├── io_bound.rs
    ├── futex_contention.rs
    ├── possible_deadlock.rs
    ├── startup_phase.rs
    ├── jitter_from_irq.rs
    ├── fork_storm.rs
    ├── gc_like_pause.rs
    ├── signal_pressure.rs
    ├── mmap_thrash.rs
    └── zombie_reap_delay.rs

ghost/src/tui/screens/analyze.rs    — new dedicated screen
ghost/src/tui/app.rs                — add ActiveScreen::Analyze + `a` key binding
ghost/src/main.rs                   — new `ghost analyze` subcommand
```

## Core types

```rust
pub enum Severity   { Info, Notice, Warning }
pub enum Confidence { Low, Medium, High }
pub enum Mode       { Quiet, Noisy }

pub struct SignalRef {
    pub kind: &'static str,     // "syscall:futex" | "ctx:involuntary" | "jitter:irq:7"
    pub value: f64,             // numeric value that matched
    pub threshold: f64,         // what the rule compared against
}

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
    pub consecutive_ticks: u32,     // debouncing / escalation
}

pub struct AnalyzerState {
    pub current: Vec<Diagnosis>,
    pub history: VecDeque<TickSnapshot>,  // 600 ticks = 10 minutes @ 1 Hz
    pub mode: Mode,
    pub config_source: ConfigSource,      // UserFile(path) | Defaults { reason }
}
```

## Rule trait

```rust
pub trait Rule: Send + Sync {
    fn id(&self) -> &'static str;
    fn evaluate(&self, s: &AppState, cfg: &RuleThresholds, hist: &History) -> Option<Diagnosis>;
    fn severity_at_defaults(&self) -> Severity;
}
```

Each rule is one small file. **No cross-rule state**; the engine owns the history ring and hands rules a view.

## Config format

**Path:** `$XDG_CONFIG_HOME/ghost/analyze.toml`, falling back to `$HOME/.config/ghost/analyze.toml`. If neither resolves (missing `$HOME`), compiled defaults apply.

**File is entirely optional.** Any missing key falls back to `defaults.rs`. If the whole file is missing, empty, or malformed, the engine logs one line to the TUI status bar (`analyze: using built-in thresholds (<reason>)`) and runs with defaults — no error, no exit.

```toml
# every section + every key is optional
[mode]
default = "quiet"              # "quiet" | "noisy"

[rule.cpu_bound_user]
enabled = true
cpu_pct_min = 80.0
syscalls_per_sec_max = 50
confidence_floor = "medium"    # suppress Low findings for this rule

[rule.futex_contention]
enabled = true
wait_p99_ms_min = 10
blocked_thread_count_min = 2

[rule.possible_deadlock]
enabled = true
quiet_ticks_min = 3            # must stay stuck N ticks before firing
cpu_pct_max = 1.0

[rule.jitter_from_irq]
enabled = true
irq_share_min = 0.5            # ≥50% of jitter attributable to one IRQ

[rule.gc_like_pause]
enabled = false                # off by default; opt-in
period_ms_min = 10
period_ms_max = 200

# ... one section per rule, all optional
```

**Precedence:** CLI flag > config file > compiled defaults. An ad-hoc single-key override via `--threshold cpu_bound_user.cpu_pct_min=70` is supported.

## Noisy / Quiet modes

- **Quiet** (default): emits `Confidence::High` + `Confidence::Medium` findings only; dedupes same-id within a 10-tick window.
- **Noisy**: emits all confidences, no dedupe window. Shows every tick's hits.

Toggle at runtime: press `n` for noisy, `q` for quiet (status bar reflects current mode). The toggle is per-session; config file sets the initial mode.

## TUI screen (new, dedicated)

```
┌─ What's happening ────────────────────────────── mode: quiet · 12 rules ─┐
│                                                                           │
│  ⚠  Possible deadlock on futex                            HIGH   now     │
│     7 threads waiting for 4.2s on 0x7f3a2c0010a0; no progress ticks: 4   │
│     → try: ghost lock <pid>                                              │
│                                                                           │
│  ●  CPU-bound in user space                              MEDIUM  now     │
│     92% CPU, 12 syscalls/s — compute loop or busy-wait                   │
│                                                                           │
│  ·  Jitter attributable to IRQ 46 (nvme0q0)                 LOW   -2s   │
│     68% of jitter samples                                                │
│                                                                           │
├─ History (last 10 min) ──────────────────────────────────────────────────┤
│  00:12  jitter_from_irq      LOW     resolved @ 00:14                   │
│  00:08  startup_phase        MEDIUM  resolved @ 00:11                   │
│  00:00  —                                                                │
└─ a:this  n:noisy  q:quiet  ↩:expand  r:reload-config  w:write-report ───┘
```

Interactions:
- `a` from any lens → jump to this screen.
- `↩` on a highlighted row → expand to full detail panel (headline + detail + every `SignalRef` + suggestion).
- `r` → reload config file without restart.
- `w` → write current + history to `~/.local/share/ghost/report-<ts>.txt` (plain text).
- `n` / `q` → toggle mode.

## CLI: `ghost analyze`

Two forms:

```
# Offline: analyze a recorded session
ghost analyze path/to/session.ghost
ghost analyze path/to/session.ghost --json
ghost analyze path/to/session.ghost --jsonl
ghost analyze path/to/session.ghost --mode=noisy

# One-shot live: attach briefly, dump diagnoses, exit
ghost analyze --pid 1234 --duration 10s
ghost analyze --pid 1234 --duration 10s --jsonl
```

### Output formats

**Plain text (default):** chronological timeline:

```
00:00.000  startup_phase          MEDIUM   process in cold-start syscall window
00:03.142  cpu_bound_user         MEDIUM   92% CPU, 12 syscalls/s
00:08.721  cpu_bound_user         resolved
00:08.721  futex_contention       HIGH     7 threads waiting on 0x7f3a2c0010a0 (p99 42ms)
00:12.004  possible_deadlock      HIGH     escalation: no progress for 3 ticks
```

**JSON array (`--json`):** single top-level array; good for scripts that `jq` the whole run after it exits.

```json
[
  {"ts_ms":0,"event":"begin","id":"startup_phase","severity":"notice","confidence":"medium","headline":"…","signals":[…]},
  {"ts_ms":3142,"event":"begin","id":"cpu_bound_user","severity":"notice","confidence":"medium","signals":[…]},
  {"ts_ms":8721,"event":"end","id":"cpu_bound_user"}
]
```

**JSONL (`--jsonl`):** one JSON object per line; stream-friendly for pipelines that process events as they land.

```json
{"ts_ms":0,"event":"begin","id":"startup_phase",…}
{"ts_ms":3142,"event":"begin","id":"cpu_bound_user",…}
{"ts_ms":8721,"event":"end","id":"cpu_bound_user"}
```

`--json` and `--jsonl` are mutually exclusive; plain-text is the default when neither is set.

## Engine timing

- Runs on the existing `/proc` poller tick (1 Hz). No new threads.
- All rules operate on a single `AppState` read-lock snapshot per tick.
- History ring: 600 slots × ~ (12 rule-states + core signals) ≈ 100 KiB.
- Expected per-tick cost: < 500 µs across all 12 rules (threshold-only scalar comparisons on fields already materialized).

## This PR's rule set (12)

See §Appendix A for the full list with default thresholds and the `AppState` fields each rule reads.

## Follow-up PR

`feat: expand analyzer to 50 scenarios` — see RFC 0002 (will be filed as a separate issue). This PR reserves the 38 extra rule-ids as `// TODO: next PR` constants in `scenarios/mod.rs` so renaming is unnecessary later.

## Testing

- **Per-rule unit tests**: positive-fire, negative-no-fire, boundary. ≥3 tests × 12 rules = ~36 tests.
- **Engine tests**: history ring correctness (600-slot wrap), dedupe window behaviour in quiet mode, mode-toggle idempotency.
- **Config tests**: missing file → defaults, empty file → defaults, malformed TOML → defaults + status bar note, partial file → merge semantics, CLI override wins, XDG path resolution.
- **Replay integration test**: craft a `.ghost` fixture that forces `futex_contention` + `cpu_bound_user` + `possible_deadlock` transitions in sequence; assert exact plain-text, JSON, and JSONL outputs.
- Total new tests: ~55 (120 → ~175).

## Scope / size

| | lines |
|---|---|
| `analyze/` module | ~750 |
| 12 scenario files | ~500 (≈40 each) |
| `tui/screens/analyze.rs` | ~250 |
| `tui/app.rs` wiring | ~30 |
| `supervisor.rs` + `main.rs` CLI wiring | ~80 |
| Tests | ~400 |
| **Total** | **~2000 LoC** |

New deps: `toml` (parse-only features).

## Risk / rollout

- Pure additive; existing lenses untouched.
- Config file is opt-in; the engine runs on defaults for every existing user.
- Noisy mode is opt-in via keypress / flag.
- The dedicated screen is reached only via `a` or `--screen=analyze`; TUI default start remains overview.

---

## Appendix A — The 12 rules in this PR (with defaults)

| id | triggers when | default thresholds | severity | reads |
|---|---|---|---|---|
| `cpu_bound_user` | high CPU, low syscall rate | cpu ≥ 80%, syscalls/s ≤ 50 | Notice | `watch.cpu_history`, syscall_stat |
| `cpu_bound_kernel` | high CPU, high involuntary ctx, high syscall rate | cpu ≥ 80%, invol_ctx/s ≥ 100, syscalls/s ≥ 500 | Notice | watch, consumer counters |
| `io_bound` | voluntary ctx dominant, I/O syscalls top | vol/invol ≥ 4, top-3 includes read/write/poll | Notice | watch, syscall_stat |
| `futex_contention` | many futex waits, high p99 | futex count ≥ 20/tick, p99 ≥ 10 ms, ≥ 2 blockers | Warning | lock lens |
| `possible_deadlock` | futex waits + no CPU + no progress | cpu ≤ 1 %, futex waits ≥ 2, 3 consecutive ticks | Warning | lock lens, watch |
| `startup_phase` | cold stats still filling, startup syscall mix | cold entries ≤ 5, archetype confidence ≥ 0.6 | Info | cold lens |
| `jitter_from_irq` | one IRQ dominates attribution | share ≥ 50 % of jitter samples | Notice | jitter lens |
| `fork_storm` | clone+exit rate elevated | ≥ 5 clone/s AND ≥ 5 exit/s | Warning | syscall_stat, exit events |
| `gc_like_pause` | periodic quiet-busy pattern | pause 10-200 ms, ≥ 3 cycles | Info (off by default) | cpu_history |
| `signal_pressure` | signal syscalls elevated | rt_sigprocmask / kill / tgkill ≥ 50/s combined | Info | syscall_stat |
| `mmap_thrash` | mmap+munmap near-equal, high rate | ≥ 20/s each AND \|diff\| ≤ 20 % | Notice | syscall_stat |
| `zombie_reap_delay` | wait4 ≫ exits observed | wait4 ≥ 10/s AND exits/s ≤ 2 | Info | syscall_stat, exit events |

## Appendix B — Config precedence (worked example)

If user runs:
```
ghost watch 1234 --config /etc/ghost/custom.toml --threshold cpu_bound_user.cpu_pct_min=70
```
and `/etc/ghost/custom.toml` contains `[rule.cpu_bound_user] cpu_pct_min = 85`:

```
compiled default:                  cpu_pct_min = 80.0
← config file override:            cpu_pct_min = 85.0
← CLI --threshold override:        cpu_pct_min = 70.0  ← wins
```

If `/etc/ghost/custom.toml` doesn't exist:
```
status bar: analyze: using built-in thresholds (config not found: /etc/ghost/custom.toml)
```
