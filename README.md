# ghost

**A process observatory for Linux — attach, and see everything.**

ghost gives a systems engineer one coherent, multi-dimensional view of a
running process without touching it: no recompile, no `LD_PRELOAD`, no restart.
Syscalls, scheduler behavior, lock contention, startup cost, and jitter sources
collapse into a single tool with switchable *lenses*.

It is a single Rust binary that drives an in-kernel eBPF pipeline (via
[aya](https://github.com/aya-rs/aya)), a `/proc` fallback for unprivileged use,
a dual-aesthetic TUI (ratatui + crossterm), and a self-contained session
format for record / replay / diff.

---

## Supported platforms

| | |
|---|---|
| **Rust** | nightly pinned to `nightly-2026-10-15` (`rust-toolchain.toml`); bumped monthly |
| **MSRV** | rustc 1.86 (bundled with the pinned nightly) |
| **Linux kernels (targeted)** | 5.10 • 5.15 • 6.1 • 6.6 • 6.12 LTS — matrix formally verified in RFC 0006 |
| **Architectures** | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |
| **Capabilities** | `CAP_BPF` + `CAP_PERFMON` (kernel ≥ 5.8) OR root. `/proc` fallback runs unprivileged with reduced coverage. |

The analyzer pipeline, release automation, and supply-chain gates are tracked in RFCs under [`docs/rfc/`](docs/rfc/).

---

## Highlights

- **Six lenses, one binary.** `snap`, `watch`, `lock`, `catch`, `cold`, `jitter`.
- **Three target selectors.** Single PID, a live process *tree* (in-kernel fork
  tracking), or a whole *cgroup* / systemd unit (inotify + poll).
- **Degrade, never die.** If BPF caps are missing, ghost falls back to the
  `/proc` path and tells you why.
- **Record / replay / diff.** Every run can tee raw events to a `.ghost`
  session file (LZ4-framed, JSON-metadata, per-second index). Replay into the
  real UI; diff two sessions.
- **Low-overhead by design.** Aggregate path always on; detail path gated by
  thresholds, with surfaced drop counts.
- **PID-reuse safe.** Start-time-anchored target identity.
- **Dual TUI aesthetic.** `dense` (default) and `minimal`, toggle at runtime
  with `v`.
- **No daemon.** No background service, no setuid; capabilities on the binary
  only when you want the kernel-side features.

---

## The six lenses

| Mode     | Answers                                                   | eBPF | Caps                                     |
|----------|-----------------------------------------------------------|------|------------------------------------------|
| `snap`   | What is true *right now*? Full /proc portrait              | no   | none                                     |
| `watch`  | Where is syscall time going? Why descheduled?              | yes  | `cap_bpf,cap_perfmon`                    |
| `lock`   | Which mutex is serializing me, and what's its shape?       | yes  | `cap_bpf,cap_perfmon`                    |
| `catch`  | Arm a latency tripwire; capture the rare spike with cause  | yes  | `cap_bpf,cap_perfmon`                    |
| `cold`   | Where did the 800 ms of startup go?                        | yes  | `cap_bpf,cap_perfmon,cap_sys_ptrace`     |
| `jitter` | What steals microseconds from my realtime thread?          | yes  | `cap_bpf,cap_perfmon`                    |

Once attached (`ghost <pid>`) you pivot between lenses from inside the
TUI — no re-attach, no second invocation:

| key | view | key | view |
|---|---|---|---|
| `w` | watch   | `t` | catch (tripwire) |
| `s` | snap    | `j` | jitter           |
| `l` | lock    | `a` | analyze          |

Press `?` (or `F1`) for the full keybind cheatsheet, including analyze
mode toggles (`n` noisy/quiet, `f` cycle confidence floor), catch
threshold tuning (`+` / `-`), and dense/minimal view (`v`). Mouse
clicks on the footer tab bar also switch views; scroll wheel scrolls
tables. `q` or `Ctrl+C` quits.

---

## Install

### One-liner (recommended)

Downloads the latest tagged release from GitHub, verifies the SHA-256,
installs to `/usr/local/bin/ghost`, and grants it the capabilities it needs:

```bash
curl -fsSL https://raw.githubusercontent.com/YanivSaar/ghost/main/scripts/install.sh | sudo bash
```

Prefer not to pipe to a shell? Download and read it first:

```bash
curl -fsSLO https://raw.githubusercontent.com/YanivSaar/ghost/main/scripts/install.sh
less install.sh
sudo bash install.sh
```

Environment overrides:

| var          | default           | meaning                                   |
|--------------|-------------------|-------------------------------------------|
| `GHOST_VERSION` | `latest`       | pin a release, e.g. `v0.1.3`              |
| `GHOST_PREFIX`  | `/usr/local`   | install prefix (`$PREFIX/bin/ghost`)      |
| `GHOST_NO_CAPS` | *(unset)*      | set to `1` to skip `setcap`               |
| `GHOST_YES`     | *(unset)*      | set to `1` to auto-confirm overwrite of an existing install |
| `GHOST_FORCE`   | *(unset)*      | set to `1` to reinstall even if the same version is already present |

The installer always resolves the latest tagged release at run time. If
`ghost` is already installed it reports the current version and prompts
before replacing it; a same-version install is a no-op unless `GHOST_FORCE=1`.

Supported targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.

### From source

Requires Linux 5.8+, Rust nightly, LLVM 18, and `bpf-linker`.

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker --locked
cargo build --release
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep target/release/ghost
```

See [`docs/RELEASING.md`](docs/RELEASING.md) for the full build-and-release
flow.

---

## Usage

```bash
# instant /proc snapshot, no caps needed
ghost snap $(pgrep -n nginx)

# live dashboard (default lens) on a single PID
ghost $(pgrep -n nginx)

# follow a process and every descendant it forks
ghost tree $(pgrep -n systemd)

# watch every process in a cgroup or systemd unit
ghost cgroup system.slice/postgresql.service

# arm a tripwire: capture the next >10 ms syscall and show why
ghost catch $(pgrep -n redis-server) --above 10ms

# lock-contention map for a hot server
ghost lock $(pgrep -n my-service)

# startup archaeology: fork+exec, show every ms until first useful work
ghost cold -- ./my-binary --flag value

# jitter attribution for a realtime thread
ghost jitter <tid>
```

### Record and replay

```bash
# record while you watch
ghost $(pgrep -n nginx) --record incident.ghost

# replay later into the same UI
ghost replay incident.ghost

# jump to a specific point
ghost replay incident.ghost --seek 00:12.500

# compare two captures
ghost diff before.ghost after.ghost
```

### Global flags

| flag                 | effect                                                 |
|----------------------|--------------------------------------------------------|
| `--record <file>`    | tee the raw event stream to a `.ghost` session file    |
| `--no-tui`           | headless; pair with `--record` and/or a duration       |
| `--theme dense|minimal` | initial TUI aesthetic (toggle at runtime with `v`)  |
| `--interval <ms>`    | /proc poll cadence (default 500 ms)                    |

---

## How it works

```
                       ┌──────────────────────┐
                       │     ghost (user)     │
         ┌─────────────┤   clap · ratatui ·   ├─────────────┐
         │             │   crossterm · aya    │             │
         │             └──────────┬───────────┘             │
         ▼                        │                         ▼
  /proc poller               ring buffers              session writer
  (always on)                   (eBPF)                 (LZ4 .ghost)
         │                        │                         │
         └──────────┬─────────────┴───────────┬─────────────┘
                    ▼                         ▼
            Arc<RwLock<AppState>>        TUI render loop
```

- **Five threads**, one `Arc<RwLock<AppState>>`, one data flow.
- **Aggregate path** (counters, histograms) is always on; **detail path**
  (per-event records) is thresholded to stay inside the per-mode overhead
  budget.
- **CO-RE** eBPF with incremental, *fallible* attach: a missing kprobe
  disables one feature, not the tool.
- **PID-reuse** guarded by start-time; **tree** target maintained in-kernel
  via `sched_process_fork` so no race leaks events.
- **Session format** is header + JSON meta + LZ4-framed raw events + a
  per-second index — raw events, not aggregates, so replay is lossless.

Full blueprint: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (rendered copy:
[`docs/architecture.html`](docs/architecture.html)).

---

## Workspace layout

```
ghost/           userspace binary (CLI, TUI, pipeline, sessions)
ghost-ebpf/      BPF programs (no_std, compiled to bytecode by build.rs)
ghost-common/    shared wire types (#[repr(C)], zero-copy)
docs/            architecture + releasing
.github/         CI and tag-driven release workflow
```

---

## Status

Phases 0 through 8 are complete: scaffold, `snap`, `watch` + TUI +
record/replay, `lock`, `catch`, `cold`, `jitter`, tree & cgroup selectors,
systemd integration, record/replay/diff, and library surface. CI builds
`x86_64` and `aarch64` on every push; tag-driven release workflow publishes
signed tarballs to GitHub Releases.

**Current release: `v0.1.12`.** Download prebuilt binaries from the
[releases page](https://github.com/YanivSaar/ghost/releases/tag/v0.1.12).

### What's new in v0.1.12

- **Fuzz + property + integration test net** (RFC 0005 / #7). `cargo-fuzz`
  target for the session reader, `proptest` round-trip for
  `SessionWriter → SessionReader`, 15 modules closed from zero coverage.
  Test count: 120 → ~180.
- **Operational readiness** (RFC 0007 / #9). `std::panic::set_hook` restores
  the terminal before any backtrace; SIGINT / SIGTERM flip the stop
  `AtomicBool` for clean unwinds; a CAP_BPF / CAP_PERFMON probe reads
  `/proc/self/status` and emits host-shape-aware remediation hints
  (bare-metal vs. container).
- **Supply-chain gates + release automation** (RFC 0008 / #10).
  `cargo-audit` (CVSS 4.0 aware) and `cargo-deny` (licences / bans /
  sources) run on every CI pass; rustc nightly pinned to
  `nightly-2026-10-15`; one-click release workflow via
  `gh workflow run bump-release.yml`.
- **Design proposals (merged for review)**. RFC 0001-0008 under
  [`docs/rfc/`](docs/rfc/) — scenario analyzer base + 12 rules → +38 → +210
  application-specific rules, plus performance / portability review tracks.

### Platform support

| | |
|---|---|
| **MSRV / toolchain** | `rustc nightly-2026-10-15` (pinned via `rust-toolchain.toml`) |
| **Supported architectures** | `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu` |
| **Targeted kernels** | Linux 5.10 / 5.15 / 6.1 / 6.6 / 6.12 — formal matrix verification tracked by RFC 0006 |
| **Required capabilities** | `CAP_BPF` + `CAP_PERFMON` for eBPF path; `/proc` fallback works unprivileged |

---

## License

Dual-licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <https://www.apache.org/licenses/LICENSE-2.0>)

at your option.
