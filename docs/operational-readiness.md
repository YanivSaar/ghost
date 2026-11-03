# Operational readiness — RFC 0007

**Date:** 2026-11-03 (v0.7.0+)

The three gaps the RFC named (no panic hook, no SIGTERM handler, no
CAP_BPF probe) have all landed. This file captures the current state
of each and the test that proves it.

## 1. TUI panic hook

- **Lives in:** `ghost/src/panic_hook.rs` (`panic_hook::install`).
- **Installed from:** `ghost/src/main.rs:main()` *before* any other
  code runs, so any panic — even in `Cli::parse` — resets the terminal
  before the backtrace prints.
- **What it does:** disables raw mode, leaves the alt screen, and
  disables mouse capture (idempotent on failure).
- **Interaction with `Tui::drop`:** on a normal exit the Drop guard
  runs first and the panic hook's reset is a no-op. On a panic that
  unwinds past Drop (or an abort), the hook still fires.

## 2. SIGTERM / SIGINT handling

- **Lives in:** `ghost/src/signals.rs` (`signals::install_shutdown`).
- **Installed from:** every supervisor entry point:
  `run_with_target`, `run_cold`, `run_replay`, and the live-analyze
  runner in `modes/analyze.rs`.
- **What it does:** registers `signal_hook::flag::register` so SIGINT
  and SIGTERM flip the shared `stop: Arc<AtomicBool>` from an
  async-signal-safe context (atomic store only; no allocations). The
  main loop sees the flag on its next poll iteration and unwinds
  through the Drop guard like a normal exit.
- **Verification:** `kill -TERM $(pgrep ghost)` on a running
  `ghost watch` returns the terminal cleanly; `Tui::drop` is reached
  and the alt screen is left.

## 3. CAP_BPF probe

- **Lives in:** `ghost/src/caps.rs`.
- **Called from:** `supervisor::load_ebpf` on any `GhostEbpf::load`
  failure. The probe reads `/proc/self/status`'s `CapEff`, checks
  CAP_BPF (bit 39), CAP_PERFMON (bit 38), and CAP_SYS_ADMIN (bit 21),
  then detects host shape via `/proc/1/comm` and prints a copy-pasteable
  fix for that shape (bare-metal setcap, Docker `--cap-add`, Kubernetes
  `securityContext.capabilities.add`, rootless Podman caveat).
- **Interaction with the offset probe (RFC 0006):** both run on load
  failure and are chained into the same error message, so a single
  look at the TUI's `ebpf_error` status line surfaces both diagnoses.

## Test coverage

| Fix | Test |
|---|---|
| Panic-hook reset | `panic_hook::tests` (install idempotent, reset primitives swallow errors) |
| Signal handler | `signals::tests` (register twice is OK) + the `screen_dispatch_renders_every_mode_without_panic` TUI test |
| CAP_BPF probe | `caps::tests` × 7 cases including rejects malformed hex, ignores missing line, hint always has an actionable fix |

## What's not landed yet

- Integration test using `nix::sys::signal::kill` to deliver SIGTERM
  to a child `ghost` process and assert clean exit. The signals module
  itself is covered, but a cross-process assertion needs `nix` as a
  dev-dep; worth doing in a follow-up.
- A hidden `--panic-test` flag for operators to assert the reset works
  on their terminal. Trivial but gratuitous for an audit PR.
