# RFC 0004: Performance audit — overhead of ghost itself

**Status:** Proposal (review scope only)
**Scope:** This PR tracks a review initiative. The audit + benchmark baseline + any fixes land in follow-up PRs.

## Motivation

Ghost is a profiler — if it costs the system it observes more than ~1 % CPU, operators will stop using it on prod. There is **no bench target anywhere** in the workspace, so we have no numbers to defend against regressions when the 260 analyzer rules (RFCs 0001-0003) start adding work on top. Baseline numbers must land **before** the first analyzer-implementation PR.

## Review scope

- **Consumer hot path:** `ghost/src/ebpf/consumer.rs` — ringbuf poll, `dispatch_event` / `dispatch_capture`, `RwLock::write` on every `SchedSwitch`.
- **Poller:** `ghost/src/supervisor.rs` `proc_poller` — once-a-second /proc reads, map drains, state fan-out.
- **TUI render:** `ghost/src/tui/app.rs` 30 fps loop, `state.read()` per frame, syscall table rebuilds.
- **Lock-held duration:** how long each writer holds `AppState` lock — potential render stutter.
- **Serde/allocation surfaces:** session writer per-frame compression, syscall-name string formatting in render.

## Deliverable

1. **Audit PR:** findings doc + flame graphs under `docs/perf/` for a canonical "attach-to-nginx-worker, 10 min" scenario; measured on a mid-tier host (document kernel + CPU + RAM).
2. **Bench PR:** new `ghost/benches/` with [criterion](https://bheisler.github.io/criterion.rs/book/) micro-benches for
   - (a) ringbuf dispatch (synthetic events through `dispatch_event`),
   - (b) proc poller tick (parse `/proc/self/*` into `ProcSnapshot`),
   - (c) TUI frame assembly (dense + minimal variants),
   - (d) replay-loop event-rate ceiling.
3. **Fix PRs:** one per hot spot the audit surfaces. Candidate expectations:
   - Hot `RwLock` reads → `ArcSwap` snapshot per tick (readers never block writers)
   - Syscall-name resolution cached by `(nr, _)` tuple instead of repeated `match`
   - Top-N re-sort deferred until TUI actually asks for the view

## Verification

- `cargo bench` prints baseline numbers reproducibly.
- A follow-up change that regresses any bench by **> 5 %** fails CI (threshold wired via `cargo criterion --baseline main`).
- On the canonical scenario the audit documents, total ghost CPU% stays below **1.5 %** at steady state.

## Risk

- Benches depend on criterion — a dev-dep, not shipped with the binary. No runtime impact.
- `ArcSwap` migration (if proposed) is a non-trivial refactor; its own fix PR gets a dedicated review pass.

## Depends on

Nothing. Can start immediately. **Should land before the first analyzer-implementation PR** so analyzer-rule PRs can show "no regression" against this baseline.
