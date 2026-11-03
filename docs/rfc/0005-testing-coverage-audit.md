# RFC 0005: Testing-coverage audit — fuzz, property, integration

**Status:** Proposal (review scope only)
**Scope:** This PR tracks the review initiative. The actual fuzz target / proptest harness / new integration tests land in follow-up PRs.

## Motivation

A validation pass confirmed **15 modules in `ghost/src/` carry zero `#[cfg(test)]` blocks**, including the untrusted-input entry point `ghost/src/session/reader.rs`. We just added `MAX_META_LEN` / `MAX_FRAME_LEN` bounds there in the stability PR, and there is still no test proving the bounds hold or that a corrupt frame is rejected cleanly. There is also no fuzz target, and no `proptest` / `quickcheck` dependency anywhere.

This is the most dangerous gap in the tree: a hostile `.ghost` file is the only remote-ish attack surface ghost has, and its reader has no coverage.

## Modules with zero tests (verified at HEAD = 3b0c236)

```
ghost/src/lib.rs
ghost/src/ebpf/consumer.rs
ghost/src/ebpf/loader.rs
ghost/src/ebpf/mod.rs
ghost/src/modes/mod.rs
ghost/src/modes/mode.rs
ghost/src/modes/snap.rs
ghost/src/proc/mod.rs
ghost/src/session/mod.rs
ghost/src/session/reader.rs    ← highest priority
ghost/src/target/cmd.rs
ghost/src/target/mod.rs
ghost/src/tui/app.rs
ghost/src/tui/mod.rs
ghost/src/tui/widgets.rs
```

## Review scope

Prioritised:
1. **Session reader** (untrusted input).
2. **`ebpf/consumer.rs` dispatch** — holds `unsafe { read_unaligned }` on raw ringbuf bytes; no coverage.
3. **`target/cmd.rs`** — fork+execvp orchestration for `ghost cold`.
4. **TUI render helpers** (`tui/app.rs`, `widgets.rs`) — no visual regression test; render-panic surfaces matter.
5. **`modes/*` dispatch** — thin glue, but still untested.

## Deliverable

1. **Audit PR (this one):** coverage matrix (module × test type) + prioritised list.
2. **Fuzz PR:** `fuzz/fuzz_targets/session_reader.rs` using `cargo-fuzz`; corpus seeded from (a) a legit recorded `.ghost`, (b) empty, (c) truncated-mid-frame, (d) randomly mutated frames.
3. **Proptest PR:** add `proptest` dev-dep; round-trip property `SessionWriter → SessionReader → equal frames` across randomly generated event streams.
4. **Integration-test PR:** in-process consumer tests that feed synthetic ringbuf bytes through `dispatch_event` / `dispatch_capture` and assert specific `AppState` transitions.
5. **Target:** close every one of the 15 zero-test modules.

## Verification

- `cargo tarpaulin` (or `grcov`) shows **100 % of the 15 listed modules** have at least one test touching them.
- `cargo fuzz run session_reader -- -max_total_time=600` runs for ≥ 10 minutes without a crash or OOM.
- Round-trip proptest runs ≥ 1000 iterations in CI.

## Risk

- `cargo-fuzz` requires nightly rustc (already in use) + libFuzzer; adds a `fuzz/` subdirectory outside the workspace, not shipped in release artifacts.
- Property tests add CI time (~30 s). Mitigate by capping iterations in CI (`PROPTEST_CASES=256`).

## Depends on

Nothing. **Highly recommended before the first analyzer-implementation PR**, because the analyzer PRs will materially change what `dispatch_event` records in `AppState` and we want the regression net in place first.
