# Performance baseline — RFC 0004

**Date:** 2026-11-03
**Host:** Linux 6.18.54.1 (WSL2), x86_64
**Target binary:** `ghost v0.5.0` (release profile: `lto=true, codegen-units=1`)

## Baseline measurements

Benchmarks live under `ghost/benches/` and run via `cargo bench -p ghost`.
Each bench reports the Criterion median (middle number of the triple).

| Bench | What it measures | Median | Comment |
|---|---|---|---|
| `analyze_tick_warm` | one `AnalyzerEngine::tick` across the full 260-rule registry over a warmed history ring | **9.4 µs** | ≪ 500 µs per-tick budget declared in RFC 0001 |
| `proc_snapshot_self` | `ProcSnapshot::collect` on this process (stat, status, io, fds, maps, smaps_rollup, sockets, oom_score, schedstat) | **758 µs** | Dominated by the maps + sockets scans; stable across runs |

The /proc tick runs at 1 Hz, so even at the current cost the poller
spends ≤ 0.08 % of a core; the analyzer tick adds 9 µs on top.
Combined, ghost's own observed CPU share on a quiet host stays well
below the 1.5 % steady-state target from the RFC.

## Regression gate

Run before merging an analyzer-touching PR:

```sh
cargo bench -p ghost --bench analyze_tick -- --save-baseline main
# … make change …
cargo bench -p ghost --bench analyze_tick -- --baseline main
```

Criterion fails the run with a "regressed" annotation on `>5 %`
degradation; wire that into CI as `cargo criterion --baseline main`.

## Known hot spots (audit)

1. **`ebpf::consumer::run` acquires `RwLock::write` on every SchedSwitch**
   event (`ghost/src/ebpf/consumer.rs`). Expected mitigation: migrate
   per-tick aggregates to an `ArcSwap` snapshot the TUI reads
   lock-free. Not yet implemented — would be a dedicated PR.
2. **`proc::maps::read_maps` reads the whole file every tick** even
   when the maps screen isn't open. The ARCHITECTURE notes "lazily
   when their screen is live"; the current `ProcSnapshot::collect`
   doesn't honour that split. Low priority (sub-ms today) but a
   trivial future win.
3. **Analyzer per-tick re-sort** by severity+confidence runs even
   when no rule fires. Negligible at today's scale; worth revisiting
   once rule authors begin emitting rich SignalRef vectors.

## Next benches to add

- `tui_frame_assembly` — ratatui draw of each dense screen.
- `replay_rate_ceiling` — frames/sec a `SessionReader → dispatch_event`
  pipeline can sustain.
- `ringbuf_dispatch` — a synthetic ringbuf-byte feed through
  `dispatch_event` + `dispatch_capture`.

These sit in follow-up PRs once the harness around them stabilises
(the ringbuf dispatcher requires a trusted-byte feeder helper).
