# ghost — fuzz targets

Nightly-only fuzzing scaffolding (uses `cargo-fuzz` + `libfuzzer-sys`).
This directory is **outside the main workspace** (declares its own
`[workspace]` table) so the host build is unaffected; CI does not run
fuzzing — it only verifies that the main crate still builds.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running

```sh
# From the ghost repo root:
cargo +nightly fuzz run session_reader
# Or with a time budget (10 min):
cargo +nightly fuzz run session_reader -- -max_total_time=600
```

## Targets

| name | input | guards |
|---|---|---|
| `session_reader` | arbitrary bytes written to a tempfile | magic check, version check, `MAX_META_LEN` (1 MiB), `MAX_FRAME_LEN` (64 MiB) |

## Seed corpus

Drop any real `.ghost` recording into `corpus/session_reader/` before
the first run. The fuzzer uses them as mutation seeds.
