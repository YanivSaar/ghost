# Contributing to ghost

Thanks for your interest. Ghost is a Linux process observatory built in Rust + eBPF.

## Build

```sh
# One-time: install nightly matching rust-toolchain.toml, bpf-linker,
# and LLVM. CI uses .github/scripts/install-llvm.sh — on your dev box,
# either run that script or install LLVM manually and `cargo install
# bpf-linker` matching your rustc's LLVM major.
cargo build -p ghost
```

The BPF object is compiled transparently by ghost's `build.rs` via `aya_build`; you do not need to build `ghost-ebpf` separately.

## Run locally

Ghost's eBPF programs need `CAP_BPF` + `CAP_PERFMON` (kernel ≥ 5.8) or root. On a dev box the simplest path is:

```sh
sudo -E cargo run -p ghost -- watch $(pidof your-target)
```

A proper per-binary cap setup is covered in [RFC 0007](docs/rfc/0007-operational-readiness-audit.md).

## Tests

```sh
cargo test -p ghost
cargo clippy -p ghost -p ghost-common --all-targets -- -D warnings
cargo fmt --all -- --check
```

The CI workflow in `.github/workflows/ci.yml` runs the same commands plus `cargo audit` and `cargo deny check` — see RFC 0008.

## Commit messages

[Conventional commits](https://www.conventionalcommits.org/). The subject prefix tells readers (and release-automation) what landed:

- `feat:` user-visible functionality
- `fix:` bug fix
- `ci:` CI / workflow changes
- `chore:` plumbing, deps, docs that don't affect behaviour
- `perf:` performance work (should carry benches)
- `refactor:` no behaviour change

Attribution footers at the bottom of a commit if a tool / coauthor contributed; grep recent `git log` for the current format.

## RFC flow

Non-trivial changes land as a proposal first: a markdown file under `docs/rfc/NNNN-<slug>.md` opened as a draft PR. The RFC describes motivation, scope, deliverable, risk, and verification. Implementation lands in a follow-up PR once the proposal is accepted.

Existing RFCs are numbered 0001 onwards — pick the next free number.

## Issues

File at <https://github.com/YanivSaar/ghost/issues>. For security reports, see [SECURITY.md](SECURITY.md).
