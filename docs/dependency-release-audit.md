# Dependency hygiene + release-process audit — RFC 0008

**Date:** 2026-11-03 (v0.8.0+)

The RFC's four deliverables (audit, CI gate, DX, release automation)
all land as of this version. This document captures the state so a
future contributor can see at a glance what runs where.

## State matrix

| RFC deliverable | Status | Where |
|---|---|---|
| `cargo audit` in CI | ✅ live | `.github/workflows/ci.yml` → `cargo audit --deny warnings` on every push & PR; cargo-audit pinned to `^0.22` so RUSTSEC entries with CVSS 4.0 vectors parse |
| `cargo deny check` in CI | ✅ live | same workflow; `cargo deny check licenses bans sources` (advisories delegated to cargo-audit above) |
| `deny.toml` with licence policy | ✅ in-tree | repository root; starts lenient (`warn` on first-run issues) with a TODO to tighten after a couple of releases |
| Nightly pinned | ✅ pinned | `rust-toolchain.toml` → `nightly-2026-10-15`; CI uses the same stamp via `dtolnay/rust-toolchain@master`. A floating `nightly` alias is installed in parallel to satisfy `aya-build`'s hardcoded `rustup run nightly` |
| CONTRIBUTING.md | ✅ in-tree | repository root |
| SECURITY.md | ✅ in-tree | repository root; routes to GitHub's private-vuln disclosure flow |
| MSRV banner in README | ✅ in-tree | documented alongside the kernel-support matrix |
| Automated release flow | ✅ in-tree | `.github/workflows/bump-release.yml` (dispatchable with `--field level=patch`) + `release.yml` (triggered by `vX.Y.Z` tags) |

## What runs on every PR

1. `cargo fmt --all -- --check`
2. `cargo clippy -p ghost -p ghost-common --all-targets -- -D warnings`
3. `cargo audit --deny warnings`
4. `cargo deny check licenses bans sources`
5. `cargo build -p ghost --release`
6. `cargo test -p ghost`

## Nightly bump cadence

The RFC asked for a monthly `bump-nightly.yml` dependabot-style PR
to roll `rust-toolchain.toml` forward. Not yet landed; a cron-driven
workflow that opens a PR with the new stamp is the obvious follow-up.
For now the pinned nightly is rolled by hand when a dependency
requires a newer toolchain.

## What's deliberately deferred

- **Tighten deny.toml:** currently lenient (`warn = "yanked"` and
  friends) so first-run doesn't block a legitimate release. The TODO
  at the top of `deny.toml` tracks tightening.
- **Monthly nightly-bump PR:** cron + checkout-and-push would do it
  in ~30 lines of workflow; small enough to be its own PR.
- **Signed releases / SBOM:** cargo-dist can emit SBOMs and sign
  artefacts; worth adopting once the release cadence stabilises.
