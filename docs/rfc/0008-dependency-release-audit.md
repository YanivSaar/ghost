# RFC 0008: Dependency hygiene + release-process audit

**Status:** Proposal (review scope only)
**Scope:** This PR tracks the review initiative. CI gate + release automation land in follow-up PRs.

## Motivation

The release path today is manual (edit `Cargo.toml`, tag, push), and there is **no vulnerability or license gate in CI**. As the analyzer PRs add dependencies (`toml` from RFC 0001; another ~5 queued for the app-rules PR), supply-chain exposure grows with the catalogue. MSRV isn't documented, so a nightly bump could silently break downstream users; the `rust-toolchain.toml` currently floats on `nightly`, meaning yesterday's reproducible build may stop reproducing today.

Everything in this audit is dull plumbing — but the plumbing is where real production incidents hide.

## Current state (verified at HEAD = 3b0c236)

- No `cargo audit` / `cargo deny` step in `.github/workflows/*.yml`.
- `rust-toolchain.toml` → floating `nightly`; `.github/workflows/*.yml` uses `dtolnay/rust-toolchain@nightly`.
- No `CONTRIBUTING.md` or MSRV banner in README.
- Release flow: three manual commits (`version` bump → tag → push) per release.

## Review scope

- **`cargo audit`** output against the current `Cargo.lock` — enumerate any advisory.
- **`cargo deny`** licence + duplicate-crate check — enumerate licence incompatibilities (apache, mit, bsd-* are fine; AGPL/SSPL are not).
- **Nightly pinning:** choose a specific date (e.g. `nightly-2026-10-15`) and establish a monthly bump cadence; document the pin in `rust-toolchain.toml` and CI.
- **MSRV & supported-kernel matrix** in `README.md`: what rustc works, what kernel versions ghost targets.
- **Release flow comparison:** `release-please` vs. `cargo-release` vs. `cargo-dist` vs. a hand-rolled `bump-release.yml`.

## Deliverable

1. **Audit PR (this one):** list of vulnerabilities / licence issues (if any) + chosen release-automation design.
2. **CI-gate PR:**
   - Add `cargo audit --deny warnings` step to `ci.yml`.
   - Add `cargo deny check` step; land `deny.toml` with the project's licence policy.
   - Pin nightly in `rust-toolchain.toml` and the CI workflow to a specific date.
3. **DX PR:** add `CONTRIBUTING.md`, an MSRV + kernel-matrix banner in `README.md`, and a `SECURITY.md` with the vulnerability-report channel.
4. **Automation PR:** wire the chosen release-automation tool so the next release is one `gh workflow run bump-release.yml --field level=patch` instead of three hand commits.

## Verification

- `cargo audit` exits 0 in CI; a knowingly-vulnerable dep (test) trips it.
- `cargo deny check` exits 0; a knowingly-GPL dep (test) trips it.
- Nightly in CI matches the pinned date; a date-drift PR surfaces it immediately via `git diff`.
- Cutting v0.1.12 is one GitHub-UI click OR one `gh workflow run` and the pipeline bumps `Cargo.toml`, tags, builds, publishes the release.

## Risk

- `cargo deny` can be too strict on first-run; mitigate by starting with `advisories = { yanked = "warn" }` and tightening after a couple of releases.
- Pinning nightly means we have to actively bump it; mitigate by scheduling a monthly `bump-nightly.yml` dependabot-style PR.

## Depends on

Nothing. Can run in parallel with every other review track.
