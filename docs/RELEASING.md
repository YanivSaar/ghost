# Releasing ghost

Releases are cut by pushing a `vX.Y.Z` tag. The `Release` workflow
(`.github/workflows/release.yml`) then builds, packages, and publishes.

## One-time repo setup

Nothing beyond default `GITHUB_TOKEN` is required. The workflow needs
`contents: write` (already declared in the file) to create the release.

## Cutting a release

1. Bump `workspace.package.version` in the root `Cargo.toml` to `X.Y.Z`.
2. Run `cargo update -p ghost` (or `cargo build`) so `Cargo.lock` picks up the
   new version.
3. Commit: `chore(release): vX.Y.Z`.
4. Tag and push:
   ```sh
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin main
   git push origin vX.Y.Z
   ```

The workflow then:

- verifies the tag matches `Cargo.toml`,
- builds `ghost` for `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`,
- uploads `ghost-vX.Y.Z-<target>.tar.gz` plus `.sha256` to the GitHub Release,
- auto-generates release notes from merged PRs since the previous tag.

A pre-release tag like `v0.2.0-rc1` is published with the `prerelease` flag
set automatically.

## Manual re-run

If the workflow fails after the tag is already pushed, use the
`workflow_dispatch` trigger ("Run workflow") on the Release workflow and pass
the existing tag (e.g. `v0.1.0`) — it will rebuild and re-publish.
