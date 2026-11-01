#!/usr/bin/env bash
# Detect the LLVM major that the currently-active nightly `rustc` was
# built with, then pick a bpf-linker version + cargo feature that
# matches that LLVM. Writes the three variables to $GITHUB_ENV so
# subsequent steps consume them.
#
# bpf-linker's `llvm-N` feature matrix is baked into the crate's
# Cargo.toml, which bumps per release. The map below is the current
# upstream situation and must be revisited when either bpf-linker or
# rustc moves to a new LLVM major.

set -euo pipefail

# rustc may be invoked via rustup; prefer the active toolchain.
if ! command -v rustc >/dev/null 2>&1; then
    echo "rustc not on PATH" >&2
    exit 1
fi

LLVM_MAJOR="$(rustc -Vv | awk '/^LLVM version:/ { print $3 }' | cut -d. -f1)"
: "${LLVM_MAJOR:?could not detect LLVM major from rustc -Vv}"

# bpf-linker version → (llvm majors it supports via cargo features)
#   0.9.15 : 19, 20, 21
#   0.10.4 : 20, 21, 22
#   0.11.1 : 21, 22, 23
#   0.12.0 : 21, 22, 23
case "$LLVM_MAJOR" in
    19) BPF_LINKER_VERSION="0.9.15"  ;;
    20) BPF_LINKER_VERSION="0.10.4"  ;;
    21) BPF_LINKER_VERSION="0.11.1"  ;;
    22) BPF_LINKER_VERSION="0.11.1"  ;;
    23) BPF_LINKER_VERSION="0.12.0"  ;;
    *)
        echo "no known bpf-linker for LLVM $LLVM_MAJOR; add a row to detect-versions.sh" >&2
        exit 1
        ;;
esac

BPF_LINKER_LLVM_FEATURE="llvm-${LLVM_MAJOR}"

echo "rustc LLVM     = $LLVM_MAJOR"
echo "bpf-linker     = $BPF_LINKER_VERSION"
echo "bpf-linker ft  = $BPF_LINKER_LLVM_FEATURE"

{
    echo "LLVM_VERSION=$LLVM_MAJOR"
    echo "BPF_LINKER_VERSION=$BPF_LINKER_VERSION"
    echo "BPF_LINKER_LLVM_FEATURE=$BPF_LINKER_LLVM_FEATURE"
} >> "$GITHUB_ENV"
