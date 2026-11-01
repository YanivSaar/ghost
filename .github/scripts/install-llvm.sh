#!/usr/bin/env bash
# Install an LLVM toolchain of the version bpf-linker requires, discover
# its real layout at runtime, and export the pieces that cargo's build
# machinery needs. Designed to be portable across whatever Linux the
# runner happens to be — nothing is hardcoded beyond the package manager
# fallback chain, and every path comes back out of `llvm-config` rather
# than being spelled out here.
#
# Required inputs (env):
#   LLVM_VERSION  — the LLVM major (e.g. "19"). Bump when bpf-linker
#                    bumps its llvm-sys dep.
#
# Outputs (via $GITHUB_ENV, $GITHUB_PATH):
#   PATH += <llvm-bindir>
#   LD_LIBRARY_PATH += <llvm-libdir>
#   LLVM_SYS_<ver>1_PREFIX = <llvm-prefix>   # for several near-neighbour versions
#   LIBCLANG_PATH          = <llvm-libdir>

set -euo pipefail

: "${LLVM_VERSION:?LLVM_VERSION env var required (e.g. 19)}"

sudo_or_not() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

install_debian_like() {
    # apt.llvm.org is the canonical multi-version LLVM source for Debian
    # family distros. It handles arch (amd64/arm64) and codename itself.
    sudo_or_not apt-get update
    sudo_or_not apt-get install -y --no-install-recommends \
        build-essential pkg-config libelf-dev curl ca-certificates gnupg lsb-release
    local tmp
    tmp="$(mktemp)"
    # EXIT trap (set at script scope below) survives set -e aborts; a
    # RETURN trap would only fire on normal function return.
    DEBIAN_TMP="$tmp"
    curl -fsSL https://apt.llvm.org/llvm.sh -o "$tmp"
    chmod +x "$tmp"
    # `all` pulls clang/lld/dev/libs together.
    sudo_or_not "$tmp" "$LLVM_VERSION" all
}

# Clean up any temp files any installer created, even on set -e abort.
DEBIAN_TMP=""
cleanup_tmp() { [ -n "${DEBIAN_TMP:-}" ] && rm -f "$DEBIAN_TMP" || true; }
trap cleanup_tmp EXIT

install_rhel_like() {
    # Version every clang/llvm/lld piece so a system install of a
    # different LLVM major doesn't poison PATH or libclang discovery.
    sudo_or_not dnf install -y \
        make gcc pkgconfig elfutils-libelf-devel \
        "clang-tools-extra-${LLVM_VERSION}" \
        "llvm${LLVM_VERSION}" "llvm${LLVM_VERSION}-devel" \
        "clang${LLVM_VERSION}" "clang${LLVM_VERSION}-devel" "lld${LLVM_VERSION}" \
        || sudo_or_not dnf install -y make gcc pkgconfig elfutils-libelf-devel \
            llvm llvm-devel clang clang-devel clang-tools-extra lld
}

install_arch_like() {
    sudo_or_not pacman -Sy --noconfirm \
        base-devel pkgconf libelf "llvm${LLVM_VERSION}" "clang${LLVM_VERSION}" \
        || sudo_or_not pacman -Sy --noconfirm base-devel pkgconf libelf llvm clang lld
}

install_alpine() {
    sudo_or_not apk add --no-cache \
        build-base pkgconf elfutils-dev clang lld llvm llvm-dev
}

# ── 1. Install packages ────────────────────────────────────────────────
if command -v apt-get >/dev/null 2>&1;  then install_debian_like
elif command -v dnf    >/dev/null 2>&1;  then install_rhel_like
elif command -v pacman >/dev/null 2>&1;  then install_arch_like
elif command -v apk    >/dev/null 2>&1;  then install_alpine
else
    echo "no supported package manager (apt-get / dnf / pacman / apk)" >&2
    exit 1
fi

# ── 2. Discover the installed layout via llvm-config ───────────────────
find_llvm_config() {
    local candidates=(
        "llvm-config-${LLVM_VERSION}"
        "llvm-config${LLVM_VERSION}"
        "llvm-config"
    )
    for c in "${candidates[@]}"; do
        if command -v "$c" >/dev/null 2>&1; then
            # Reject llvm-config that doesn't match requested major.
            local v
            v="$("$c" --version 2>/dev/null | cut -d. -f1 || true)"
            if [ "$v" = "$LLVM_VERSION" ]; then echo "$c"; return 0; fi
        fi
    done
    # Last resort: scan standard install roots. Compare the major
    # field (cut on '.') rather than byte-prefixing — the latter breaks
    # for single-digit majors ("9.0.1" → "9." which doesn't match "9").
    local root
    for root in /usr /usr/local /opt; do
        local hit
        hit="$(find "$root" -maxdepth 5 -type f -name 'llvm-config*' 2>/dev/null \
               | xargs -I{} sh -c '"$1" --version 2>/dev/null | cut -d. -f1 | grep -qx "'"$LLVM_VERSION"'" && echo "$1"' _ {} \
               | head -n 1 || true)"
        [ -n "$hit" ] && { echo "$hit"; return 0; }
    done
    return 1
}

LLVM_CONFIG="$(find_llvm_config)" \
    || { echo "could not locate llvm-config for LLVM $LLVM_VERSION" >&2; exit 1; }

LLVM_PREFIX="$("$LLVM_CONFIG" --prefix)"
LLVM_LIBDIR="$("$LLVM_CONFIG" --libdir)"
LLVM_BINDIR="$("$LLVM_CONFIG" --bindir)"
LLVM_MAJOR="$("$LLVM_CONFIG" --version | cut -d. -f1)"

echo "LLVM $LLVM_MAJOR discovered at:"
echo "  prefix = $LLVM_PREFIX"
echo "  libdir = $LLVM_LIBDIR"
echo "  bindir = $LLVM_BINDIR"

# ── 3. Export for subsequent cargo steps ────────────────────────────────
if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$LLVM_BINDIR" >> "$GITHUB_PATH"
fi

if [ -n "${GITHUB_ENV:-}" ]; then
    # llvm-sys picks its env var from its own crate version — set a few
    # neighbouring majors so a bpf-linker version bump doesn't force
    # another workflow edit.
    for v in $((LLVM_MAJOR - 1)) "$LLVM_MAJOR" $((LLVM_MAJOR + 1)); do
        echo "LLVM_SYS_${v}1_PREFIX=$LLVM_PREFIX" >> "$GITHUB_ENV"
    done
    echo "LIBCLANG_PATH=$LLVM_LIBDIR" >> "$GITHUB_ENV"
fi

# ── 4. Make libLLVM findable at *runtime* for the installed bpf-linker ──
# Not every distro's dynamic linker searches $LLVM_LIBDIR by default.
# Adding it to the system ld.so cache is the one durable fix that
# doesn't depend on knowing the exact path.
if [ -d /etc/ld.so.conf.d ]; then
    echo "$LLVM_LIBDIR" | sudo_or_not tee /etc/ld.so.conf.d/llvm-ghost.conf >/dev/null
    sudo_or_not ldconfig
fi
