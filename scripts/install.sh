#!/usr/bin/env bash
# ghost installer — fetches a release tarball from GitHub, verifies its
# SHA-256, installs the binary to $GHOST_PREFIX/bin, and (unless disabled)
# grants it the capabilities it needs to run the eBPF lenses without root.
#
#   curl -fsSL https://raw.githubusercontent.com/YanivSaar/ghost/main/scripts/install.sh | sudo bash
#
# Environment:
#   GHOST_VERSION   release tag to install (default: latest)
#   GHOST_PREFIX    install prefix        (default: /usr/local)
#   GHOST_NO_CAPS   set to 1 to skip setcap
#   GHOST_REPO      override the GitHub repo (default: YanivSaar/ghost)
#   GHOST_YES       set to 1 to auto-confirm overwrite of an existing install
#   GHOST_FORCE     set to 1 to reinstall even if the same version is present

set -euo pipefail

REPO="${GHOST_REPO:-YanivSaar/ghost}"
VERSION="${GHOST_VERSION:-latest}"
PREFIX="${GHOST_PREFIX:-/usr/local}"
BIN_DIR="${PREFIX}/bin"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[1;31mxx\033[0m  %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "ghost only runs on Linux (detected: $(uname -s))."

case "$(uname -m)" in
  x86_64|amd64)   TARGET="x86_64-unknown-linux-gnu" ;;
  aarch64|arm64)  TARGET="aarch64-unknown-linux-gnu" ;;
  *) die "unsupported architecture: $(uname -m) (need x86_64 or aarch64)" ;;
esac

for cmd in curl tar sha256sum install; do
  command -v "$cmd" >/dev/null 2>&1 || die "required command missing: $cmd"
done

# Resolve the tag.
if [ "$VERSION" = "latest" ]; then
  say "Resolving latest release of ${REPO}..."
  TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep -m1 '"tag_name"' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
  [ -n "${TAG:-}" ] || die "could not resolve latest release (is one published?)"
else
  TAG="$VERSION"
fi
VER="${TAG#v}"
say "Latest release is ${TAG} (${TARGET})"

# Detect an existing install and ask before overwriting it.
EXISTING_BIN=""
if command -v ghost >/dev/null 2>&1; then
  EXISTING_BIN="$(command -v ghost)"
elif [ -x "${BIN_DIR}/ghost" ]; then
  EXISTING_BIN="${BIN_DIR}/ghost"
fi

if [ -n "$EXISTING_BIN" ]; then
  EXISTING_VER="$("$EXISTING_BIN" --version 2>/dev/null | awk '{print $NF}' || true)"
  EXISTING_VER="${EXISTING_VER:-unknown}"
  say "Existing install: ${EXISTING_BIN} (version ${EXISTING_VER})"

  if [ "$EXISTING_VER" = "$VER" ] && [ -z "${GHOST_FORCE:-}" ]; then
    say "Already on ${TAG}. Nothing to do. (set GHOST_FORCE=1 to reinstall.)"
    exit 0
  fi

  if [ "${GHOST_YES:-}" = "1" ]; then
    REPLY="y"
  elif [ -r /dev/tty ]; then
    printf '\033[1;33m??\033[0m  Replace %s (%s) with %s? [y/N] ' \
      "$EXISTING_BIN" "$EXISTING_VER" "$TAG" > /dev/tty
    read -r REPLY < /dev/tty || REPLY=""
  else
    die "existing install detected and no TTY to confirm — re-run with GHOST_YES=1 to proceed"
  fi

  case "${REPLY:-}" in
    y|Y|yes|YES)
      say "Removing ${EXISTING_BIN}"
      rm -f "$EXISTING_BIN" || die "could not remove ${EXISTING_BIN}"
      # If `which ghost` resolved to a different prefix than the one we're
      # about to install into, clean that one too so the new install wins.
      if [ "$EXISTING_BIN" != "${BIN_DIR}/ghost" ] && [ -e "${BIN_DIR}/ghost" ]; then
        rm -f "${BIN_DIR}/ghost"
      fi
      ;;
    *)
      die "aborted by user — existing install left in place"
      ;;
  esac
fi

say "Installing ghost ${TAG} for ${TARGET}"

ASSET="ghost-${TAG}-${TARGET}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

say "Downloading ${ASSET}"
curl -fsSL -o "${ASSET}"        "${BASE_URL}/${ASSET}"
curl -fsSL -o "${ASSET}.sha256" "${BASE_URL}/${ASSET}.sha256"

say "Verifying SHA-256"
sha256sum -c "${ASSET}.sha256" >/dev/null || die "checksum mismatch — refusing to install"

say "Extracting"
tar -xzf "${ASSET}"
SRC_BIN="ghost-${TAG}-${TARGET}/ghost"
[ -f "$SRC_BIN" ] || die "tarball layout unexpected (no ${SRC_BIN})"

say "Installing to ${BIN_DIR}/ghost"
if [ -w "$BIN_DIR" ] || [ "$(id -u)" = 0 ]; then
  install -D -m 0755 "$SRC_BIN" "${BIN_DIR}/ghost"
else
  die "cannot write to ${BIN_DIR} — re-run with sudo, or set GHOST_PREFIX to a writable path"
fi

# Grant eBPF-friendly capabilities so ghost need not run as root. snap works
# without this; every other lens wants cap_bpf,cap_perfmon (and cap_sys_ptrace
# for cold).
if [ -z "${GHOST_NO_CAPS:-}" ]; then
  if command -v setcap >/dev/null 2>&1; then
    if [ "$(id -u)" = 0 ]; then
      setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep "${BIN_DIR}/ghost" \
        && say "Granted cap_bpf,cap_perfmon,cap_sys_ptrace to ${BIN_DIR}/ghost" \
        || warn "setcap failed; ghost will still work but needs sudo for non-snap lenses"
    else
      warn "not root — skipped setcap. Run:  sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep ${BIN_DIR}/ghost"
    fi
  else
    warn "setcap not found; install libcap2-bin (Debian/Ubuntu) or libcap (RHEL) to enable non-root eBPF"
  fi
else
  say "GHOST_NO_CAPS set — skipping setcap"
fi

say "Done. Try:  ghost --help"
say "Persistent watcher? See docs/DAEMON.md, or: sudo ghost --install --pid <PID>"
