# RFC 0007: Operational-readiness audit — panic / signals / permission UX

**Status:** Proposal (review scope only)
**Scope:** This PR tracks the review initiative. The fix lands in a follow-up PR.

## Motivation

Three concrete gaps make ghost brittle in real operation. Each one has already bitten operators of similar tools; each one has a cheap, well-understood fix.

| Gap | Evidence | Impact |
|---|---|---|
| **No TUI panic hook** | `ghost/src/tui/app.rs` has no `panic::set_hook`; grep for `std::panic` across `ghost/src/` returns zero hits (only a doc-comment claim at `tui/app.rs:4`) | Any panic leaves the user staring at a broken raw-mode terminal; they must `reset` by hand or close the pty |
| **No SIGTERM / SIGINT handler** | No `signal_hook` / `signal` / `ctrl_c` / `signal_hook::low_level::register` reference anywhere in `main.rs`, `supervisor.rs`, `tui/app.rs` | `kill -TERM $(pgrep ghost)`, lost stdin, or a frozen TUI never unwinds cleanly — supervisor threads and eBPF map detach may be skipped |
| **No CAP_BPF probe** | `ghost/src/ebpf/loader.rs:21` surfaces a static hint string in the error context; no actual capability detection | Users hit a generic aya error with no clear "install libcap", "run with `--cap-add=BPF`", or "add `CapEff` bit 23" path |

## Review scope

- **Panic paths:** every `.unwrap()` / `.expect()` reached under TUI mode — flag the ones in render-hot paths that will panic on malformed data.
- **Shutdown ordering:** TUI drop guard (`tui/app.rs` `impl Drop for Tui`) vs. supervisor consumer/poller threads vs. eBPF map detach. What runs if ghost gets SIGTERM mid-render?
- **CAP_BPF / CAP_PERFMON story** on common hosts:
  - bare metal (root vs. file caps)
  - Kubernetes pod (`securityContext.capabilities.add: ["BPF","PERFMON"]`)
  - Docker (`--cap-add=BPF --cap-add=PERFMON`, kernel-version caveats)
  - rootless Podman (notoriously painful)

## Deliverable

1. **Audit PR (this one):** findings + action list.
2. **Fix PR:**
   - Install a `panic::set_hook` early in `main` that drops raw mode / leaves alt screen / disables mouse before re-raising the panic (same shape as the `Tui` drop guard).
   - Register a SIGTERM/SIGINT handler via `signal_hook::low_level::register` (or `signal_hook::iterator::Signals` on a dedicated thread) that flips the existing `stop: Arc<AtomicBool>`, letting the main loop unwind through the Drop guard like a normal exit.
   - Add a `cap_probe()` that reads `/proc/self/status`'s `CapEff` and checks for `CAP_BPF` (bit 39), `CAP_PERFMON` (bit 38), and `CAP_SYS_ADMIN` fallback; print a copy-pasteable fix for the host the user is likely on (detect via `/proc/1/comm`: `systemd` → bare metal, `init` → container, etc.).

## Verification

- `kill -TERM $(pgrep ghost)` returns the terminal cleanly on a running ghost — no leftover raw mode, cursor visible, alt screen left.
- A forced panic (via a hidden `--panic-test` flag or a test harness) resets raw mode before the backtrace prints.
- Running ghost without CAP_BPF prints an actionable hint naming the host shape and the exact one-liner to fix it.
- Integration test using `nix::sys::signal::kill` to deliver SIGTERM to a child ghost process asserts clean exit.

## Risk

- `signal_hook` adds one small dep. No release-time impact.
- Panic hooks interact with Rust's unwinding model; the fix needs careful testing on both debug and release builds (release has `panic = abort` concerns if ever enabled).

## Depends on

Nothing. Small-scope, high-leverage; could land in a single afternoon of implementation after the audit.
