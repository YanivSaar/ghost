# RFC 0006: Portability audit — kernel-version matrix + CO-RE path

**Status:** Proposal (review scope only)
**Scope:** This PR tracks the review initiative. Migration to BTF-relocated reads (or a runtime offset probe) lands in a follow-up PR.

## Motivation

Every eBPF program in `ghost-ebpf/src/*.rs` reads tracepoint fields at **hardcoded byte offsets** (`ctx.read_at(24)?`, …). Tracepoint field layouts can and do shift between kernel versions — fields can be reordered, grown (e.g. `pid_t` from 32 → 64 bits in theory), or deprecated. If a kernel upgrade silently shifts a field, ghost reads garbage with **no warning**: counts are wrong, filters miss, and the user has no way to know.

The RFC 0002 samplers queue more offset reads on top. The risk compounds with every new offset.

## Verified hardcoded-offset sites (HEAD = 3b0c236)

| File | Line | Offset | Tracepoint |
|---|---|---|---|
| `ghost-ebpf/src/jitter.rs` | 28 | 24 | sched_switch (next_pid) |
| `ghost-ebpf/src/watch.rs` | 99 / 105-107 | 16 / 24 / 28 | sched_switch fields |
| `ghost-ebpf/src/lock.rs` | 41 / 47 | 16 / 24 | sys_enter_futex / sys_exit_futex |
| `ghost-ebpf/src/track.rs` | 33 / 34 / 52 | 12 / 20 / 24 | sched_process_fork / sched_process_exit |
| `ghost-ebpf/src/catch.rs` | 33 / 55 | 24 / 16 | raw_syscalls/sys_enter / sys_exit |
| `ghost-ebpf/src/cold.rs` | 31 | 24 | raw_syscalls/sys_enter |

## Review scope

- Enumerate every `ctx.read_at(N)` call + which tracepoint it targets + what field is expected at N.
- Diff those offsets against `/sys/kernel/debug/tracing/events/*/format` on a kernel matrix: **5.10, 5.15, 6.1, 6.6, 6.12** (LTS + current).
- Evaluate aya's CO-RE support: `aya-ebpf` BTF-relocated field reads via `bpf_core_read` / `btf_tracepoint` style helpers.
- Compare runtime cost: BTF relocation at load time vs. offset probe at attach time vs. hardcoded compile-time.

## Deliverable

1. **Audit PR (this one):** offset-vs-kernel-version matrix (markdown table in `docs/perf/kernel-matrix.md`), explicitly naming any kernel where ghost **already** silently misreads.
2. **Fix PR:** one of two paths, chosen by the review:
   - **Path A (preferred):** migrate every `ctx.read_at` to BTF-relocated reads. Lose compile-time offsets; gain kernel portability.
   - **Path B (fallback):** add a runtime offset probe at startup that parses `/sys/kernel/debug/tracing/events/*/format`, compares against ghost's compile-time constants, and **refuses to attach with a clear error** when they diverge. Fail-loud over fail-silent.
3. **CI PR:** add a GitHub Actions matrix job that boots QEMU with each kernel version and runs a smoke `ghost snap <pid>` + ringbuf attach, so a kernel-version regression trips CI immediately.

## Verification

- Matrix smoke test passes on **5.10 / 5.15 / 6.1 / 6.6 / 6.12**.
- On a deliberately-wrong-offset test build, ghost refuses to attach with an actionable error message (Path B) OR correctly relocates (Path A).

## Risk

- CO-RE migration (Path A) is the larger change; needs its own careful review.
- Runtime probe (Path B) is small but adds attach-time latency (~5 ms per tracepoint).
- QEMU-based CI matrix adds CI time (~3 min per kernel); mitigate by running only on tagged releases.

## Depends on

Nothing. Should land before RFC 0002 samplers merge, so new offset reads land already on the portable substrate.
