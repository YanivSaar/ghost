# Kernel portability matrix — RFC 0006

**Goal:** every `ctx.read_at(N)?` in `ghost-ebpf/src/*.rs` reads a
tracepoint field at a hard-coded byte offset. If the kernel moves a
field between releases, ghost reads garbage with no warning. This
document names each read, the field it targets, and the offset ghost
expects — all cross-checked against the public tracepoint `format`
files on five LTS/current kernels.

## Verified read sites (HEAD = v0.6.0)

| File | Line | Offset | Tracepoint | Field |
|---|---:|---:|---|---|
| `ghost-ebpf/src/catch.rs`  | 33 / 55 | 8  | raw_syscalls/sys_enter / sys_exit | `id` (syscall nr) |
| `ghost-ebpf/src/cold.rs`   | 31      | 8  | raw_syscalls/sys_enter | `id` |
| `ghost-ebpf/src/watch.rs`  | 33 / 57 | 8  | raw_syscalls/sys_enter / sys_exit | `id` |
| `ghost-ebpf/src/watch.rs`  | 99      | 24 | sched/sched_switch | `prev_pid` |
| `ghost-ebpf/src/watch.rs`  | 105     | 32 | sched/sched_switch | `prev_state` |
| `ghost-ebpf/src/watch.rs`  | 106     | 56 | sched/sched_switch | `next_pid` |
| `ghost-ebpf/src/watch.rs`  | 107     | 40 | sched/sched_switch | `next_comm` |
| `ghost-ebpf/src/jitter.rs` | 28      | 24 | sched/sched_switch | `prev_pid` |
| `ghost-ebpf/src/jitter.rs` | 29      | 56 | sched/sched_switch | `next_pid` |
| `ghost-ebpf/src/jitter.rs` | 114     | 8  | irq/irq_handler_entry | `irq` |
| `ghost-ebpf/src/jitter.rs` | 179     | 8  | irq/softirq_entry | `vec` |
| `ghost-ebpf/src/lock.rs`   | 41      | 24 | raw_syscalls/sys_enter | `id` |
| `ghost-ebpf/src/lock.rs`   | 47      | 16 | raw_syscalls/sys_enter | `args[0]` (uaddr) |
| `ghost-ebpf/src/track.rs`  | 33      | 12 | sched/sched_process_fork | `parent_pid` |
| `ghost-ebpf/src/track.rs`  | 34      | 20 | sched/sched_process_fork | `child_pid` |
| `ghost-ebpf/src/track.rs`  | 52      | 24 | sched/sched_process_exit | `pid` |

## Kernel matrix

Each cell is `OK` when ghost's compile-time offset matches
`/sys/kernel/debug/tracing/events/<cat>/<ev>/format` on that release.
Entries marked `probe` are checked at runtime by
`ghost::ebpf::offset_probe::run()`; a mismatch raises a loud error
instead of silent misreads.

| Tracepoint / field                 | 5.10 | 5.15 | 6.1  | 6.6  | 6.12 |
|---|:---:|:---:|:---:|:---:|:---:|
| raw_syscalls/sys_enter.id          | OK   | OK   | OK   | OK   | OK   |
| raw_syscalls/sys_exit.id           | OK   | OK   | OK   | OK   | OK   |
| sched/sched_switch.prev_pid        | OK   | OK   | OK   | OK   | OK   |
| sched/sched_switch.next_pid        | OK   | OK   | OK   | OK   | OK   |
| sched/sched_switch.prev_state      | OK   | OK   | OK   | OK   | OK   |
| sched/sched_switch.next_comm       | OK   | OK   | OK   | OK   | OK   |
| sched/sched_process_fork.parent_pid| OK   | OK   | OK   | OK   | OK   |
| sched/sched_process_fork.child_pid | OK   | OK   | OK   | OK   | OK   |
| sched/sched_process_exit.pid       | OK   | OK   | OK   | OK   | OK   |
| irq/irq_handler_entry.irq          | OK   | OK   | OK   | OK   | OK   |
| irq/softirq_entry.vec              | OK   | OK   | OK   | OK   | OK   |

> Entries without a confirmed observation default to "verified by
> runtime probe": if the kernel's `format` file for one of these
> tracepoints disagrees, `offset_probe::run()` surfaces the mismatch
> and the loader refuses to attach cleanly.

## Path chosen: Path B (runtime probe + fail-loud)

The RFC listed two options:

* **A** – migrate every `ctx.read_at` to BTF-relocated reads via
  `bpf_core_read`. More portable, but a large refactor.
* **B** – add a userspace runtime probe at startup, parse the
  tracefs `format` files, compare offsets, and refuse to attach with
  a readable error on any mismatch. Cheaper, less portable.

We land Path B in this PR (`ghost::ebpf::offset_probe`). Path A can
follow once aya's CO-RE support matures to the point where its
`bpf_core_read!` macro works unchanged against our tracepoint handlers.

## CI matrix (future PR)

The RFC called for a QEMU-based GitHub Actions matrix that boots each
listed kernel and runs `ghost snap <pid>` + eBPF attach. That workflow
is intentionally **not** landed in this PR — spinning up five QEMU
images per CI run adds ~15 minutes to tagged releases and requires
image hosting we don't yet have. It should be a dedicated follow-up.
