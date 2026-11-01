# ghost

**A process observatory for Linux — attach, and see everything.**

ghost gives a systems engineer one coherent, multi-dimensional view of a
running process without touching it: no recompile, no `LD_PRELOAD`, no restart.
Syscalls, scheduler behavior, lock contention, startup cost, and jitter sources
collapse into a single tool with switchable lenses.

## Status

Phase-0 scaffold. The architecture is fully specified in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) (rendered:
[`docs/architecture.html`](docs/architecture.html)). Code follows the blueprint.

## The six lenses (modes)

| Mode     | Answers                                             |
|----------|-----------------------------------------------------|
| `snap`   | What is true right now? (/proc, no eBPF, no caps)   |
| `watch`  | Where is syscall time going? Why descheduled?       |
| `lock`   | Which mutex is serializing me, and what's its shape?|
| `catch`  | Catch the rare latency spike and show why           |
| `cold`   | Where did the 800ms of startup go?                  |
| `jitter` | What steals microseconds from my realtime thread?   |

## Targets

Single PID (`ghost <pid>`), a process tree (`ghost tree <pid>`), or a cgroup /
systemd unit (`ghost cgroup <path|unit>`).

## Sessions

Record any run (`--record incident.ghost`) and replay it into the full UI
(`ghost replay incident.ghost`), or compare two (`ghost diff a.ghost b.ghost`).

## Build

Requires Linux 5.8+, Rust nightly, and `bpf-linker`.

```bash
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
cargo build --release
# grant capabilities instead of running as root:
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+ep target/release/ghost
ghost $(pgrep -n nginx)
```

## Build phases

0. workspace scaffold + embedded BPF build   ← you are here
1. `snap` — full /proc portrait, no eBPF
2. `watch` + dual TUI + record/replay core    ← MVP line
3. `lock` · 4. `catch` · 5. `cold` · 6. `jitter` + tree/cgroup hardening

## License

MIT OR Apache-2.0
