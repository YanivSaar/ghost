# RFC 0002: Expand analyzer to 50 scenarios

**Status:** Proposal (not yet implemented)
**Depends on:** RFC 0001 (PR #3) — the base engine, config schema, TUI screen, and `ghost analyze` CLI.
**Scope:** This PR tracks the proposal only. Implementation lands once the design is accepted.

## Motivation

RFC 0001 ships 12 general-purpose rules — enough to cover the common "stuck" / "burning" / "noisy neighbour" shapes. To be useful across the long tail of real-world incidents (networking stalls, memory climb, scheduler weirdness, zombie reaping, respawn loops, OOM proximity, etc.) we extend the catalogue to **50 rules** grouped by the subsystem each one leans on. The engine, config schema, TUI screen, and CLI output stay unchanged — this PR is almost pure data plus the few `AppState` sampler additions those new rules need.

A separate RFC 0003 will later propose **200 application-specific rules** (nginx, mysql, redis, docker, node.js, …) that build on this foundation to recognise what a given well-known process is doing wrong.

## Decisions baked in (amendments on top of RFC 0001)

| Decision | Value |
|---|---|
| Catalog size | **50 rules total** (12 from RFC 0001 + **38 new** here) |
| Prep work (new signals in `AppState`) | **Inline in this PR** (not split into separate micro-PRs) |
| Confidence floor | **Configurable per rule via `~/.config/ghost/analyze.toml` AND via the TUI analyze screen** (new keybinding `f` cycles Low → Medium → High for the highlighted row; the TUI value is written back to the config file on next `w` report write) |

## Confidence floor — TUI & config contract

**Config file:**
```toml
[rule.cpu_bound_user]
confidence_floor = "medium"      # suppress Low findings for this rule
```

**TUI (new on the analyze screen):**
- Keybinding `f` on the highlighted row cycles its floor: `Low → Medium → High → Low`.
- The current floor renders as a column badge: `floor:LOW`, `floor:MED`, `floor:HIGH`.
- Global `shift+F` cycles the floor for every rule at once.
- Changes are session-local until the user presses `w` to persist (writes the full config back to disk, preserving comments where possible; new rules get sensible defaults).

**Precedence (unchanged from RFC 0001):**
`CLI --threshold / --floor > TUI runtime value > config file > compiled default`

## Expansion roster (38 new rules → 50 total)

Rule-ids are reserved as `// TODO: next PR` constants in RFC 0001's `scenarios/mod.rs` so no renaming is needed here.

### CPU / scheduler (8)
| id | triggers when | signals |
|---|---|---|
| `preemption_storm` | involuntary ctx/s ≥ 500 for 3 ticks | `watch.involuntary_ctx` delta |
| `cpu_migration_thrash` | target seen on ≥ 4 distinct CPUs/s | sched_switch next_cpu (new sampler) |
| `cpu_affinity_mismatch` | pinned affinity ≠ actual run CPUs | /proc/<pid>/status Cpus_allowed vs sched_switch |
| `priority_inversion` | high-prio target blocked on futex held by lower-prio holder | LockStat.holder_tid + /proc prio |
| `cpu_starvation` | runnable but on-CPU ratio ≤ 10% for 5 ticks | /proc/<pid>/schedstat (new sampler) |
| `cgroup_throttled` | nr_throttled delta > 0 in cgroup target | cgroup `cpu.stat` nr_throttled (new sampler) |
| `rt_scheduling_pressure` | RT task preempts target ≥ N/s | sched_switch next_prio ≤ 99 |
| `nice_demotion_live` | /proc/<pid>/stat priority drops mid-run | /proc stat prio delta |

### Syscall / I/O (9)
| id | triggers when | signals |
|---|---|---|
| `read_heavy` | read/pread64 ≥ 70% of syscall time | SyscallStat totals |
| `write_heavy` | write/pwrite64 ≥ 70% of syscall time | SyscallStat totals |
| `small_io_pattern` | many read/write with tiny byte counts | tracepoint arg capture (new ebpf field) |
| `fsync_wall` | fsync/fdatasync p99 ≥ 50 ms | SyscallStat.max_ns |
| `nonblocking_poll_loop` | high poll/epoll_wait rate with ~0 timeout | tracepoint arg capture (new ebpf field) |
| `epoll_hot_fd` | one fd dominates ready-events | tracepoint arg capture (new ebpf field) |
| `select_vs_epoll_antipattern` | select used with large fd sets | tracepoint arg capture (new ebpf field) |
| `getdents_crawl` | sustained getdents rate | SyscallStat.count |
| `splice_sendfile_opportunity` | large read→write pairs that could be splice()/sendfile() | tracepoint arg capture |

### Memory (5)
| id | triggers when | signals |
|---|---|---|
| `brk_growth` | monotonic brk/sbrk growth over 10 ticks | /proc/<pid>/stat `brk` |
| `mmap_heap_fragmentation` | mmap/munmap ratio and churn pattern | SyscallStat |
| `page_fault_major_storm` | /proc/<pid>/stat majflt delta ≥ 100/s | /proc stat majflt (new sampler) |
| `madvise_dontneed_abuse` | high madvise(DONTNEED) rate | tracepoint arg capture |
| `rss_climb_steady` | RSS up ≥ 10 MiB/s sustained | /proc/<pid>/status VmRSS (new sampler) |

### Locking / concurrency (5)
| id | triggers when | signals |
|---|---|---|
| `reader_writer_imbalance` | writers blocking many readers | LockStat.holder_tid + queue depth |
| `spinlock_livelock_user` | high CPU with no futex waits and no forward progress | watch + lock |
| `convoying` | queue depth on a single futex ≥ N for ≥ 3 ticks | LockStat.max_queue |
| `yield_loop` | sched_yield rate ≥ 100/s | SyscallStat |
| `many_short_locks` | short futex p50 (< 50 µs) at very high rate | LockStat waits/total_wait_ns |

### Networking (4)
| id | triggers when | signals |
|---|---|---|
| `connect_timeout_wall` | connect calls with EINPROGRESS → long epoll gap | tracepoint arg capture (errno) |
| `connection_reset_storm` | recv returning ECONNRESET high rate | tracepoint arg capture (errno) |
| `send_recv_imbalance` | sendmsg ≫ recvmsg or vice versa | SyscallStat |
| `tcp_small_segments` | many tiny writes without TCP_NODELAY | tracepoint arg capture |

### Process lifecycle (4)
| id | triggers when | signals |
|---|---|---|
| `respawn_loop` | parent sees ≥ 3 clone→exit cycles within 10 s on the same comm | track module exit events + fork |
| `exec_chain_long` | execve chain depth ≥ 5 | cold-launch tracking |
| `daemon_double_fork_detected` | fork→setsid→fork pattern (info-only) | fork tracepoint + setsid syscall |
| `oom_killer_proximate` | /proc/<pid>/oom_score climbs ≥ threshold | /proc oom_score sampler (new) |

### Signals / timers (3)
| id | triggers when | signals |
|---|---|---|
| `sigpipe_bleed` | repeated SIGPIPE delivery | signal_deliver tracepoint |
| `timer_wheel_wobble` | timerfd/timer_create setitimer at irregular intervals | SyscallStat variance |
| `signal_blocked_handler_pending` | sigprocmask block + pending signal | /proc/<pid>/status SigPnd + SigBlk |

## New samplers landed inline

These prep pieces land as part of this PR (not as separate PRs):

| Sampler | Added to | Fields exposed |
|---|---|---|
| /proc/<pid>/status extras | `proc::ProcSnapshot` | `vm_rss_kb`, `vm_data_kb`, `sig_pnd`, `sig_blk` |
| /proc/<pid>/stat extras | `proc::ProcSnapshot` | `majflt`, `cmajflt`, `prio`, `nice` |
| /proc/<pid>/schedstat | `proc::ProcSnapshot` | `run_ns`, `wait_ns`, `pcount` |
| /proc/<pid>/oom_score | `proc::ProcSnapshot` | `oom_score`, `oom_score_adj` |
| cgroup `cpu.stat` | existing cgroup target refresh loop | `nr_throttled`, `throttled_time_ns` |
| sched_switch next_cpu/next_prio | existing ebpf `track` program | `SchedSwitchRecord.next_cpu`, `next_prio` |
| syscall-enter arg capture (selective: byte counts, fd, errno, timeout) | new ebpf `enter` program for ~15 syscalls | emits to EVENTS ring under `EventKind::SyscallArgs` |

Each sampler is behind a `cfg(target_os = "linux")` and no-ops cleanly if the file doesn't exist (e.g. inside unprivileged containers). The `SyscallArgs` ring budget is small (~16 bytes/record) and arg capture only activates when at least one rule that needs it is enabled, so the default-config overhead stays near zero.

## Risk / rollout

- Additive. Every new rule defaults to **enabled** at Info/Notice severity; the three highest-noise ones (`cpu_migration_thrash`, `yield_loop`, `tcp_small_segments`) default to Info with floor Medium so Quiet mode doesn't surface them unless the user asks.
- Several rules are heuristic. Each heuristic rule's rustdoc names its known false-positive shape so the user can disable with one config line.
- Rules that need prep samplers are compiled unconditionally; the sampler returns `None`/zero on kernels / containers where the source file is missing, and the rule short-circuits.

## Testing

- Per-rule unit tests: positive-fire, negative-no-fire, boundary — ~3 per rule → **~115 new tests**.
- Sampler tests: each new /proc parser fuzzed against synthetic input + the real file on the dev host.
- Confidence-floor tests: TUI cycle idempotency, config write-back round-trip, CLI `--floor` precedence.
- Replay fixture: craft a `.ghost` with signals that trigger `preemption_storm` → `priority_inversion` → `respawn_loop` in sequence; assert exact plain-text, JSON, and JSONL outputs.
- Total: 175 (post-RFC-0001) → ~**290 tests**.

## Scope / size

| | lines |
|---|---|
| 38 scenario files | ~1500 (≈40 each) |
| New samplers (proc, schedstat, oom_score, cgroup cpu.stat) | ~400 |
| ebpf arg-capture program + wire type | ~200 |
| TUI confidence-floor keybind + render | ~80 |
| Config write-back | ~120 |
| Tests | ~800 |
| **Total** | **~3100 LoC** |

No new dependencies.

## Open calls for review

1. Confidence-floor TUI UX: `f` per-row + `shift+F` global — ok, or prefer a modal picker?
2. `w` writes back the full config (preserving unknown keys, re-emitting known ones). Preserve TOML comments? Best-effort or hard requirement?
3. Any rule in the 38 above you want **cut** before implementation?
4. Any rule in the 38 above you want **tuned** (e.g. a different default threshold)?
