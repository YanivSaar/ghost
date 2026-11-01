# ghost — architecture

The complete, rendered blueprint ships alongside this file as
`architecture.html` (open it in a browser). This Markdown is the quick map; the
HTML is authoritative.

## Contents

1. Executive summary — the relay-race-of-tools problem ghost kills
2. Design philosophy — five tenets (one target many lenses; overhead has a
   budget; the kernel already knows; degrade never die; honest about uncertainty)
3. System architecture — five threads, one `Arc<RwLock<AppState>>`, one data flow
4. Target selection — single PID / process tree (in-kernel fork tracking) /
   cgroup (inotify + poll); PID-reuse guard via start-time
5. eBPF subsystem — aya, the map inventory, per-CPU counters, ring buffers, the
   PID_SET filter gate, CO-RE load + incremental fallible attach
6. Data pipeline — aggregate path (always) vs detail path (thresholded);
   backpressure + surfaced drop counts; zero-copy decode
7. /proc subsystem — the privilege-free layer and what each file yields
8. Session record/replay — the `.ghost` format (header + JSON meta + LZ4 frames
   + per-second index); raw events not aggregates; adjustable replay clock
9. Mode specifications — snap, watch, lock, catch, cold, jitter (with sample output)
10. TUI architecture — dual dense/minimal, screen graph, keymap, detected
    mouse/clickable support, stability guarantees
11. Workspace layout
12. Core data types — the shared wire types and the `Mode` trait
13. Configuration — flags, config file, env vars
14. Error handling — the load-time fallback ladder + a failure-scenario table
15. Performance — per-mode overhead budgets and scaling levers
16. Security model — capabilities, read-only toward the target, redaction
17. Testing strategy — unit / BPF-in-VM / integration (known-bad targets) / TUI
18. Limitations & technical debt — honest ledger (Linux-only, SMIs inferred,
    x86_64 first)
19. Build & deployment — Step 0 project setup, build, phased delivery
20. Roadmap — symbol resolution, arm64, deepened diff, export, triggers, remote

See `architecture.html` for the full prose, diagrams, tables, and code.
