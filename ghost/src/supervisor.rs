//! Thread lifecycle: load eBPF, spawn poller + consumer, run TUI (ARCHITECTURE §3).

use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    time::Duration,
};

use anyhow::{Context, Result};
use ghost_common::Config;

use crate::{
    ebpf::{consumer::RecordSink, loader::GhostEbpf},
    proc::ProcSnapshot,
    session::{format::SessionMeta, writer::SessionWriter},
    state::{ActiveMode, AppState},
    target::pid::PidTarget,
    tui::app::Tui,
};

fn mode_name(m: ActiveMode) -> &'static str {
    match m {
        ActiveMode::Watch => "watch",
        ActiveMode::Snap => "snap",
        ActiveMode::Lock => "lock",
        ActiveMode::Catch => "catch",
        ActiveMode::Cold => "cold",
        ActiveMode::Jitter => "jitter",
        ActiveMode::Analyze => "analyze",
    }
}

/// Open a .ghost session file for recording. Returns None (and prints a
/// warning) if the path can't be opened — we never let a bad --record
/// derail the session.
fn open_sink(path: &str, pid: u32, comm: &str, mode: ActiveMode) -> RecordSink {
    let meta = SessionMeta::new(pid, comm, mode_name(mode));
    match SessionWriter::open(path, &meta) {
        Ok(w) => Some(Arc::new(Mutex::new(w))),
        Err(e) => {
            eprintln!("ghost: could not open session file {path}: {e}");
            None
        }
    }
}

pub fn run(pid: u32, record: Option<String>) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Watch, 0)
}

pub fn run_lock(pid: u32, record: Option<String>) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Lock, 0)
}

pub fn run_catch(pid: u32, record: Option<String>, threshold_ns: u64) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Catch, threshold_ns)
}

pub fn run_jitter(pid: u32, record: Option<String>) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Jitter, 0)
}

/// Follow `root_pid` and all of its (current + future) descendants.
pub fn run_tree(root_pid: u32, record: Option<String>) -> Result<()> {
    use crate::target::tree::TreeTarget;

    let tree = TreeTarget::attach(root_pid)?;
    let extras: Vec<u32> = tree
        .members
        .iter()
        .copied()
        .filter(|p| *p != root_pid)
        .collect();
    let label = format!("tree({})  +{}", root_pid, extras.len());
    run_with_target(
        root_pid,
        record,
        ActiveMode::Watch,
        0,
        extras,
        Some(label),
        tree.members.len(),
    )
}

/// Watch every process in `target` cgroup (and any children forked afterwards).
pub fn run_cgroup(target: String, record: Option<String>) -> Result<()> {
    use crate::target::cgroup::CgroupTarget;

    let cg = CgroupTarget::attach(&target)?;
    if cg.members.is_empty() {
        anyhow::bail!("ghost cgroup: {} has no processes", cg.label);
    }
    // Representative pid for /proc poller + identity header.
    let root_pid = cg.members[0];
    let extras: Vec<u32> = cg
        .members
        .iter()
        .copied()
        .filter(|p| *p != root_pid)
        .collect();
    let total = cg.members.len();
    let label = format!("{}  ({} procs)", cg.label, total);
    run_with_target(
        root_pid,
        record,
        ActiveMode::Watch,
        0,
        extras,
        Some(label),
        total,
    )
}

/// Launch `cmd` under cold-mode instrumentation: fork the target with
/// SIGSTOP, wire it into PID_SET + the cold BPF program, write COLD_LAUNCH,
/// then SIGCONT and watch its startup until it exits.
pub fn run_cold(cmd: Vec<String>, record: Option<String>) -> Result<()> {
    use crate::target::cmd::CmdHandle;

    if cmd.is_empty() {
        anyhow::bail!("ghost cold: no command supplied");
    }

    let handle = CmdHandle::spawn_stopped(&cmd).context("ghost cold: spawning stopped child")?;
    let pid = handle.pid as u32;
    let cmdline = cmd.join(" ");

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, cmd[0].clone());
        s.mode = ActiveMode::Cold;
        s.cold.cmdline = cmdline;
        s
    }));
    let stop = Arc::new(AtomicBool::new(false));
    if let Err(e) = crate::signals::install_shutdown(&stop) {
        eprintln!("ghost: signal handler install failed: {e:#}");
    }

    // Open the session sink (if --record was passed).
    let sink: RecordSink = record
        .as_deref()
        .and_then(|p| open_sink(p, pid, &cmd[0], ActiveMode::Cold));

    // Load eBPF, track the stopped child, attach cold probe.
    match load_ebpf(pid, 0) {
        Ok(mut ebpf) => {
            let probe_res = ebpf.attach_cold();
            let track_res = ebpf.attach_track();
            let errors: Vec<_> = probe_res
                .errors()
                .into_iter()
                .chain(track_res.errors())
                .map(|s| s.to_string())
                .collect();

            // Timestamp the launch moment just before releasing the child.
            let launch_ns = read_monotonic_ns();
            let _ = ebpf.set_cold_launch(launch_ns);

            {
                let mut st = state.write().unwrap();
                st.ebpf_ok = errors.is_empty();
                st.ebpf_error = if errors.is_empty() {
                    None
                } else {
                    Some(errors.join("; "))
                };
                st.cold.launch_ts_ns = launch_ns;
            }

            // Spawn the consumer BEFORE resuming the child so no event is lost
            // between SIGCONT and the first poll.
            let state_c = Arc::clone(&state);
            let stop_c = Arc::clone(&stop);
            let sink_c = sink.clone();
            std::thread::spawn(move || {
                crate::ebpf::consumer::run(ebpf, state_c, stop_c, sink_c);
            });
        }
        Err(e) => {
            let mut st = state.write().unwrap();
            st.ebpf_ok = false;
            st.ebpf_error = Some(format!("eBPF unavailable: {e}"));
            // No eBPF — still release the child, but the timeline will stay empty.
            st.cold.launch_ts_ns = read_monotonic_ns();
        }
    }

    // Release the child. From this instant the cold timeline is live.
    // If SIGCONT fails we've already spawned the consumer thread, so
    // flip `stop` first so it unwinds instead of running against a
    // never-resumed target.
    if let Err(e) = handle.resume().context("resuming stopped child") {
        stop.store(true, Ordering::Relaxed);
        return Err(e);
    }

    // /proc poller for identity + RSS.
    {
        let state_p = Arc::clone(&state);
        let stop_p = Arc::clone(&stop);
        let target_p = PidTarget::attach(pid)?;
        std::thread::spawn(move || proc_poller(target_p, state_p, stop_p));
    }

    // Reaper: waitpid in the background, record exit status.
    {
        let state_r = Arc::clone(&state);
        std::thread::spawn(move || {
            let code = handle.wait().ok();
            let mut st = state_r.write().unwrap();
            st.cold.exit_status = code;
            st.cold.done = true;
            st.target_gone = true;
        });
    }

    let mut tui = Tui::init()?;
    tui.run(Arc::clone(&state), Arc::clone(&stop))?;

    stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(50));
    // Drop the sink; its Drop will not flush, so explicitly flush here.
    if let Some(w) = &sink {
        let _ = w.lock().unwrap().flush();
    }
    Ok(())
}

/// Replay a .ghost session file in the TUI. The replay thread dispatches
/// each frame through the same handlers the live consumer uses, so screens
/// see the same state shape — just no map-polled aggregates (those weren't
/// captured). An optional seek skips the first `seek_us` microseconds.
pub fn run_replay(path: String, seek: Option<String>) -> Result<()> {
    use crate::session::reader::SessionReader;

    let mut reader =
        SessionReader::open(&path).with_context(|| format!("opening session {path}"))?;

    // Decode mode name back to ActiveMode.
    let mode = match reader.meta.mode.as_str() {
        "lock" => ActiveMode::Lock,
        "catch" => ActiveMode::Catch,
        "cold" => ActiveMode::Cold,
        "jitter" => ActiveMode::Jitter,
        "snap" => ActiveMode::Snap,
        _ => ActiveMode::Watch,
    };
    let seek_us = seek.as_deref().map(parse_seek).transpose()?.unwrap_or(0);

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(reader.meta.pid, reader.meta.comm.clone());
        s.mode = mode;
        s.ebpf_ok = false;
        s.ebpf_error = Some(format!("replay {path}"));
        s.target_label = Some(format!("replay[{}]", reader.meta.mode));
        s
    }));
    let stop = Arc::new(AtomicBool::new(false));
    if let Err(e) = crate::signals::install_shutdown(&stop) {
        eprintln!("ghost: signal handler install failed: {e:#}");
    }

    // Replay thread: iterate frames, respect ts_delta_us (speed = 1x after seek).
    {
        let state_r = Arc::clone(&state);
        let stop_r = Arc::clone(&stop);
        std::thread::spawn(move || replay_loop(&mut reader, seek_us, state_r, stop_r));
    }

    let mut tui = Tui::init()?;
    tui.run(Arc::clone(&state), Arc::clone(&stop))?;
    stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(50));
    Ok(())
}

fn replay_loop(
    reader: &mut crate::session::reader::SessionReader,
    seek_us: u64,
    state: Arc<RwLock<AppState>>,
    stop: Arc<AtomicBool>,
) {
    let mut cumulative_us: u64 = 0;
    while !stop.load(Ordering::Relaxed) {
        let frame = match reader.next_frame() {
            Ok(Some(f)) => f,
            Ok(None) => {
                state.write().unwrap().target_gone = true;
                return;
            }
            Err(e) => {
                state.write().unwrap().ebpf_error = Some(format!("replay error: {e}"));
                return;
            }
        };
        let (_kind, delta_us, bytes) = frame;
        cumulative_us = cumulative_us.saturating_add(delta_us as u64);

        if cumulative_us <= seek_us {
            // Still inside the seek window — drop the frame entirely so
            // aggregates (WatchState, CatchLensState, …) don't include
            // the span the user explicitly asked to skip.
            continue;
        }

        if delta_us > 0 {
            // Cap pacing at 100ms so very long idle gaps don't freeze replay.
            let sleep_us = (delta_us as u64).min(100_000);
            std::thread::sleep(Duration::from_micros(sleep_us));
        }

        crate::ebpf::consumer::dispatch_event(&bytes, &state);
        crate::ebpf::consumer::dispatch_capture(&bytes, &state);
    }
}

fn parse_seek(s: &str) -> Result<u64> {
    // Accept "1s" / "500ms" / "250us" / "750000"
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    let (num, mult): (&str, u64) = if let Some(r) = s.strip_suffix("ms") {
        (r, 1_000)
    } else if let Some(r) = s.strip_suffix("us") {
        (r, 1)
    } else if let Some(r) = s.strip_suffix('s') {
        (r, 1_000_000)
    } else {
        (s, 1)
    };
    num.trim()
        .parse::<u64>()
        .map(|n| n.saturating_mul(mult))
        .map_err(|_| anyhow::anyhow!("ghost replay: bad --seek value '{s}'"))
}

/// Compute a brief diff between two .ghost sessions and print it.
pub fn run_diff(a: String, b: String) -> Result<()> {
    use crate::session::reader::SessionReader;
    let fold = |path: &str| -> Result<(SessionMeta, [u64; 11])> {
        let mut r = SessionReader::open(path)?;
        let mut counts = [0u64; 11];
        let meta_pid = r.meta.pid;
        let meta_comm = r.meta.comm.clone();
        let meta_mode = r.meta.mode.clone();
        let meta_start = r.meta.start_ns;
        let meta_host = r.meta.hostname.clone();
        while let Some((kind, _delta, _body)) = r.next_frame()? {
            if (kind as usize) < counts.len() {
                counts[kind as usize] += 1;
            }
        }
        Ok((
            SessionMeta {
                pid: meta_pid,
                comm: meta_comm,
                mode: meta_mode,
                start_ns: meta_start,
                hostname: meta_host,
            },
            counts,
        ))
    };

    let (ma, ca) = fold(&a).with_context(|| format!("reading {a}"))?;
    let (mb, cb) = fold(&b).with_context(|| format!("reading {b}"))?;

    println!(
        "A: {} pid={} mode={} host={}",
        a, ma.pid, ma.mode, ma.hostname
    );
    println!(
        "B: {} pid={} mode={} host={}",
        b, mb.pid, mb.mode, mb.hostname
    );
    println!("{:>14}  {:>10}  {:>10}  {:>10}", "KIND", "A", "B", "Δ(B-A)");
    for (i, name) in EVENT_KIND_NAMES.iter().enumerate() {
        if ca[i] == 0 && cb[i] == 0 {
            continue;
        }
        let d = cb[i] as i64 - ca[i] as i64;
        println!("{:>14}  {:>10}  {:>10}  {:>+10}", name, ca[i], cb[i], d);
    }
    Ok(())
}

const EVENT_KIND_NAMES: [&str; 11] = [
    "unknown",
    "SyscallExit",
    "SchedSwitch",
    "SchedWakeup",
    "FutexWait",
    "FutexWake",
    "IrqSpan",
    "Fork",
    "Exit",
    "ExecPhase",
    "CatchHit",
];

/// CLOCK_MONOTONIC nanoseconds — same clock as bpf_ktime_get_ns.
fn read_monotonic_ns() -> u64 {
    let mut ts: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn run_with_mode(
    pid: u32,
    record: Option<String>,
    mode: ActiveMode,
    catch_threshold_ns: u64,
) -> Result<()> {
    run_with_target(pid, record, mode, catch_threshold_ns, vec![], None, 1)
}

/// Headless pipeline: attach eBPF (if available) + /proc poller to the given
/// target, teeing frames into `sink`, and block until `stop` is set (by
/// SIGINT/SIGTERM or the target exiting). No TUI, no interactive state.
///
/// Used by `ghost daemon` to feed a `SessionDirWriter`. The caller owns the
/// `stop` flag (which is also registered against SIGINT/SIGTERM here) and
/// is responsible for flushing any wrapping writer after this returns.
pub fn run_headless(
    pid: u32,
    sink: RecordSink,
    extra_pids: Vec<u32>,
    target_label: Option<String>,
    tracked_count: usize,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let target = PidTarget::attach(pid)?;
    let comm = crate::proc::stat::Stat::read(pid)
        .map(|s| s.comm.clone())
        .unwrap_or_else(|_| "?".into());

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, comm.clone());
        s.mode = ActiveMode::Watch;
        s.catch.threshold_ns = 10_000_000;
        s.target_label = target_label;
        s.tracked_count = tracked_count.max(1);
        s
    }));
    if let Err(e) = crate::signals::install_shutdown(&stop) {
        eprintln!("ghost: signal handler install failed: {e:#}");
    }

    match load_ebpf(pid, 0) {
        Ok(mut ebpf) => {
            if !extra_pids.is_empty() {
                if let Err(e) = ebpf.track_pids(&extra_pids, pid) {
                    eprintln!("ghost: seeding extra pids failed: {e}");
                }
            }
            let watch_res = ebpf.attach_watch();
            let lock_res = ebpf.attach_lock();
            let catch_res = ebpf.attach_catch();
            let jitter_res = ebpf.attach_jitter();
            let track_res = ebpf.attach_track();
            let errors: Vec<_> = watch_res
                .errors()
                .into_iter()
                .chain(lock_res.errors())
                .chain(catch_res.errors())
                .chain(jitter_res.errors())
                .chain(track_res.errors())
                .map(|s| s.to_string())
                .collect();
            {
                let mut st = state.write().unwrap();
                st.ebpf_ok = errors.is_empty();
                st.ebpf_error = if errors.is_empty() {
                    None
                } else {
                    Some(errors.join("; "))
                };
            }
            let state_c = Arc::clone(&state);
            let stop_c = Arc::clone(&stop);
            let sink_c = sink.clone();
            std::thread::spawn(move || {
                crate::ebpf::consumer::run(ebpf, state_c, stop_c, sink_c);
            });
        }
        Err(e) => {
            eprintln!("ghost daemon: eBPF unavailable: {e}");
        }
    }

    {
        let state_p = Arc::clone(&state);
        let stop_p = Arc::clone(&stop);
        let target_p = PidTarget {
            pid: target.pid,
            start_time: target.start_time,
        };
        std::thread::spawn(move || proc_poller(target_p, state_p, stop_p));
    }

    // Block until signal or target exit. Target liveness is already written
    // into state.target_gone by the proc poller; mirror that into stop.
    while !stop.load(Ordering::Relaxed) {
        if state.read().unwrap().target_gone {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(100));
    if let Some(w) = &sink {
        let _ = w.lock().unwrap().flush();
    }
    Ok(())
}

fn run_with_target(
    pid: u32,
    record: Option<String>,
    mode: ActiveMode,
    catch_threshold_ns: u64,
    extra_pids: Vec<u32>,
    target_label: Option<String>,
    tracked_count: usize,
) -> Result<()> {
    // ── resolve target ────────────────────────────────────────────────────────
    let target = PidTarget::attach(pid)?;
    let comm = crate::proc::stat::Stat::read(pid)
        .map(|s| s.comm.clone())
        .unwrap_or_else(|_| "?".into());

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, comm.clone());
        s.mode = mode;
        // Mirror the kernel-side default (10 ms when the user didn't
        // pass `--above` explicitly) so the TUI header renders the live
        // threshold.
        s.catch.threshold_ns = if catch_threshold_ns > 0 {
            catch_threshold_ns
        } else {
            10_000_000
        };
        s.target_label = target_label;
        s.tracked_count = tracked_count.max(1);
        s
    }));
    let stop = Arc::new(AtomicBool::new(false));
    // Bridge SIGINT/SIGTERM → stop. Already-ok if the handler is
    // layered from a previous call-site in the same process (the
    // installer is idempotent for the AtomicBool target).
    if let Err(e) = crate::signals::install_shutdown(&stop) {
        eprintln!("ghost: signal handler install failed: {e:#}");
    }

    // ── try to load eBPF ──────────────────────────────────────────────────────
    let ebpf_result = load_ebpf(pid, catch_threshold_ns);

    // Open the session sink (if --record was passed) up front; the consumer
    // thread holds a clone and tees frames into it.
    let sink: RecordSink = record
        .as_deref()
        .and_then(|p| open_sink(p, pid, &comm, mode));

    match ebpf_result {
        Ok(mut ebpf) => {
            // Seed the extra pids (tree descendants, cgroup members).
            if !extra_pids.is_empty() {
                if let Err(e) = ebpf.track_pids(&extra_pids, pid) {
                    eprintln!("ghost: seeding extra pids failed: {e}");
                }
            }
            // Attach ALL live-view probes (not just the one the subcommand
            // picked), so the user can pivot between watch / lock / catch /
            // jitter / analyze from inside the TUI with `w` / `l` / `t` /
            // `j` / `a` without re-attaching. Each program is independent;
            // multi-attach on shared tracepoints like `raw_syscalls/sys_enter`
            // runs each handler in sequence. Cold stays out because it's
            // a spawn-time lens, not an attach.
            let watch_res = ebpf.attach_watch();
            let lock_res = ebpf.attach_lock();
            let catch_res = ebpf.attach_catch();
            let jitter_res = ebpf.attach_jitter();
            let track_res = ebpf.attach_track();

            let errors: Vec<_> = watch_res
                .errors()
                .into_iter()
                .chain(lock_res.errors())
                .chain(catch_res.errors())
                .chain(jitter_res.errors())
                .chain(track_res.errors())
                .map(|s| s.to_string())
                .collect();

            {
                let mut st = state.write().unwrap();
                st.ebpf_ok = errors.is_empty();
                st.ebpf_error = if errors.is_empty() {
                    None
                } else {
                    Some(errors.join("; "))
                };
            }

            // Spawn eBPF consumer thread.
            let state_c = Arc::clone(&state);
            let stop_c = Arc::clone(&stop);
            let sink_c = sink.clone();
            std::thread::spawn(move || {
                crate::ebpf::consumer::run(ebpf, state_c, stop_c, sink_c);
            });
        }
        Err(e) => {
            let mut st = state.write().unwrap();
            st.ebpf_ok = false;
            st.ebpf_error = Some(format!("eBPF unavailable: {e}"));
        }
    }

    // ── spawn /proc poller ────────────────────────────────────────────────────
    {
        let state_p = Arc::clone(&state);
        let stop_p = Arc::clone(&stop);
        let target_p = PidTarget {
            pid: target.pid,
            start_time: target.start_time,
        };
        std::thread::spawn(move || proc_poller(target_p, state_p, stop_p));
    }

    // ── TUI (blocks until quit) ───────────────────────────────────────────────
    let mut tui = Tui::init()?;
    tui.run(Arc::clone(&state), Arc::clone(&stop))?;

    // Signal background threads to exit.
    stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(50));

    Ok(())
}

fn load_ebpf(pid: u32, catch_above_ns: u64) -> Result<GhostEbpf> {
    let mut ebpf = GhostEbpf::load().map_err(|e| {
        // Attach a host-shape-aware remediation hint so the TUI's
        // ebpf_error status line (or an operator reading stderr) can
        // see exactly which capabilities are missing and how to grant
        // them on this host. The probes are read-only — safe to run
        // from an error path.
        let caps = crate::caps::cap_probe();
        let offset_findings = crate::ebpf::offset_probe::run();
        let offset_note = crate::ebpf::offset_probe::report(&offset_findings);
        let mut msg = format!("{e:#}");
        if !caps.is_sufficient_for_ebpf() {
            msg.push_str("\n\n");
            msg.push_str(&crate::caps::remediation_hint());
        }
        if !offset_note.is_empty() {
            msg.push('\n');
            msg.push_str(&offset_note);
        }
        anyhow::anyhow!(msg)
    })?;
    ebpf.track_pid(pid)?;
    let mut cfg = Config::default();
    // With the attach-all change the catch probe is loaded even for
    // `ghost <pid>` (default Watch). Seed a 10 ms floor so switching
    // to the catch view from inside the TUI fires on something; the
    // explicit `ghost catch --above <d>` subcommand still wins.
    cfg.catch_above_ns = if catch_above_ns > 0 {
        catch_above_ns
    } else {
        10_000_000
    };
    ebpf.set_config(cfg)?;
    Ok(ebpf)
}

fn proc_poller(target: PidTarget, state: Arc<RwLock<AppState>>, stop: Arc<AtomicBool>) {
    // Each supervisor gets its own analyzer engine; the config loads
    // once (silent-fallback to defaults on every error).
    let cfg = crate::analyze::config::load_or_default(None);
    let mut engine = crate::analyze::engine::AnalyzerEngine::new(cfg);
    while !stop.load(Ordering::Relaxed) {
        if !target.is_alive() {
            state.write().unwrap().target_gone = true;
            break;
        }
        match ProcSnapshot::collect(target.pid) {
            Ok(snap) => {
                let mut st = state.write().unwrap();
                // Update CPU history from /proc/stat delta.
                let curr_ticks = snap.stat.utime_ticks + snap.stat.stime_ticks;
                if let Some(prev) = st.watch.prev_cpu_ticks {
                    let delta_ticks = curr_ticks.saturating_sub(prev);
                    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f32;
                    let cpu_pct = (delta_ticks as f32 / hz.max(1.0)) * 100.0;
                    st.watch.cpu_history.push_back(cpu_pct.min(100.0));
                    if st.watch.cpu_history.len() > crate::state::HISTORY_DEPTH {
                        st.watch.cpu_history.pop_front();
                    }
                }
                st.watch.prev_cpu_ticks = Some(curr_ticks);
                // /proc reports counters for the representative PID only.
                // For single-PID targets that's authoritative (lifetime
                // count including pre-attach history); for multi-PID
                // targets (tree, cgroup) it would discard every switch
                // we're already summing from sched_switch across the
                // other members, so defer to the eBPF-side counters in
                // that case.
                if st.tracked_count <= 1 {
                    st.watch.voluntary_ctx = snap.status.voluntary_ctxt_switches;
                    st.watch.involuntary_ctx = snap.status.nonvoluntary_ctxt_switches;
                }
                st.snap = Some(snap);
                // Reflect any TUI-driven mode / floor toggles back into the engine.
                engine.set_mode(st.analyze.mode);
                engine.global_floor = st.analyze.global_floor;
                // Run analyzer against this tick's state.
                let mut analyze_out = std::mem::take(&mut st.analyze);
                engine.tick(&st, &mut analyze_out);
                st.analyze = analyze_out;
            }
            Err(_) => {
                state.write().unwrap().target_gone = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seek_bare_us() {
        assert_eq!(parse_seek("500").unwrap(), 500);
    }
    #[test]
    fn parse_seek_ms() {
        assert_eq!(parse_seek("250ms").unwrap(), 250_000);
    }
    #[test]
    fn parse_seek_s() {
        assert_eq!(parse_seek("2s").unwrap(), 2_000_000);
    }
    #[test]
    fn parse_seek_us() {
        assert_eq!(parse_seek("750us").unwrap(), 750);
    }
    #[test]
    fn parse_seek_empty_zero() {
        assert_eq!(parse_seek("").unwrap(), 0);
    }
    #[test]
    fn parse_seek_bad() {
        assert!(parse_seek("nope").is_err());
    }

    #[test]
    fn mode_name_covers_all_variants() {
        assert_eq!(mode_name(ActiveMode::Watch), "watch");
        assert_eq!(mode_name(ActiveMode::Lock), "lock");
        assert_eq!(mode_name(ActiveMode::Catch), "catch");
        assert_eq!(mode_name(ActiveMode::Cold), "cold");
        assert_eq!(mode_name(ActiveMode::Jitter), "jitter");
        assert_eq!(mode_name(ActiveMode::Snap), "snap");
    }
}
