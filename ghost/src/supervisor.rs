//! Thread lifecycle: load eBPF, spawn poller + consumer, run TUI (ARCHITECTURE §3).

use std::{
    sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use anyhow::{Context, Result};
use ghost_common::Config;

use crate::{
    ebpf::loader::GhostEbpf,
    proc::ProcSnapshot,
    state::{ActiveMode, AppState},
    target::pid::PidTarget,
    tui::app::Tui,
};

pub fn run(pid: u32, record: Option<String>) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Watch, 0)
}

pub fn run_lock(pid: u32, record: Option<String>) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Lock, 0)
}

pub fn run_catch(pid: u32, record: Option<String>, threshold_ns: u64) -> Result<()> {
    run_with_mode(pid, record, ActiveMode::Catch, threshold_ns)
}

/// Launch `cmd` under cold-mode instrumentation: fork the target with
/// SIGSTOP, wire it into PID_SET + the cold BPF program, write COLD_LAUNCH,
/// then SIGCONT and watch its startup until it exits.
pub fn run_cold(cmd: Vec<String>, record: Option<String>) -> Result<()> {
    use crate::target::cmd::CmdHandle;

    if cmd.is_empty() {
        anyhow::bail!("ghost cold: no command supplied");
    }

    let handle = CmdHandle::spawn_stopped(&cmd)
        .context("ghost cold: spawning stopped child")?;
    let pid = handle.pid as u32;
    let cmdline = cmd.join(" ");

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, cmd[0].clone());
        s.mode = ActiveMode::Cold;
        s.cold.cmdline = cmdline;
        s
    }));
    let stop  = Arc::new(AtomicBool::new(false));

    // Load eBPF, track the stopped child, attach cold probe.
    let ebpf_result = load_ebpf(pid, 0);
    let mut launch_ns: u64 = 0;
    match ebpf_result {
        Ok(mut ebpf) => {
            let probe_res = ebpf.attach_cold();
            let track_res = ebpf.attach_track();
            let errors: Vec<_> = probe_res.errors().into_iter()
                .chain(track_res.errors())
                .map(|s| s.to_string())
                .collect();

            // Timestamp the launch moment just before releasing the child.
            launch_ns = read_monotonic_ns();
            let _ = ebpf.set_cold_launch(launch_ns);

            {
                let mut st = state.write().unwrap();
                st.ebpf_ok    = errors.is_empty();
                st.ebpf_error = if errors.is_empty() { None } else { Some(errors.join("; ")) };
                st.cold.launch_ts_ns = launch_ns;
            }

            // Spawn the consumer BEFORE resuming the child so no event is lost
            // between SIGCONT and the first poll.
            let state_c = Arc::clone(&state);
            let stop_c  = Arc::clone(&stop);
            std::thread::spawn(move || {
                crate::ebpf::consumer::run(ebpf, state_c, stop_c);
            });
        }
        Err(e) => {
            let mut st = state.write().unwrap();
            st.ebpf_ok    = false;
            st.ebpf_error = Some(format!("eBPF unavailable: {e}"));
            // No eBPF — still release the child, but the timeline will stay empty.
            launch_ns = read_monotonic_ns();
            st.cold.launch_ts_ns = launch_ns;
        }
    }

    // Release the child. From this instant the cold timeline is live.
    handle.resume().context("resuming stopped child")?;

    // /proc poller for identity + RSS.
    {
        let state_p = Arc::clone(&state);
        let stop_p  = Arc::clone(&stop);
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
            st.cold.done        = true;
            st.target_gone      = true;
        });
    }

    if let Some(path) = record {
        eprintln!("ghost: cold recording to {path} (writer stub)");
    }

    let mut tui = Tui::init()?;
    tui.run(Arc::clone(&state), Arc::clone(&stop))?;

    stop.store(true, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(50));
    Ok(())
}

/// CLOCK_MONOTONIC nanoseconds — same clock as bpf_ktime_get_ns.
fn read_monotonic_ns() -> u64 {
    let mut ts: libc::timespec = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts); }
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

fn run_with_mode(pid: u32, record: Option<String>, mode: ActiveMode, catch_threshold_ns: u64) -> Result<()> {
    // ── resolve target ────────────────────────────────────────────────────────
    let target = PidTarget::attach(pid)?;
    let comm   = crate::proc::stat::Stat::read(pid)
        .map(|s| s.comm.clone())
        .unwrap_or_else(|_| "?".into());

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, comm.clone());
        s.mode = mode;
        s.catch.threshold_ns = catch_threshold_ns;
        s
    }));
    let stop  = Arc::new(AtomicBool::new(false));

    // ── try to load eBPF ──────────────────────────────────────────────────────
    let ebpf_result = load_ebpf(pid, catch_threshold_ns);

    match ebpf_result {
        Ok(mut ebpf) => {
            // Attach probes needed for the active mode. Lock mode needs futex
            // tracepoints; watch mode needs the sys_enter/exit + sched_switch
            // set. Track probes (fork/exit) are always useful.
            let probe_res = match mode {
                ActiveMode::Lock  => ebpf.attach_lock(),
                ActiveMode::Catch => ebpf.attach_catch(),
                _                 => ebpf.attach_watch(),
            };
            let track_res = ebpf.attach_track();

            let errors: Vec<_> = probe_res.errors().into_iter()
                .chain(track_res.errors())
                .map(|s| s.to_string())
                .collect();

            {
                let mut st = state.write().unwrap();
                st.ebpf_ok    = errors.is_empty();
                st.ebpf_error = if errors.is_empty() { None } else {
                    Some(errors.join("; "))
                };
            }

            // Spawn eBPF consumer thread.
            let state_c  = Arc::clone(&state);
            let stop_c   = Arc::clone(&stop);
            std::thread::spawn(move || {
                crate::ebpf::consumer::run(ebpf, state_c, stop_c);
            });
        }
        Err(e) => {
            let mut st = state.write().unwrap();
            st.ebpf_ok    = false;
            st.ebpf_error = Some(format!("eBPF unavailable: {e}"));
        }
    }

    // ── spawn /proc poller ────────────────────────────────────────────────────
    {
        let state_p  = Arc::clone(&state);
        let stop_p   = Arc::clone(&stop);
        let target_p = PidTarget { pid: target.pid, start_time: target.start_time };
        std::thread::spawn(move || proc_poller(target_p, state_p, stop_p));
    }

    // ── optional session writer ───────────────────────────────────────────────
    if let Some(path) = record {
        let meta = crate::session::format::SessionMeta::new(pid, &comm, "watch");
        match crate::session::writer::SessionWriter::open(&path, &meta) {
            Ok(_writer) => {
                // TODO: thread to tee events from consumer to writer
                eprintln!("ghost: recording to {path} (writer stub)");
            }
            Err(e) => eprintln!("ghost: could not open session file {path}: {e}"),
        }
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
    let mut ebpf = GhostEbpf::load()?;
    ebpf.track_pid(pid)?;
    let mut cfg = Config::default();
    cfg.catch_above_ns = catch_above_ns;
    ebpf.set_config(cfg)?;
    Ok(ebpf)
}

fn proc_poller(
    target: PidTarget,
    state:  Arc<RwLock<AppState>>,
    stop:   Arc<AtomicBool>,
) {
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
                st.watch.voluntary_ctx   = snap.status.voluntary_ctxt_switches;
                st.watch.involuntary_ctx = snap.status.nonvoluntary_ctxt_switches;
                st.snap = Some(snap);
            }
            Err(_) => {
                state.write().unwrap().target_gone = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(1000));
    }
}
