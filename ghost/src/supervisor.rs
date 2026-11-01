//! Thread lifecycle: load eBPF, spawn poller + consumer, run TUI (ARCHITECTURE §3).

use std::{
    sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use anyhow::Result;
use ghost_common::Config;

use crate::{
    ebpf::loader::GhostEbpf,
    proc::ProcSnapshot,
    state::AppState,
    target::pid::PidTarget,
    tui::app::Tui,
};

pub fn run(pid: u32, record: Option<String>) -> Result<()> {
    // ── resolve target ────────────────────────────────────────────────────────
    let target = PidTarget::attach(pid)?;
    let comm   = crate::proc::stat::Stat::read(pid)
        .map(|s| s.comm.clone())
        .unwrap_or_else(|_| "?".into());

    let state = Arc::new(RwLock::new(AppState::new(pid, comm.clone())));
    let stop  = Arc::new(AtomicBool::new(false));

    // ── try to load eBPF ──────────────────────────────────────────────────────
    let ebpf_result = load_ebpf(pid);

    match ebpf_result {
        Ok(mut ebpf) => {
            // Attach watch + track probes (incremental — failures are logged, not fatal).
            let watch_res = ebpf.attach_watch();
            let track_res = ebpf.attach_track();

            let errors: Vec<_> = watch_res.errors().into_iter()
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

fn load_ebpf(pid: u32) -> Result<GhostEbpf> {
    let mut ebpf = GhostEbpf::load()?;
    ebpf.track_pid(pid)?;
    ebpf.set_config(Config::default())?;
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
