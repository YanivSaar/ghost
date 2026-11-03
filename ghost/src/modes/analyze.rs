//! `ghost analyze` CLI runner. Two forms:
//!   * `ghost analyze <file.ghost>`             — offline over a session
//!   * `ghost analyze --pid <pid> --duration …` — live attach
//!
//! Produces plain-text (default), JSON array, or JSONL.

use anyhow::{Context, Result};
use std::{
    path::PathBuf,
    sync::{atomic::AtomicBool, Arc, RwLock},
    thread,
    time::{Duration, Instant},
};

use crate::{
    analyze::{
        config::load_or_default, engine::AnalyzerEngine, json, report, AnalyzerState, Diagnosis,
        Mode,
    },
    state::{ActiveMode, AppState},
};

#[derive(Clone, Copy, Debug)]
pub enum Format {
    Plain,
    Json,
    Jsonl,
}

pub struct Args {
    pub file: Option<String>,
    pub pid: Option<u32>,
    pub duration: String,
    pub format: Format,
    pub mode: Mode,
    pub config: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    match (&args.file, args.pid) {
        (Some(path), None) => run_offline(path.clone(), args),
        (None, Some(pid)) => run_live(pid, args),
        _ => {
            anyhow::bail!(
                "ghost analyze: supply a session file OR --pid <pid> (not both / neither)"
            )
        }
    }
}

// ─────────────── live mode ─────────────────────────────────────────────────

fn run_live(pid: u32, args: Args) -> Result<()> {
    let dur = parse_duration(&args.duration)?;
    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(pid, "?".into());
        s.mode = ActiveMode::Analyze;
        s.analyze.mode = args.mode;
        s
    }));
    let stop = Arc::new(AtomicBool::new(false));

    // Install Ctrl-C → stop before any thread starts.
    let _ = crate::signals::install_shutdown(&stop);

    // Spawn a /proc poller directly here; we don't need eBPF for the
    // *common-shape* rules — they only need /proc deltas. (eBPF would
    // populate lock / jitter / per-syscall data, but a 10s live sample
    // without CAP_BPF still produces useful diagnoses.)
    let target = crate::target::pid::PidTarget::attach(pid)?;
    let state_p = Arc::clone(&state);
    let stop_p = Arc::clone(&stop);
    let cfg_path = args.config.clone().map(PathBuf::from);
    thread::spawn(move || {
        proc_poller_live(target, state_p, stop_p, cfg_path);
    });

    // Emit events as diagnoses appear/disappear.
    let format = args.format;
    let mut emitter = Emitter::new(format);
    let start = Instant::now();

    // JSON array needs an open bracket.
    if matches!(format, Format::Json) {
        print!("[");
    }

    while start.elapsed() < dur && !stop.load(std::sync::atomic::Ordering::Relaxed) {
        thread::sleep(Duration::from_millis(1000));
        let st = state.read().unwrap();
        emitter.step(&st.analyze, start.elapsed().as_millis() as u64);
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    // Final sweep: any still-active diagnosis gets no explicit "end" row.
    if matches!(format, Format::Json) {
        emitter.flush_json_tail();
    }
    Ok(())
}

fn proc_poller_live(
    target: crate::target::pid::PidTarget,
    state: Arc<RwLock<AppState>>,
    stop: Arc<AtomicBool>,
    cfg_path: Option<PathBuf>,
) {
    let cfg = load_or_default(cfg_path.as_deref());
    let mut engine = AnalyzerEngine::new(cfg);
    engine.set_mode(state.read().unwrap().analyze.mode);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        if !target.is_alive() {
            state.write().unwrap().target_gone = true;
            break;
        }
        if let Ok(snap) = crate::proc::ProcSnapshot::collect(target.pid) {
            let mut st = state.write().unwrap();
            let curr_ticks = snap.stat.utime_ticks + snap.stat.stime_ticks;
            if let Some(prev) = st.watch.prev_cpu_ticks {
                let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) } as f32;
                let cpu = ((curr_ticks.saturating_sub(prev)) as f32 / hz.max(1.0)) * 100.0;
                st.watch.cpu_history.push_back(cpu.min(100.0));
                if st.watch.cpu_history.len() > crate::state::HISTORY_DEPTH {
                    st.watch.cpu_history.pop_front();
                }
            }
            st.watch.prev_cpu_ticks = Some(curr_ticks);
            if st.tracked_count <= 1 {
                st.watch.voluntary_ctx = snap.status.voluntary_ctxt_switches;
                st.watch.involuntary_ctx = snap.status.nonvoluntary_ctxt_switches;
            }
            st.snap = Some(snap);
            let mut out = std::mem::take(&mut st.analyze);
            engine.tick(&st, &mut out);
            st.analyze = out;
        }
        thread::sleep(Duration::from_millis(1000));
    }
}

// ─────────────── offline (session file) ────────────────────────────────────

fn run_offline(path: String, args: Args) -> Result<()> {
    use crate::session::reader::SessionReader;
    let mut reader =
        SessionReader::open(&path).with_context(|| format!("opening session {path}"))?;

    let state = Arc::new(RwLock::new({
        let mut s = AppState::new(reader.meta.pid, reader.meta.comm.clone());
        s.mode = ActiveMode::Analyze;
        s.analyze.mode = args.mode;
        s
    }));
    let cfg = load_or_default(args.config.as_deref().map(PathBuf::from).as_deref());
    let mut engine = AnalyzerEngine::new(cfg);
    engine.set_mode(args.mode);

    let format = args.format;
    let mut emitter = Emitter::new(format);
    if matches!(format, Format::Json) {
        print!("[");
    }

    let mut cumulative_us: u64 = 0;
    let mut last_tick_us: u64 = 0;
    const TICK_US: u64 = 1_000_000;
    while let Some((_kind, delta_us, bytes)) = reader
        .next_frame()
        .map_err(|e| anyhow::anyhow!("replay error: {e}"))?
    {
        cumulative_us = cumulative_us.saturating_add(delta_us as u64);
        crate::ebpf::consumer::dispatch_event(&bytes, &state);
        crate::ebpf::consumer::dispatch_capture(&bytes, &state);

        // Every simulated second → engine tick.
        while cumulative_us - last_tick_us >= TICK_US {
            last_tick_us += TICK_US;
            let mut st = state.write().unwrap();
            let mut out = std::mem::take(&mut st.analyze);
            engine.tick(&st, &mut out);
            st.analyze = out;
            emitter.step(&st.analyze, last_tick_us / 1000);
        }
    }
    if matches!(format, Format::Json) {
        emitter.flush_json_tail();
    }
    Ok(())
}

// ─────────────── emitter: begin / end diffing over successive snapshots ───

struct Emitter {
    format: Format,
    active: std::collections::HashSet<&'static str>,
    json_first: bool,
}

impl Emitter {
    fn new(format: Format) -> Self {
        Self {
            format,
            active: std::collections::HashSet::new(),
            json_first: true,
        }
    }

    fn step(&mut self, a: &AnalyzerState, ts_ms: u64) {
        let now_ids: std::collections::HashSet<&'static str> =
            a.current.iter().map(|d| d.id).collect();
        // begins: in now, not in active
        for d in &a.current {
            if !self.active.contains(d.id) {
                self.emit_begin(d, ts_ms);
            }
        }
        // ends: in active, not in now
        let ended: Vec<&'static str> = self.active.difference(&now_ids).copied().collect();
        for id in ended {
            self.emit_end(id, ts_ms);
        }
        self.active = now_ids;
    }

    fn emit_begin(&mut self, d: &Diagnosis, ts_ms: u64) {
        match self.format {
            Format::Plain => {
                println!("{}", report::format_plain(d, ts_ms));
            }
            Format::Json => {
                let e = json::begin_event(ts_ms, d);
                self.json_sep();
                print!("{}", serde_json::to_string(&e).unwrap());
            }
            Format::Jsonl => {
                let e = json::begin_event(ts_ms, d);
                println!("{}", serde_json::to_string(&e).unwrap());
            }
        }
    }

    fn emit_end(&mut self, id: &'static str, ts_ms: u64) {
        match self.format {
            Format::Plain => {
                let min = ts_ms / 60_000;
                let sec = (ts_ms % 60_000) / 1000;
                let ms = ts_ms % 1000;
                println!("{:02}:{:02}.{:03}  {:<22} resolved", min, sec, ms, id);
            }
            Format::Json => {
                let e = json::end_event(ts_ms, id);
                self.json_sep();
                print!("{}", serde_json::to_string(&e).unwrap());
            }
            Format::Jsonl => {
                let e = json::end_event(ts_ms, id);
                println!("{}", serde_json::to_string(&e).unwrap());
            }
        }
    }

    fn json_sep(&mut self) {
        if self.json_first {
            self.json_first = false;
        } else {
            print!(",");
        }
    }

    fn flush_json_tail(&mut self) {
        println!("]");
    }
}

fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    let (num, mult_ms): (&str, u64) = if let Some(r) = s.strip_suffix("ms") {
        (r, 1)
    } else if let Some(r) = s.strip_suffix('s') {
        (r, 1000)
    } else if let Some(r) = s.strip_suffix('m') {
        (r, 60_000)
    } else {
        (s, 1000)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("ghost analyze: bad --duration '{s}'"))?;
    Ok(Duration::from_millis(n.saturating_mul(mult_ms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_formats() {
        assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_duration("5").unwrap(), Duration::from_secs(5));
        assert!(parse_duration("junk").is_err());
    }
}
