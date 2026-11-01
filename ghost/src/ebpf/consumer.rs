//! Ring-buffer drain thread (ARCHITECTURE §6).

use std::{
    sync::{Arc, Mutex, RwLock, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};

use aya::maps::RingBuf;
use ghost_common::{CatchRecord, EventKind, ExitRecord, SchedSwitchRecord};

use crate::{
    ebpf::loader::GhostEbpf,
    session::writer::SessionWriter,
    state::{AppState, CatchHit},
};

/// Optional tee sink shared with the supervisor; wrapped in Mutex because
/// SessionWriter is `&mut`-only.
pub type RecordSink = Option<Arc<Mutex<SessionWriter>>>;

pub fn run(
    mut ebpf:   GhostEbpf,
    state:      Arc<RwLock<AppState>>,
    stop:       Arc<AtomicBool>,
    record:     RecordSink,
) {
    let poll_interval      = Duration::from_millis(500);
    let mut last_stat_poll = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        // ── Phase 1: drain ring buffer ─────────────────────────────────────
        // Re-borrow map_mut each tick. RingBuf is a thin wrapper; the consumer
        // position lives in the kernel's consumer page (shared memory), so
        // recreating the struct preserves the read pointer.
        {
            if let Some(map_mut) = ebpf.ebpf.map_mut("EVENTS") {
                if let Ok(mut ring) = RingBuf::try_from(map_mut) {
                    while let Some(item) = ring.next() {
                        dispatch_event(&item, &state);
                        tee(&record, &item);
                    }
                }
            }
        } // map_mut borrow released here

        // Drain the CAPTURE ring (catch lens). Separate map, so a separate borrow.
        {
            if let Some(map_mut) = ebpf.ebpf.map_mut("CAPTURE") {
                if let Ok(mut ring) = RingBuf::try_from(map_mut) {
                    while let Some(item) = ring.next() {
                        dispatch_capture(&item, &state);
                        tee(&record, &item);
                    }
                }
            }
        }

        // ── Phase 2: refresh map-backed stats (immutable borrow, no conflict) ─
        if last_stat_poll.elapsed() >= poll_interval {
            last_stat_poll = Instant::now();

            // syscall stats (watch lens)
            let stats = ebpf.read_syscall_stats();
            // lock stats (lock lens) — cheap: empty vec if the map is empty.
            let locks = ebpf.read_lock_stats();
            // cold stats (cold lens) — cheap: empty vec if the map is empty.
            let cold = ebpf.read_cold_stats();
            // jitter stats (jitter lens) — cheap: empty if maps are empty.
            let hard = ebpf.read_irq_stats();
            let soft = ebpf.read_softirq_stats();

            let mut st = state.write().unwrap();

            let total_ns:    u64 = stats.iter().map(|(_, s)| s.total_ns).sum();
            let total_count: u64 = stats.iter().map(|(_, s)| s.count).sum();
            st.watch.top_syscalls   = stats.into_iter().take(20).collect();
            st.watch.total_syscalls = total_count;
            st.watch.total_cpu_ns   = total_ns;

            let waits_total: u64 = locks.iter().map(|(_, s)| s.waits).sum();
            let ns_total:    u64 = locks.iter().map(|(_, s)| s.total_wait_ns).sum();
            st.lock.top_locks     = locks.into_iter().take(20).collect();
            st.lock.total_waits   = waits_total;
            st.lock.total_wait_ns = ns_total;

            st.cold.timeline = cold.into_iter()
                .map(|(_pid, nr, s)| (nr, s.first_ts_ns, s.count))
                .collect();

            let hard_total: u64 = hard.iter().map(|(_, s)| s.total_ns).sum();
            let soft_total: u64 = soft.iter().map(|(_, s)| s.total_ns).sum();
            st.jitter.hard_irqs        = hard;
            st.jitter.soft_irqs        = soft;
            st.jitter.total_irq_ns     = hard_total;
            st.jitter.total_softirq_ns = soft_total;
            // involuntary_ctx comes from the sched_switch path we already have in
            // the watch pipeline; mirror what the proc poller writes to watch
            // so the jitter screen stays coherent even in watch-less sessions.
            st.jitter.involuntary_ctx  = st.watch.involuntary_ctx;

            // Dynamic PID_SET size — grows via in-kernel fork propagation.
            let n = ebpf.tracked_count();
            if n > 0 { st.tracked_count = n; }

            // Keep the session file on disk warm.
            if let Some(w) = &record {
                let _ = w.lock().unwrap().flush();
            }
        }

        std::thread::sleep(Duration::from_millis(10));
    }

    // Final flush on shutdown.
    if let Some(w) = &record {
        let _ = w.lock().unwrap().flush();
    }
}

/// Write a raw frame to the optional session sink. The first byte of the
/// ring-buffer slice is already the EventKind discriminant, so we pass it
/// as `kind` and the rest as the body.
fn tee(sink: &RecordSink, bytes: &[u8]) {
    let Some(sink) = sink else { return };
    let Some(&kind) = bytes.first() else { return };
    if let Ok(mut w) = sink.lock() {
        let _ = w.write_frame(kind, bytes);
    }
}

pub(crate) fn dispatch_capture(bytes: &[u8], state: &Arc<RwLock<AppState>>) {
    let Some(&kind_byte) = bytes.first() else { return };
    if kind_byte != EventKind::CatchHit as u8 { return; }
    if bytes.len() < core::mem::size_of::<CatchRecord>() { return; }

    let rec: CatchRecord = unsafe {
        core::ptr::read_unaligned(bytes.as_ptr() as *const CatchRecord)
    };
    let mut st = state.write().unwrap();
    st.catch.push(CatchHit {
        ts_ns:    rec.ts_ns,
        tid:      rec.tid,
        nr:       rec.nr,
        delta_ns: rec.delta_ns,
    });
}

pub(crate) fn dispatch_event(bytes: &[u8], state: &Arc<RwLock<AppState>>) {
    let Some(&kind_byte) = bytes.first() else { return };

    if kind_byte == EventKind::SchedSwitch as u8 {
        if bytes.len() < core::mem::size_of::<SchedSwitchRecord>() { return; }
        let rec: SchedSwitchRecord = unsafe {
            core::ptr::read_unaligned(bytes.as_ptr() as *const SchedSwitchRecord)
        };
        let mut st = state.write().unwrap();
        if rec.involuntary == 1 {
            st.watch.involuntary_ctx += 1;
        } else {
            st.watch.voluntary_ctx += 1;
        }
    } else if kind_byte == EventKind::Exit as u8 {
        if bytes.len() < core::mem::size_of::<ExitRecord>() { return; }
        let rec: ExitRecord = unsafe {
            core::ptr::read_unaligned(bytes.as_ptr() as *const ExitRecord)
        };
        let mut st = state.write().unwrap();
        if rec.pid == st.pid {
            st.target_gone = true;
        }
    }
}
