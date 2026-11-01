//! Ring-buffer drain thread (ARCHITECTURE §6).

use std::{
    sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};

use aya::maps::RingBuf;
use ghost_common::{EventKind, ExitRecord, SchedSwitchRecord};

use crate::{
    ebpf::loader::GhostEbpf,
    state::AppState,
};

pub fn run(
    mut ebpf: GhostEbpf,
    state:    Arc<RwLock<AppState>>,
    stop:     Arc<AtomicBool>,
) {
    let poll_interval      = Duration::from_millis(500);
    let mut last_stat_poll = Instant::now();

    while !stop.load(Ordering::Relaxed) {
        // ── Phase 1: drain ring buffer ─────────────────────────────────────
        // Re-borrow map_mut each tick. RingBuf is a thin wrapper; the consumer
        // position lives in the kernel's consumer page (shared memory), so
        // recreating the struct preserves the read pointer.
        {
            let Some(map_mut) = ebpf.ebpf.map_mut("EVENTS") else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            if let Ok(mut ring) = RingBuf::try_from(map_mut) {
                while let Some(item) = ring.next() {
                    dispatch_event(&item, &state);
                }
            }
        } // map_mut borrow released here

        // ── Phase 2: refresh syscall stats (immutable borrow, no conflict) ─
        if last_stat_poll.elapsed() >= poll_interval {
            last_stat_poll = Instant::now();
            let stats = ebpf.read_syscall_stats();
            let mut st = state.write().unwrap();
            let total_ns:    u64 = stats.iter().map(|(_, s)| s.total_ns).sum();
            let total_count: u64 = stats.iter().map(|(_, s)| s.count).sum();
            st.watch.top_syscalls   = stats.into_iter().take(20).collect();
            st.watch.total_syscalls = total_count;
            st.watch.total_cpu_ns   = total_ns;
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn dispatch_event(bytes: &[u8], state: &Arc<RwLock<AppState>>) {
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
