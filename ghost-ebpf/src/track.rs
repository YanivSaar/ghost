//! track programs: maintain PID_SET across fork/exec/exit.
//!
//! Tracepoint offsets:
//!   sched/sched_process_fork: parent_pid @ 12, child_pid @ 20
//!   sched/sched_process_exit: pid @ 24
//!
//! Note on `sched_process_exit`: the `pid` field at offset 24 is the
//! kernel's `task_struct->pid`, i.e. the TID — one event fires per
//! thread of a multithreaded process. Because fork propagation inserts
//! every clone-child into PID_SET, each thread exit correctly removes
//! its own entry. The ExitRecord's `pid` is therefore a TID too, and
//! consumer's `rec.pid == st.pid` check only trips when the thread
//! whose TID == the user-supplied PID exits — which, for the usual
//! `ghost <pid>` where <pid> is a TGID (process ID / main-thread TID),
//! coincides with the thread-group leader's exit. For the inverse
//! (user attached to a non-leader TID, or a cold-launched child whose
//! main thread exits via `exit_group` while workers still run), fall
//! back on the /proc poller's own `target_gone` edge in supervisor.rs.

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use ghost_common::{ExitRecord, TrackInfo};

use crate::{EVENTS, PID_SET};

// ── fork: propagate tracking into child ──────────────────────────────────────

#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    unsafe { try_fork(ctx) }.unwrap_or(0)
}

unsafe fn try_fork(ctx: TracePointContext) -> Result<u32, i64> {
    let parent_pid: u32 = ctx.read_at(12)?;
    let child_pid: u32 = ctx.read_at(20)?;

    if let Some(&info) = PID_SET.get(&parent_pid) {
        PID_SET
            .insert(&child_pid, &TrackInfo { root: info.root }, 0)
            .ok();
    }
    Ok(0)
}

// ── exit: remove from PID_SET and emit Exit event ────────────────────────────

#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_exit(ctx) }.unwrap_or(0)
}

unsafe fn try_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let pid: u32 = ctx.read_at(24)?;

    if PID_SET.get(&pid).is_none() {
        return Ok(0);
    }
    PID_SET.remove(&pid).ok();

    let rec = ExitRecord {
        kind: 8,
        _pad: [0; 3],
        pid,
    };
    if let Some(mut entry) = EVENTS.reserve::<ExitRecord>(0) {
        core::ptr::write(entry.as_mut_ptr(), rec);
        entry.submit(0);
    }

    Ok(0)
}
