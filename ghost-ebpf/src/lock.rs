//! lock programs: futex contention timing via sys_enter_futex/sys_exit_futex.
//!
//! Tracepoint offsets verified against /sys/kernel/debug/tracing/events/:
//!   syscalls/sys_enter_futex: uaddr @ 16 (u64 ptr), op @ 24 (int, 8-byte slot)
//!   syscalls/sys_exit_futex:  ret   @ 16 (long)
//!
//! We only time FUTEX_WAIT / FUTEX_WAIT_BITSET — those are the operations that
//! actually block a waiter and are what "lock contention" means to the user.
//! Wakes are counted indirectly: each completed WAIT returned by the kernel
//! implies a wake arrived (or the waiter was interrupted / timed out).

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use ghost_common::{FutexInflight, LockStat};

use crate::{FUTEX_INFLIGHT, LOCK_STAT, PID_SET};

// FUTEX op constants (uapi/linux/futex.h). We mask the low 7 bits.
const FUTEX_CMD_MASK: i32 = 0x7f;
const FUTEX_WAIT: i32 = 0;
const FUTEX_WAIT_BITSET: i32 = 9;

// ── sys_enter_futex ─────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_futex(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter_futex(ctx) }.unwrap_or(0)
}

unsafe fn try_sys_enter_futex(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;

    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let op_raw: i64 = ctx.read_at(24)?;
    let cmd = (op_raw as i32) & FUTEX_CMD_MASK;
    if cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET {
        return Ok(0);
    }

    let uaddr: u64 = ctx.read_at(16)?;
    let tid = tgid_tid as u32;
    let ts = bpf_ktime_get_ns();

    let inflight = FutexInflight { ts_ns: ts, uaddr };
    FUTEX_INFLIGHT.insert(&tid, &inflight, 0).ok();
    Ok(0)
}

// ── sys_exit_futex ──────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_exit_futex(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_exit_futex(ctx) }.unwrap_or(0)
}

unsafe fn try_sys_exit_futex(_ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;

    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let tid = tgid_tid as u32;
    let Some(&inflight) = FUTEX_INFLIGHT.get(&tid) else {
        return Ok(0);
    };
    FUTEX_INFLIGHT.remove(&tid).ok();

    let now = bpf_ktime_get_ns();
    let delta = now.saturating_sub(inflight.ts_ns);
    let uaddr = inflight.uaddr;

    if let Some(stat) = LOCK_STAT.get_ptr_mut(&uaddr) {
        (*stat).waits += 1;
        (*stat).total_wait_ns += delta;
        if delta > (*stat).max_wait_ns {
            (*stat).max_wait_ns = delta;
        }
    } else {
        let stat = LockStat {
            waits: 1,
            total_wait_ns: delta,
            max_wait_ns: delta,
            holder_tid: 0,
            max_queue: 0,
        };
        LOCK_STAT.insert(&uaddr, &stat, 0).ok();
    }

    Ok(0)
}
