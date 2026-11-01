//! cold programs: startup archaeology.
//!
//! A single sys_enter_cold tracepoint on raw_syscalls/sys_enter records the
//! first-observed timestamp and running count for each (pid, nr) pair in
//! COLD_STAT. The userspace side launches a stopped child, inserts it into
//! PID_SET, writes COLD_LAUNCH[0] = now, then SIGCONTs the child — so the
//! first entry stored here is the first syscall the child ever made after
//! being observed, i.e. the earliest sign of life.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use ghost_common::ColdStat;

use crate::{COLD_STAT, PID_SET};

#[tracepoint]
pub fn sys_enter_cold(ctx: TracePointContext) -> u32 {
    unsafe { try_enter(ctx) }.unwrap_or(0)
}

unsafe fn try_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;
    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let nr: i64 = ctx.read_at(8)?;
    let key: u64 = (tgid as u64) << 32 | (nr as u64 & 0xffff_ffff);

    if let Some(stat) = COLD_STAT.get_ptr_mut(&key) {
        (*stat).count += 1;
    } else {
        let now = bpf_ktime_get_ns();
        let stat = ColdStat {
            first_ts_ns: now,
            count: 1,
        };
        COLD_STAT.insert(&key, &stat, 0).ok();
    }
    Ok(0)
}
