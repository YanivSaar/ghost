//! watch programs: sys_enter/exit timing + sched_switch events.
//!
//! Tracepoint offsets verified against /sys/kernel/debug/tracing/events/:
//!   raw_syscalls/sys_enter: id @ offset 8 (i64)
//!   raw_syscalls/sys_exit:  id @ offset 8 (i64)
//!   sched/sched_switch:     prev_pid @ 24, prev_state @ 32, next_comm @ 40, next_pid @ 56

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use ghost_common::{SchedSwitchRecord, SyscallKey, SyscallStat};

use crate::{EVENTS, INFLIGHT, PID_SET, SYSCALL_STAT};

// ── sys_enter ────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_enter(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_sys_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;

    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let tid = tgid_tid as u32;
    let nr: i64 = ctx.read_at(8)?;
    let ts = bpf_ktime_get_ns();

    let key: u64 = (tid as u64) << 32 | (nr as u64 & 0xffff_ffff);
    INFLIGHT.insert(&key, &ts, 0).ok();
    Ok(0)
}

// ── sys_exit ─────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_sys_exit(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_sys_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;

    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let tid = tgid_tid as u32;
    let nr: i64 = ctx.read_at(8)?;
    let key: u64 = (tid as u64) << 32 | (nr as u64 & 0xffff_ffff);

    let Some(&enter_ts) = INFLIGHT.get(&key) else {
        return Ok(0);
    };
    INFLIGHT.remove(&key).ok();

    let now = bpf_ktime_get_ns();
    let delta = now.saturating_sub(enter_ts);

    let skey = SyscallKey { pid: tgid, nr: nr as u32 };

    if let Some(stat) = SYSCALL_STAT.get_ptr_mut(&skey) {
        (*stat).count    += 1;
        (*stat).total_ns += delta;
        if delta > (*stat).max_ns { (*stat).max_ns = delta; }
    } else {
        let stat = SyscallStat { count: 1, total_ns: delta, max_ns: delta };
        SYSCALL_STAT.insert(&skey, &stat, 0).ok();
    }

    Ok(0)
}

// ── sched_switch ─────────────────────────────────────────────────────────────

#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    unsafe { try_sched_switch(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_sched_switch(ctx: TracePointContext) -> Result<u32, i64> {
    let prev_pid: u32 = ctx.read_at(24)?;

    if PID_SET.get(&prev_pid).is_none() {
        return Ok(0);
    }

    let prev_state: i64 = ctx.read_at(32)?;
    let next_pid: u32   = ctx.read_at(56)?;
    let next_comm: [u8; 16] = ctx.read_at(40)?;
    let ts = bpf_ktime_get_ns();

    // prev_state == 0 means TASK_RUNNING → preempted (involuntary).
    let involuntary: u8 = if prev_state == 0 { 1 } else { 0 };

    // We're on the CPU that did the switch; tid == prev_pid here.
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;
    let tid  = tgid_tid as u32;

    let rec = SchedSwitchRecord {
        kind: 2,  // EventKind::SchedSwitch
        involuntary,
        _pad:  [0; 2],
        pid:   tgid,
        tid,
        _pad2: 0,
        ts_ns: ts,
        next_pid,
        _pad3: 0,
        next_comm,
    };

    if let Some(mut entry) = EVENTS.reserve::<SchedSwitchRecord>(0) {
        core::ptr::write(entry.as_mut_ptr(), rec);
        entry.submit(0);
    }

    Ok(0)
}
