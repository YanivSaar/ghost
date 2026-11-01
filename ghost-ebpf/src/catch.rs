//! catch programs: latency tripwire on sys_enter/sys_exit.
//!
//! Mirrors the watch sys_enter/exit pair but uses its own CATCH_INFLIGHT map,
//! and on exit — when the elapsed time exceeds cfg.catch_above_ns — emits a
//! CatchRecord on the dedicated CAPTURE ring. The map keeps catch independent
//! of watch, so the two lenses can coexist (userspace attaches one at a time
//! today, but nothing in the kernel side prevents both).

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns},
    macros::tracepoint,
    programs::TracePointContext,
};
use ghost_common::{CatchRecord, EventKind};

use crate::{CAPTURE, CATCH_INFLIGHT, CFG, PID_SET};

// ── sys_enter ────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_enter_catch(ctx: TracePointContext) -> u32 {
    unsafe { try_enter(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_enter(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;
    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let tid = tgid_tid as u32;
    let nr: i64 = ctx.read_at(8)?;
    let ts = bpf_ktime_get_ns();
    let key: u64 = (tid as u64) << 32 | (nr as u64 & 0xffff_ffff);
    CATCH_INFLIGHT.insert(&key, &ts, 0).ok();
    Ok(0)
}

// ── sys_exit ─────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn sys_exit_catch(ctx: TracePointContext) -> u32 {
    unsafe { try_exit(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let tgid_tid = bpf_get_current_pid_tgid();
    let tgid = (tgid_tid >> 32) as u32;
    if PID_SET.get(&tgid).is_none() {
        return Ok(0);
    }

    let tid = tgid_tid as u32;
    let nr: i64 = ctx.read_at(8)?;
    let key: u64 = (tid as u64) << 32 | (nr as u64 & 0xffff_ffff);

    let Some(&enter_ts) = CATCH_INFLIGHT.get(&key) else {
        return Ok(0);
    };
    CATCH_INFLIGHT.remove(&key).ok();

    let now = bpf_ktime_get_ns();
    let delta = now.saturating_sub(enter_ts);

    // Threshold check: read current CFG[0]. 0 means "disabled".
    let threshold = match CFG.get(0) {
        Some(cfg) => cfg.catch_above_ns,
        None => 0,
    };
    if threshold == 0 || delta < threshold {
        return Ok(0);
    }

    let rec = CatchRecord {
        kind:     EventKind::CatchHit as u8,
        _pad:     [0; 3],
        pid:      tgid,
        tid,
        nr:       nr as u32,
        ts_ns:    now,
        delta_ns: delta,
    };

    if let Some(mut entry) = CAPTURE.reserve::<CatchRecord>(0) {
        core::ptr::write(entry.as_mut_ptr(), rec);
        entry.submit(0);
    }

    Ok(0)
}
