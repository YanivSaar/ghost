//! jitter programs: IRQ / softirq attribution.
//!
//! Attribution model: the target process is the one being jittered, so we
//! only count IRQ / softirq time that fires on the CPU the target is
//! currently running on. We track that state with a per-CPU u8 flag
//! TARGET_ON_CPU, maintained by jitter_sched_switch.
//!
//! Tracepoint offsets verified against /sys/kernel/debug/tracing/events/:
//!   irq/irq_handler_entry: irq @ 8 (int)
//!   irq/irq_handler_exit:  irq @ 8 (int)
//!   irq/softirq_entry:     vec @ 8 (uint)
//!   irq/softirq_exit:      vec @ 8 (uint)
//!   sched/sched_switch:    prev_pid @ 24, next_pid @ 56 (same as watch)

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::tracepoint,
    programs::TracePointContext,
};
use ghost_common::IrqStat;

use crate::{IRQ_INFLIGHT, IRQ_STAT, PID_SET, SOFTIRQ_INFLIGHT, SOFTIRQ_STAT, TARGET_ON_CPU};

// ── sched_switch: toggle TARGET_ON_CPU ───────────────────────────────────────

#[tracepoint]
pub fn jitter_sched_switch(ctx: TracePointContext) -> u32 {
    unsafe { try_switch(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_switch(ctx: TracePointContext) -> Result<u32, i64> {
    let prev_pid: u32 = ctx.read_at(24)?;
    let next_pid: u32 = ctx.read_at(56)?;

    let next_tracked: u8 = if PID_SET.get(&next_pid).is_some() { 1 } else { 0 };
    let prev_tracked: u8 = if PID_SET.get(&prev_pid).is_some() { 1 } else { 0 };

    // Only touch the flag when the on-cpu state actually changes.
    if next_tracked == prev_tracked { return Ok(0); }

    if let Some(flag) = TARGET_ON_CPU.get_ptr_mut(0) {
        *flag = next_tracked;
    }
    Ok(0)
}

// ── hardirq ──────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn jitter_irq_entry(ctx: TracePointContext) -> u32 {
    unsafe { try_irq_entry(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_irq_entry(_ctx: TracePointContext) -> Result<u32, i64> {
    let on = TARGET_ON_CPU.get(0).map(|v| *v).unwrap_or(0);
    if on == 0 { return Ok(0); }

    let ts = bpf_ktime_get_ns();
    if let Some(slot) = IRQ_INFLIGHT.get_ptr_mut(0) {
        *slot = ts;
    }
    Ok(0)
}

#[tracepoint]
pub fn jitter_irq_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_irq_exit(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_irq_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let on = TARGET_ON_CPU.get(0).map(|v| *v).unwrap_or(0);
    if on == 0 { return Ok(0); }

    let entry = IRQ_INFLIGHT.get(0).map(|v| *v).unwrap_or(0);
    if entry == 0 { return Ok(0); }

    let irq_nr: i32 = ctx.read_at(8)?;
    let now = bpf_ktime_get_ns();
    let delta = now.saturating_sub(entry);

    let key = irq_nr as u32;
    upsert(&IRQ_STAT, key, delta);

    if let Some(slot) = IRQ_INFLIGHT.get_ptr_mut(0) { *slot = 0; }
    Ok(0)
}

// ── softirq ──────────────────────────────────────────────────────────────────

#[tracepoint]
pub fn jitter_softirq_entry(ctx: TracePointContext) -> u32 {
    unsafe { try_softirq_entry(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_softirq_entry(_ctx: TracePointContext) -> Result<u32, i64> {
    let on = TARGET_ON_CPU.get(0).map(|v| *v).unwrap_or(0);
    if on == 0 { return Ok(0); }
    let ts = bpf_ktime_get_ns();
    if let Some(slot) = SOFTIRQ_INFLIGHT.get_ptr_mut(0) {
        *slot = ts;
    }
    Ok(0)
}

#[tracepoint]
pub fn jitter_softirq_exit(ctx: TracePointContext) -> u32 {
    unsafe { try_softirq_exit(ctx) }.unwrap_or(0) as u32
}

unsafe fn try_softirq_exit(ctx: TracePointContext) -> Result<u32, i64> {
    let on = TARGET_ON_CPU.get(0).map(|v| *v).unwrap_or(0);
    if on == 0 { return Ok(0); }

    let entry = SOFTIRQ_INFLIGHT.get(0).map(|v| *v).unwrap_or(0);
    if entry == 0 { return Ok(0); }

    let vec_nr: u32 = ctx.read_at(8)?;
    let now = bpf_ktime_get_ns();
    let delta = now.saturating_sub(entry);

    upsert(&SOFTIRQ_STAT, vec_nr, delta);

    if let Some(slot) = SOFTIRQ_INFLIGHT.get_ptr_mut(0) { *slot = 0; }
    Ok(0)
}

// ── shared upsert ────────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn upsert(map: &aya_ebpf::maps::HashMap<u32, IrqStat>, key: u32, delta: u64) {
    if let Some(s) = map.get_ptr_mut(&key) {
        (*s).count    += 1;
        (*s).total_ns += delta;
        if delta > (*s).max_ns { (*s).max_ns = delta; }
    } else {
        let s = IrqStat { count: 1, total_ns: delta, max_ns: delta };
        map.insert(&key, &s, 0).ok();
    }
}
