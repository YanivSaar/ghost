//! Wire types shared across the kernel/user boundary.
//!
//! Every type here is `#[repr(C)]` with a fixed, documented layout so the
//! userspace consumer can cast a ring-buffer byte slice directly to a typed
//! reference with zero deserialization (see ARCHITECTURE §6, §12).
#![cfg_attr(not(feature = "user"), no_std)]

/// Discriminant tag; the first byte of every ring-buffer record.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    SyscallExit = 1,
    SchedSwitch = 2,
    SchedWakeup = 3,
    FutexWait   = 4,
    FutexWake   = 5,
    IrqSpan     = 6,
    Fork        = 7,
    Exit        = 8,
    ExecPhase   = 9,
}

/// Per-tracked-PID metadata stored as the value of the PID_SET map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrackInfo {
    pub root: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SyscallKey {
    pub pid: u32,
    pub nr:  u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallStat {
    pub count:    u64,
    pub total_ns: u64,
    pub max_ns:   u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LockStat {
    pub waits:         u64,
    pub total_wait_ns: u64,
    pub max_wait_ns:   u64,
    pub holder_tid:    u32,
    pub max_queue:     u32,
}

/// Runtime knobs pushed into the CFG map so userspace can retune without a reload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub event_threshold_ns: u64,
    pub catch_above_ns:     u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { event_threshold_ns: 1_000_000, catch_above_ns: 0 }
    }
}

/// Ring-buffer record: sched_switch event (kind = SchedSwitch = 2).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SchedSwitchRecord {
    pub kind:        u8,    // EventKind::SchedSwitch
    pub involuntary: u8,    // 1 = preempted (prev_state == 0), 0 = voluntary
    pub _pad:        [u8; 2],
    pub pid:         u32,   // tgid of the tracked process
    pub tid:         u32,   // tid that was switched out
    pub _pad2:       u32,
    pub ts_ns:       u64,
    pub next_pid:    u32,
    pub _pad3:       u32,
    pub next_comm:   [u8; 16],
}

/// Ring-buffer record: process exit (kind = Exit = 8).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExitRecord {
    pub kind: u8,    // EventKind::Exit
    pub _pad:  [u8; 3],
    pub pid:  u32,
}

// ── userspace-only impls ─────────────────────────────────────────────────────

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for TrackInfo {}
    unsafe impl aya::Pod for SyscallKey {}
    unsafe impl aya::Pod for SyscallStat {}
    unsafe impl aya::Pod for LockStat {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for SchedSwitchRecord {}
    unsafe impl aya::Pod for ExitRecord {}
}
