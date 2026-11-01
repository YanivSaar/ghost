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
    CatchHit    = 10,
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

/// Per-TID in-flight futex wait: enter timestamp + user-space futex address.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FutexInflight {
    pub ts_ns: u64,
    pub uaddr: u64,
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

/// Capture-ring record: a syscall whose latency exceeded cfg.catch_above_ns.
/// Emitted by the `catch` lens programs on the CAPTURE ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CatchRecord {
    pub kind:     u8,    // EventKind::CatchHit = 10
    pub _pad:     [u8; 3],
    pub pid:      u32,   // tgid of the tracked process
    pub tid:      u32,   // thread that tripped the wire
    pub nr:       u32,   // syscall number
    pub ts_ns:    u64,   // exit timestamp (monotonic ns)
    pub delta_ns: u64,   // enter→exit elapsed
}

/// Ring-buffer record: an exec phase marker (used by `cold`).
/// `phase` encodes the stage reached since execve:
///   0 = execve-return, 1 = ld.so (first mmap of a .so),
///   2 = libc-ready    (first non-mmap/mprotect/brk syscall)
///   3 = first-syscall-batch end (reserved)
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ExecPhaseRecord {
    pub kind:  u8,     // EventKind::ExecPhase = 9
    pub phase: u8,
    pub _pad:  [u8; 2],
    pub pid:   u32,
    pub tid:   u32,
    pub _pad2: u32,
    pub ts_ns: u64,
    pub nr:    u32,    // syscall nr that caused the transition (0 for execve-return)
    pub _pad3: u32,
}

// ── userspace-only impls ─────────────────────────────────────────────────────

#[cfg(feature = "user")]
mod user_impls {
    use super::*;
    unsafe impl aya::Pod for TrackInfo {}
    unsafe impl aya::Pod for SyscallKey {}
    unsafe impl aya::Pod for SyscallStat {}
    unsafe impl aya::Pod for LockStat {}
    unsafe impl aya::Pod for FutexInflight {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for SchedSwitchRecord {}
    unsafe impl aya::Pod for ExitRecord {}
    unsafe impl aya::Pod for CatchRecord {}
    unsafe impl aya::Pod for ExecPhaseRecord {}
}
