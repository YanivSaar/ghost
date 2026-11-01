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
    FutexWait = 4,
    FutexWake = 5,
    IrqSpan = 6,
    Fork = 7,
    Exit = 8,
    ExecPhase = 9,
}

/// Per-tracked-PID metadata stored as the value of the PID_SET map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TrackInfo {
    /// Root PID of the tracked subtree (equals pid for a single-PID target).
    pub root: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallKey {
    pub pid: u32,
    pub nr: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SyscallStat {
    pub count: u64,
    pub total_ns: u64,
    pub max_ns: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LockStat {
    pub waits: u64,
    pub total_wait_ns: u64,
    pub max_wait_ns: u64,
    pub holder_tid: u32,
    pub max_queue: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SchedSwitch {
    pub pid: u32,
    pub tid: u32,
    pub ts: u64,
    pub next_comm: [u8; 16],
    /// 1 if the switch was involuntary (preemption), 0 otherwise.
    pub involuntary: u8,
}

/// Runtime knobs pushed into the CFG map so userspace can retune without a reload.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Only emit a detail event for a syscall slower than this (ns).
    pub event_threshold_ns: u64,
    /// `catch` trip threshold (ns); 0 disables.
    pub catch_above_ns: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self { event_threshold_ns: 1_000_000, catch_above_ns: 0 }
    }
}

// SAFETY: all fields are plain-old-data with no padding that matters across
// the boundary. On the userspace side (feature = "user") these also implement
// aya::Pod via the loader; kept out of this crate to avoid the dep here.
