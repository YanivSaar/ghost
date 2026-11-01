//! ghost BPF programs (no_std). Compiled to BPF bytecode by `bpf-linker` via
//! the userspace crate's build.rs and embedded in the final binary.
//!
//! Every program's first act is the PID_SET gate (ARCHITECTURE §5): read the
//! current PID, return immediately if it is not a tracked target.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, PerCpuArray, PerCpuHashMap, RingBuf},
};
use ghost_common::{ColdStat, Config, FutexInflight, LockStat, SyscallKey, SyscallStat, TrackInfo};

mod track;
mod watch;
mod lock;
mod catch;
mod cold;
mod irq;
mod startup;

// ---- maps (ARCHITECTURE §5) ------------------------------------------------

/// The filter gate: tracked PID -> metadata. Owned by userspace; grown in
/// kernel on fork in tree mode.
#[map]
static PID_SET: HashMap<u32, TrackInfo> = HashMap::with_max_entries(65_536, 0);

/// tid<<32 | nr -> enter timestamp. Per-CPU, lock-free.
#[map]
static INFLIGHT: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(16_384, 0);

/// Aggregated syscall stats. Per-CPU; userspace sums on read.
#[map]
static SYSCALL_STAT: PerCpuHashMap<SyscallKey, SyscallStat> =
    PerCpuHashMap::with_max_entries(16_384, 0);

/// futex address -> contention stats.
#[map]
static LOCK_STAT: HashMap<u64, LockStat> = HashMap::with_max_entries(16_384, 0);

/// tid -> (enter_ts, uaddr) for a pending FUTEX_WAIT. Per-CPU is wrong here
/// because the waiter blocks on one CPU and may be woken on another, so a
/// shared HashMap keyed by tid is the correct store.
#[map]
static FUTEX_INFLIGHT: HashMap<u32, FutexInflight> = HashMap::with_max_entries(16_384, 0);

/// catch lens: tid<<32 | nr -> enter timestamp. Per-CPU because a syscall
/// executes on the CPU it entered on and returns on the same CPU.
#[map]
static CATCH_INFLIGHT: PerCpuHashMap<u64, u64> = PerCpuHashMap::with_max_entries(16_384, 0);

/// cold lens: (pid<<32|nr) -> ColdStat. first_ts_ns is the earliest time this
/// (pid, nr) pair was observed since the program was attached; count rolls up
/// every enter afterward. Shared HashMap (not per-CPU) so first-observation
/// semantics are global across CPUs.
#[map]
static COLD_STAT: HashMap<u64, ColdStat> = HashMap::with_max_entries(16_384, 0);

/// cold lens: launch timestamp — written once by userspace right before it
/// resumes the stopped child, so the TUI can show "ms since launch". Index 0.
#[map]
static COLD_LAUNCH: Array<u64> = Array::with_max_entries(1, 0);

/// CPU -> IRQ handler entry timestamp (jitter mode).
#[map]
static IRQ_ENTER: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Detail event stream for watch/lock/jitter/cold (MPSC, ordered, drop-counted).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Dedicated capture ring for `catch` (wire) mode.
#[map]
static CAPTURE: RingBuf = RingBuf::with_byte_size(4 * 1024 * 1024, 0);

/// Runtime config, index 0.
#[map]
static CFG: Array<Config> = Array::with_max_entries(1, 0);

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF has no unwinding; this is unreachable after the verifier.
    loop {}
}
