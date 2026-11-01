//! The privilege-free /proc layer (ARCHITECTURE §7). Cheap core set every tick;
//! expensive sets (maps, full fd enumeration) lazily when their screen is live.
pub mod status;  // state, threads, VmRSS/VmSize, ctxt switches
pub mod stat;    // start-time (PID-reuse guard), utime/stime, last CPU
pub mod wchan;   // kernel symbol the task sleeps in
pub mod maps;    // VM regions / smaps_rollup
pub mod fds;     // open descriptors by type
pub mod net;     // sockets with connection state
pub mod io;      // cumulative read/write bytes
