//! ghost-ebpf: `track` programs. See ARCHITECTURE §5 / §9 for the attach points
//! and the data each program records.
//!
//! TODO(phase): implement the track programs. Each must begin with the PID_SET
//! gate and keep within the verifier's loop/stack/instruction limits.
