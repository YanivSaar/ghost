//! ghost-ebpf: `startup` programs. See ARCHITECTURE §5 / §9 for the attach points
//! and the data each program records.
//!
//! TODO(phase): implement the startup programs. Each must begin with the PID_SET
//! gate and keep within the verifier's loop/stack/instruction limits.
