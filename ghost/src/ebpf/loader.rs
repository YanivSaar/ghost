//! CO-RE load against the running kernel's BTF; populate CFG + PID_SET; attach
//! only the probes the active modes need. Incremental + fallible per-program:
//! a failed attach disables one lens, never the whole session (§5, §14). TODO.
