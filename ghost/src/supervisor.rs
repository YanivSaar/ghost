//! Thread lifecycle: load+attach eBPF, spawn the /proc poller, eBPF consumer,
//! session writer, and TUI render loop; handle signals; tear down cleanly
//! (ARCHITECTURE §3). TODO(phase 0/2).
