//! .ghost on-disk format (ARCHITECTURE §8).
//!
//! Layout:
//!   [8]  magic "GHOST000"
//!   [4]  version (u32 le) = 1
//!   [4]  reserved = 0
//!   [8]  meta_len (u64 le)
//!   [*]  JSON metadata (pid, mode, start_ns, hostname, …)
//!   [*]  frames: each = [kind:u8][ts_delta:u32 le][len:u32 le][LZ4 body]
//!
//! Raw events, not aggregates — future views and `ghost diff` need full fidelity.

pub const MAGIC: &[u8; 8] = b"GHOST000";
pub const VERSION: u32     = 1;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMeta {
    pub pid:      u32,
    pub comm:     String,
    pub mode:     String,
    pub start_ns: u64,
    pub hostname: String,
}

impl SessionMeta {
    pub fn new(pid: u32, comm: impl Into<String>, mode: impl Into<String>) -> Self {
        let hostname = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string();
        let start_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        Self { pid, comm: comm.into(), mode: mode.into(), start_ns, hostname }
    }
}
