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
pub const VERSION: u32 = 1;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionMeta {
    pub pid: u32,
    pub comm: String,
    pub mode: String,
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
        Self {
            pid,
            comm: comm.into(),
            mode: mode.into(),
            start_ns,
            hostname,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_fields_populated() {
        let m = SessionMeta::new(42, "myproc", "watch");
        assert_eq!(m.pid, 42);
        assert_eq!(m.comm, "myproc");
        assert_eq!(m.mode, "watch");
        assert!(m.start_ns > 0);
        // hostname should be set (non-empty on any real system).
        assert!(!m.hostname.is_empty());
    }

    #[test]
    fn meta_serialises_and_deserialises() {
        let m = SessionMeta::new(99, "test", "snap");
        let json = serde_json::to_vec(&m).unwrap();
        let m2: SessionMeta = serde_json::from_slice(&json).unwrap();
        assert_eq!(m2.pid, m.pid);
        assert_eq!(m2.comm, m.comm);
        assert_eq!(m2.mode, m.mode);
        assert_eq!(m2.start_ns, m.start_ns);
    }

    #[test]
    fn magic_and_version_constants() {
        assert_eq!(MAGIC, b"GHOST000");
        assert_eq!(VERSION, 1);
    }
}
