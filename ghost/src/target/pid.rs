//! Single-PID target. Seeds PID_SET with one entry.
//! PID-reuse guard: compare start_time from /proc/{pid}/stat on each liveness check.

use anyhow::{bail, Result};
use crate::proc::stat::Stat;

pub struct PidTarget {
    pub pid:        u32,
    pub start_time: u64,   // from /proc/{pid}/stat; guards against PID reuse
}

impl PidTarget {
    pub fn attach(pid: u32) -> Result<Self> {
        let stat = Stat::read(pid)?;
        Ok(Self { pid, start_time: stat.start_time })
    }

    pub fn is_alive(&self) -> bool {
        Stat::read(self.pid)
            .map(|s| s.start_time == self.start_time)
            .unwrap_or(false)
    }
}
