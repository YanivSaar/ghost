//! Single-PID target. Seeds PID_SET with one entry.
//! PID-reuse guard: compare start_time from /proc/{pid}/stat on each liveness check.

use anyhow::Result;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_self_succeeds() {
        let pid = std::process::id();
        let target = PidTarget::attach(pid).expect("attach to self should succeed");
        assert_eq!(target.pid, pid);
        assert!(target.start_time > 0, "start_time should be non-zero");
    }

    #[test]
    fn is_alive_self_returns_true() {
        let pid = std::process::id();
        let target = PidTarget::attach(pid).unwrap();
        assert!(target.is_alive(), "current process should be alive");
    }

    #[test]
    fn is_alive_wrong_start_time_returns_false() {
        let pid = std::process::id();
        let target = PidTarget { pid, start_time: 0 };
        // start_time=0 never matches a real process's start_time.
        assert!(!target.is_alive(), "mismatched start_time should return false");
    }

    #[test]
    fn attach_nonexistent_pid_fails() {
        // PID 0 is the idle process and has no /proc/0/stat on Linux.
        let result = PidTarget::attach(0);
        assert!(result.is_err(), "attaching to pid 0 should fail");
    }
}
