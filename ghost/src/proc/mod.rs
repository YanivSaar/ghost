//! The privilege-free /proc layer (ARCHITECTURE §7). Cheap core set every tick;
//! expensive sets (maps, full fd enumeration) lazily when their screen is live.
pub mod fds;
pub mod io;
pub mod maps;
pub mod net;
pub mod stat;
pub mod status;
pub mod wchan;

use anyhow::Result;

/// All /proc data collected in a single snapshot pass.
#[derive(Debug)]
pub struct ProcSnapshot {
    pub stat: stat::Stat,
    pub status: status::Status,
    pub wchan: String,
    pub io: io::Io,
    pub fds: fds::FdSummary,
    pub maps: Vec<maps::MapRegion>,
    pub smaps: Option<maps::SmasRollup>,
    pub sockets: Vec<net::SocketEntry>,
    pub cmdline: String,
    pub exe: String,
    pub cwd: String,
    /// /proc/<pid>/oom_score as an unsigned integer; 0 if the file is
    /// missing (unprivileged container, kernel too old, …).
    pub oom_score: u32,
    /// /proc/<pid>/schedstat → (run_ns, wait_ns, pcount); all zero when
    /// CONFIG_SCHEDSTATS is off or the file is missing.
    pub sched_run_ns: u64,
    pub sched_wait_ns: u64,
    pub sched_pcount: u64,
}

impl ProcSnapshot {
    pub fn collect(pid: u32) -> Result<Self> {
        let stat = stat::Stat::read(pid)?;
        let status = status::Status::read(pid)?;
        let wchan = wchan::read(pid).unwrap_or_else(|_| "?".into());
        let io = io::Io::read(pid).unwrap_or_default();
        let fds = fds::read(pid).unwrap_or_default();
        let maps = maps::read_maps(pid).unwrap_or_default();
        let smaps = maps::read_smaps_rollup(pid);
        let sockets = net::read(pid).unwrap_or_default();
        let cmdline = read_cmdline(pid);
        let exe = read_link(pid, "exe");
        let cwd = read_link(pid, "cwd");
        let oom_score = read_oom_score(pid);
        let (sched_run_ns, sched_wait_ns, sched_pcount) = read_schedstat(pid);

        Ok(ProcSnapshot {
            stat,
            status,
            wchan,
            io,
            fds,
            maps,
            smaps,
            sockets,
            cmdline,
            exe,
            cwd,
            oom_score,
            sched_run_ns,
            sched_wait_ns,
            sched_pcount,
        })
    }
}

/// /proc/<pid>/oom_score as a u32. Returns 0 on any error so the field
/// is always safe to read; a real score of 0 is possible and benign.
fn read_oom_score(pid: u32) -> u32 {
    std::fs::read_to_string(format!("/proc/{pid}/oom_score"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// /proc/<pid>/schedstat: three whitespace-separated integers:
///   run_ns  wait_ns  pcount
/// Zeros when CONFIG_SCHEDSTATS=off or the file is missing.
fn read_schedstat(pid: u32) -> (u64, u64, u64) {
    let text = std::fs::read_to_string(format!("/proc/{pid}/schedstat")).unwrap_or_default();
    let mut it = text.split_whitespace();
    let a = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let b = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    let c = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    (a, b, c)
}

fn read_cmdline(pid: u32) -> String {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| {
            b.split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn read_link(pid: u32, name: &str) -> String {
    std::fs::read_link(format!("/proc/{pid}/{name}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_against_self_succeeds() {
        let pid = std::process::id();
        let snap = ProcSnapshot::collect(pid).expect("ProcSnapshot::collect on self");
        assert_eq!(snap.stat.pid, pid, "stat.pid mismatch");
        assert!(!snap.status.name.is_empty(), "status.name should be set");
    }

    #[test]
    fn collect_against_nonexistent_pid_errors() {
        // PID 1<<30 is almost certainly not a live process on any realistic host.
        let r = ProcSnapshot::collect(1 << 30);
        assert!(r.is_err(), "collect on dead pid must error");
    }

    #[test]
    fn read_cmdline_self_nonempty() {
        let s = read_cmdline(std::process::id());
        assert!(
            !s.is_empty(),
            "self cmdline must be non-empty under cargo test"
        );
    }

    #[test]
    fn read_link_question_mark_on_missing() {
        // PID 0 has no /proc entry.
        assert_eq!(read_link(0, "cwd"), "?");
    }
}
