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
        })
    }
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
