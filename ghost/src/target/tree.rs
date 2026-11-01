//! Process-tree target. In-kernel sched_process_fork propagates PID_SET
//! membership to future children (see ghost-ebpf/src/track.rs). At attach
//! time we also walk /proc once so that any *existing* descendants of the
//! root are tracked from the first event.

use std::fs;
use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};

use crate::proc::stat::Stat;

pub struct TreeTarget {
    pub root:    u32,
    pub members: Vec<u32>,
}

impl TreeTarget {
    /// Resolve `root` into the set of currently-live PIDs in its subtree,
    /// inclusive of `root` itself. Order is BFS, parents before children.
    /// Short-lived children are tolerated: a missing stat file just means
    /// that pid vanished between enumeration and read, and we skip it.
    pub fn attach(root: u32) -> Result<Self> {
        // Verify root exists.
        Stat::read(root).context("ghost tree: root pid")?;

        let (parent_of, _comm_of) = scan_proc()?;

        // Build children index.
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        for (pid, ppid) in &parent_of {
            children.entry(*ppid).or_default().push(*pid);
        }

        let mut seen: HashSet<u32> = HashSet::new();
        let mut order: Vec<u32>    = Vec::new();
        let mut q: VecDeque<u32>   = VecDeque::new();
        q.push_back(root);

        while let Some(pid) = q.pop_front() {
            if !seen.insert(pid) { continue; }
            order.push(pid);
            if let Some(kids) = children.get(&pid) {
                for &k in kids { q.push_back(k); }
            }
        }

        Ok(Self { root, members: order })
    }
}

/// Walk /proc once, returning (pid -> ppid). Threads (/proc/N/task/*)
/// are not enumerated — PID_SET is keyed by tgid, and the kernel fork
/// tracepoint fires on tgid granularity.
fn scan_proc() -> Result<(HashMap<u32, u32>, HashMap<u32, String>)> {
    let mut parent_of: HashMap<u32, u32> = HashMap::new();
    let mut comm_of:   HashMap<u32, String> = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(name)  = entry.file_name().into_string() else { continue };
        let Ok(pid)   = name.parse::<u32>() else { continue };
        let Ok(stat)  = Stat::read(pid) else { continue };
        parent_of.insert(pid, stat.ppid);
        comm_of.insert(pid, stat.comm);
    }
    Ok((parent_of, comm_of))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attach_self_includes_self() {
        let me = std::process::id();
        let t = TreeTarget::attach(me).unwrap();
        assert_eq!(t.root, me);
        assert!(t.members.contains(&me));
        // Root comes first in BFS order.
        assert_eq!(t.members[0], me);
    }

    #[test]
    fn attach_bad_pid_fails() {
        assert!(TreeTarget::attach(0).is_err() || TreeTarget::attach(u32::MAX).is_err());
    }
}
