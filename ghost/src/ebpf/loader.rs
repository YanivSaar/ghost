//! eBPF load + attach (ARCHITECTURE §5).

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, PerCpuHashMap},
    programs::TracePoint,
    Ebpf,
};
use ghost_common::{Config, LockStat, SyscallKey, SyscallStat, TrackInfo};

static GHOST_EBPF_BYTES: &[u8] = include_bytes_aligned!(
    concat!(env!("OUT_DIR"), "/ghost")
);

pub struct GhostEbpf {
    pub ebpf: Ebpf,
}

impl GhostEbpf {
    pub fn load() -> Result<Self> {
        let ebpf = Ebpf::load(GHOST_EBPF_BYTES)
            .context("loading embedded BPF object — do you have CAP_BPF + CAP_PERFMON?")?;
        Ok(Self { ebpf })
    }

    pub fn track_pid(&mut self, pid: u32) -> Result<()> {
        let map = self.ebpf.map_mut("PID_SET")
            .ok_or_else(|| anyhow!("PID_SET map not found"))?;
        let mut pid_set: HashMap<_, u32, TrackInfo> = HashMap::try_from(map)?;
        pid_set.insert(pid, TrackInfo { root: pid }, 0)
            .context("inserting into PID_SET")
    }

    pub fn set_config(&mut self, cfg: Config) -> Result<()> {
        let map = self.ebpf.map_mut("CFG")
            .ok_or_else(|| anyhow!("CFG map not found"))?;
        let mut cfg_map: Array<_, Config> = Array::try_from(map)?;
        cfg_map.set(0, cfg, 0).context("writing CFG[0]")
    }

    pub fn attach_watch(&mut self) -> AttachResult {
        let mut res = AttachResult::default();
        res.sys_enter    = attach_tp(&mut self.ebpf, "sys_enter",         "raw_syscalls", "sys_enter");
        res.sys_exit     = attach_tp(&mut self.ebpf, "sys_exit",          "raw_syscalls", "sys_exit");
        res.sched_switch = attach_tp(&mut self.ebpf, "sched_switch",      "sched",        "sched_switch");
        res
    }

    pub fn attach_lock(&mut self) -> AttachResult {
        let mut res = AttachResult::default();
        res.futex_enter = attach_tp(&mut self.ebpf, "sys_enter_futex", "syscalls", "sys_enter_futex");
        res.futex_exit  = attach_tp(&mut self.ebpf, "sys_exit_futex",  "syscalls", "sys_exit_futex");
        res
    }

    pub fn attach_catch(&mut self) -> AttachResult {
        let mut res = AttachResult::default();
        res.catch_enter = attach_tp(&mut self.ebpf, "sys_enter_catch", "raw_syscalls", "sys_enter");
        res.catch_exit  = attach_tp(&mut self.ebpf, "sys_exit_catch",  "raw_syscalls", "sys_exit");
        res
    }

    pub fn attach_track(&mut self) -> AttachResult {
        let mut res = AttachResult::default();
        res.fork = attach_tp(&mut self.ebpf, "sched_process_fork", "sched", "sched_process_fork");
        res.exit = attach_tp(&mut self.ebpf, "sched_process_exit", "sched", "sched_process_exit");
        res
    }

    pub fn read_syscall_stats(&self) -> Vec<(SyscallKey, SyscallStat)> {
        let Some(map) = self.ebpf.map("SYSCALL_STAT") else { return vec![] };
        let Ok(per_cpu) = PerCpuHashMap::<_, SyscallKey, SyscallStat>::try_from(map) else {
            return vec![];
        };

        let mut out = Vec::new();
        for item in per_cpu.iter() {
            let Ok((key, cpus)) = item else { continue };
            let total = cpus.iter().fold(SyscallStat::default(), |acc, v| SyscallStat {
                count:    acc.count    + v.count,
                total_ns: acc.total_ns + v.total_ns,
                max_ns:   acc.max_ns.max(v.max_ns),
            });
            if total.count > 0 {
                out.push((key, total));
            }
        }
        out.sort_by(|a, b| b.1.total_ns.cmp(&a.1.total_ns));
        out
    }

    /// Read LOCK_STAT (keyed by user-space futex address). Sorted by
    /// total_wait_ns descending so the caller can take_N.
    pub fn read_lock_stats(&self) -> Vec<(u64, LockStat)> {
        let Some(map) = self.ebpf.map("LOCK_STAT") else { return vec![] };
        let Ok(h) = HashMap::<_, u64, LockStat>::try_from(map) else { return vec![] };

        let mut out: Vec<(u64, LockStat)> = h.iter().filter_map(|r| r.ok()).collect();
        out.sort_by(|a, b| b.1.total_wait_ns.cmp(&a.1.total_wait_ns));
        out
    }
}

fn attach_tp(ebpf: &mut Ebpf, fn_name: &str, category: &str, name: &str) -> Option<String> {
    let program: &mut TracePoint = match ebpf.program_mut(fn_name)
        .and_then(|p| p.try_into().ok())
    {
        Some(p) => p,
        None => return Some(format!("{fn_name}: program not found")),
    };
    if let Err(e) = program.load() {
        return Some(format!("{fn_name}: load failed: {e}"));
    }
    if let Err(e) = program.attach(category, name) {
        return Some(format!("{fn_name}: attach({category}/{name}) failed: {e}"));
    }
    None
}

#[derive(Default)]
pub struct AttachResult {
    pub sys_enter:    Option<String>,
    pub sys_exit:     Option<String>,
    pub sched_switch: Option<String>,
    pub fork:         Option<String>,
    pub exit:         Option<String>,
    pub futex_enter:  Option<String>,
    pub futex_exit:   Option<String>,
    pub catch_enter:  Option<String>,
    pub catch_exit:   Option<String>,
}

impl AttachResult {
    pub fn errors(&self) -> Vec<&str> {
        [
            &self.sys_enter, &self.sys_exit, &self.sched_switch,
            &self.fork, &self.exit,
            &self.futex_enter, &self.futex_exit,
            &self.catch_enter, &self.catch_exit,
        ].iter().filter_map(|e| e.as_deref()).collect()
    }
}
