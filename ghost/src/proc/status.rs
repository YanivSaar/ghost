//! /proc/{pid}/status reader — key:\tvalue pairs, one per line.

use anyhow::{Context, Result};
use std::fs;

#[derive(Debug, Clone, Default)]
pub struct Status {
    pub name: String,
    pub uid_real: u32,
    pub uid_effective: u32,
    pub gid_real: u32,
    pub gid_effective: u32,
    pub vm_peak_kb: u64,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub vm_swap_kb: u64,
    pub vm_exe_kb: u64,
    pub vm_lib_kb: u64,
    pub voluntary_ctxt_switches: u64,
    pub nonvoluntary_ctxt_switches: u64,
    pub threads: u32,
    pub sig_pending: String,
    pub sig_blocked: String,
    pub sig_ignored: String,
    pub sig_caught: String,
    pub no_new_privs: bool,
    pub seccomp: u8,
}

impl Status {
    pub fn read(pid: u32) -> Result<Self> {
        let raw = fs::read_to_string(format!("/proc/{pid}/status"))
            .with_context(|| format!("reading /proc/{pid}/status"))?;
        Ok(parse(&raw))
    }
}

fn parse(raw: &str) -> Status {
    let mut s = Status::default();
    for line in raw.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let val = val.trim();
        match key {
            "Name"               => s.name = val.to_string(),
            "Threads"            => s.threads = val.parse().unwrap_or(0),
            "VmPeak"             => s.vm_peak_kb = parse_kb(val),
            "VmSize"             => s.vm_size_kb = parse_kb(val),
            "VmRSS"              => s.vm_rss_kb = parse_kb(val),
            "VmSwap"             => s.vm_swap_kb = parse_kb(val),
            "VmExe"              => s.vm_exe_kb = parse_kb(val),
            "VmLib"              => s.vm_lib_kb = parse_kb(val),
            "voluntary_ctxt_switches"    => s.voluntary_ctxt_switches = val.parse().unwrap_or(0),
            "nonvoluntary_ctxt_switches" => s.nonvoluntary_ctxt_switches = val.parse().unwrap_or(0),
            "SigPnd"             => s.sig_pending = val.to_string(),
            "SigBlk"             => s.sig_blocked = val.to_string(),
            "SigIgn"             => s.sig_ignored = val.to_string(),
            "SigCgt"             => s.sig_caught = val.to_string(),
            "NoNewPrivs"         => s.no_new_privs = val == "1",
            "Seccomp"            => s.seccomp = val.parse().unwrap_or(0),
            "Uid" => {
                let mut parts = val.split_whitespace();
                s.uid_real     = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                s.uid_effective = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            "Gid" => {
                let mut parts = val.split_whitespace();
                s.gid_real     = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                s.gid_effective = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
            }
            _ => {}
        }
    }
    s
}

fn parse_kb(val: &str) -> u64 {
    val.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0)
}
