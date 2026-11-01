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

pub(crate) fn parse(raw: &str) -> Status {
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

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
Name:\tnginx
Uid:\t1000\t1001\t1001\t1001
Gid:\t2000\t2001\t2001\t2001
Threads:\t4
VmPeak:\t 51200 kB
VmSize:\t 40960 kB
VmRSS:\t  8192 kB
VmSwap:\t   512 kB
VmExe:\t  1024 kB
VmLib:\t  4096 kB
voluntary_ctxt_switches:\t150
nonvoluntary_ctxt_switches:\t20
SigPnd:\t0000000000000000
SigBlk:\t0000000000010000
SigIgn:\t0000000000001000
SigCgt:\t0000000180005202
NoNewPrivs:\t1
Seccomp:\t2
";

    #[test]
    fn parses_all_fields() {
        let s = parse(SAMPLE);
        assert_eq!(s.name,                     "nginx");
        assert_eq!(s.uid_real,                 1000);
        assert_eq!(s.uid_effective,            1001);
        assert_eq!(s.gid_real,                 2000);
        assert_eq!(s.gid_effective,            2001);
        assert_eq!(s.threads,                  4);
        assert_eq!(s.vm_peak_kb,               51200);
        assert_eq!(s.vm_size_kb,               40960);
        assert_eq!(s.vm_rss_kb,                8192);
        assert_eq!(s.vm_swap_kb,               512);
        assert_eq!(s.vm_exe_kb,                1024);
        assert_eq!(s.vm_lib_kb,                4096);
        assert_eq!(s.voluntary_ctxt_switches,  150);
        assert_eq!(s.nonvoluntary_ctxt_switches, 20);
        assert_eq!(s.sig_pending,              "0000000000000000");
        assert_eq!(s.sig_blocked,              "0000000000010000");
        assert!(s.no_new_privs);
        assert_eq!(s.seccomp,                  2);
    }

    #[test]
    fn empty_input_returns_default() {
        let s = parse("");
        assert_eq!(s.name, "");
        assert_eq!(s.threads, 0);
        assert_eq!(s.vm_rss_kb, 0);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let s = parse("FutureKey:\tsome value\nName:\tmyproc\n");
        assert_eq!(s.name, "myproc");
    }

    #[test]
    fn parse_kb_handles_unit_suffix() {
        // "1024 kB" → 1024
        assert_eq!(parse_kb("1024 kB"), 1024);
        // plain number
        assert_eq!(parse_kb("512"), 512);
        // zero
        assert_eq!(parse_kb("0 kB"), 0);
    }

    #[test]
    fn read_current_process() {
        let pid = std::process::id();
        let s = Status::read(pid).expect("read own /proc/status");
        assert!(!s.name.is_empty());
        assert!(s.threads >= 1);
        assert!(s.vm_rss_kb > 0);
    }
}
