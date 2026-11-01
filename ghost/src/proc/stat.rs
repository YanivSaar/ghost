//! /proc/{pid}/stat reader.
//!
//! Fields are space-separated, but the comm field (2) is wrapped in parens and
//! may contain spaces and parens itself — we strip the outer parens first, then
//! parse the remaining fixed-position fields relative to the end of comm.

use anyhow::{Context, Result};
use std::fs;

#[derive(Debug, Clone)]
pub struct Stat {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    pub pgrp: u32,
    pub session: u32,
    pub utime_ticks: u64,
    pub stime_ticks: u64,
    pub num_threads: u32,
    pub start_time: u64,
    pub vsize_bytes: u64,
    pub rss_pages: i64,
    pub last_cpu: u32,
    pub priority: i32,
    pub nice: i32,
}

impl Stat {
    pub fn read(pid: u32) -> Result<Self> {
        let raw = fs::read_to_string(format!("/proc/{pid}/stat"))
            .with_context(|| format!("reading /proc/{pid}/stat"))?;
        parse(&raw).with_context(|| format!("parsing /proc/{pid}/stat"))
    }
}

fn parse(raw: &str) -> Result<Stat> {
    let raw = raw.trim_end();

    // The comm field is the last `(…)` block before the state letter.
    // Find the last ')' to correctly handle comms that contain '(' or ')'.
    let comm_start = raw.find('(').context("no '(' in stat")?;
    let comm_end = raw.rfind(')').context("no ')' in stat")?;

    let pid: u32 = raw[..comm_start]
        .trim()
        .parse()
        .context("pid field")?;
    let comm = raw[comm_start + 1..comm_end].to_string();

    // Everything after ')' is space-delimited; field indices restart at 0 == state.
    let rest = &raw[comm_end + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    let f = |i: usize, name: &'static str| -> Result<&str> {
        fields.get(i).copied().with_context(|| format!("stat field {name} missing"))
    };

    let state = f(0, "state")?.chars().next().unwrap_or('?');
    let ppid: u32 = f(1, "ppid")?.parse().context("ppid")?;
    let pgrp: u32 = f(2, "pgrp")?.parse().context("pgrp")?;
    let session: u32 = f(3, "session")?.parse().context("session")?;
    let utime_ticks: u64 = f(11, "utime")?.parse().context("utime")?;
    let stime_ticks: u64 = f(12, "stime")?.parse().context("stime")?;
    let num_threads: u32 = f(17, "num_threads")?.parse().context("num_threads")?;
    let start_time: u64 = f(19, "starttime")?.parse().context("starttime")?;
    let vsize_bytes: u64 = f(20, "vsize")?.parse().context("vsize")?;
    let rss_pages: i64 = f(21, "rss")?.parse().context("rss")?;
    let priority: i32 = f(15, "priority")?.parse().context("priority")?;
    let nice: i32 = f(16, "nice")?.parse().context("nice")?;
    let last_cpu: u32 = f(36, "processor")?.parse().context("processor")?;

    Ok(Stat {
        pid,
        comm,
        state,
        ppid,
        pgrp,
        session,
        utime_ticks,
        stime_ticks,
        num_threads,
        start_time,
        vsize_bytes,
        rss_pages,
        last_cpu,
        priority,
        nice,
    })
}

/// CPU ticks → seconds using the configured clock tick rate.
pub fn ticks_to_secs(ticks: u64) -> f64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz <= 0 { 100 } else { hz as u64 };
    ticks as f64 / hz as f64
}
