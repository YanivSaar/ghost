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

pub(crate) fn parse(raw: &str) -> Result<Stat> {
    let raw = raw.trim_end();

    // The comm field is the last `(…)` block before the state letter.
    // Find the last ')' to correctly handle comms that contain '(' or ')'.
    let comm_start = raw.find('(').context("no '(' in stat")?;
    let comm_end = raw.rfind(')').context("no ')' in stat")?;

    let pid: u32 = raw[..comm_start].trim().parse().context("pid field")?;
    let comm = raw[comm_start + 1..comm_end].to_string();

    // Everything after ')' is space-delimited; field indices restart at 0 == state.
    let rest = &raw[comm_end + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();

    let f = |i: usize, name: &'static str| -> Result<&str> {
        fields
            .get(i)
            .copied()
            .with_context(|| format!("stat field {name} missing"))
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
pub fn ticks_to_secs(ticks: u64) -> f64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let hz = if hz <= 0 { 100 } else { hz as u64 };
    ticks as f64 / hz as f64
}

/// CPU ticks → seconds using the configured clock tick rate.
// ── tests ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;

    // A realistic /proc/{pid}/stat line (52 fields, all common values)
    const SAMPLE: &str = "1234 (my-proc) S 1000 1234 1234 0 -1 4194304 \
        100 200 0 0 50 30 0 0 20 0 4 0 12345678 5242880 1280 \
        18446744073709551615 94000 95000 140000 0 0 0 0 0 0 0 0 0 17 2 0 \
        0 0 0 94100 94200 95000 140001 140002 140002 140003 0";

    #[test]
    fn parses_all_fields() {
        let s = parse(SAMPLE).unwrap();
        assert_eq!(s.pid, 1234);
        assert_eq!(s.comm, "my-proc");
        assert_eq!(s.state, 'S');
        assert_eq!(s.ppid, 1000);
        assert_eq!(s.pgrp, 1234);
        assert_eq!(s.session, 1234);
        assert_eq!(s.utime_ticks, 50);
        assert_eq!(s.stime_ticks, 30);
        assert_eq!(s.priority, 20);
        assert_eq!(s.nice, 0);
        assert_eq!(s.num_threads, 4);
        assert_eq!(s.start_time, 12345678);
        assert_eq!(s.vsize_bytes, 5242880);
        assert_eq!(s.rss_pages, 1280);
        assert_eq!(s.last_cpu, 2);
    }

    #[test]
    fn comm_with_spaces_and_parens() {
        // comm = "(kworker/u:1)" — contains parens; rfind must strip correctly
        let line = "42 ((kworker/u:1)) R 1 42 42 0 -1 4194304 \
            0 0 0 0 0 0 0 0 20 0 1 0 100 0 0 \
            18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 3 0 0 \
            0 0 0 0 0 0 0 0 0";
        let s = parse(line).unwrap();
        assert_eq!(s.pid, 42);
        assert_eq!(s.comm, "(kworker/u:1)");
        assert_eq!(s.state, 'R');
    }

    #[test]
    fn comm_with_internal_spaces() {
        let line = "99 (my proc name) D 0 99 99 0 -1 4194304 \
            0 0 0 0 10 5 0 0 20 0 1 0 999 4096 1 \
            18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 \
            0 0 0 0 0 0 0 0 0";
        let s = parse(line).unwrap();
        assert_eq!(s.comm, "my proc name");
        assert_eq!(s.state, 'D');
    }

    #[test]
    fn all_state_chars_parsed() {
        for (ch, _) in [
            ('R', "running"),
            ('S', "sleeping"),
            ('D', "disk-wait"),
            ('Z', "zombie"),
            ('T', "stopped"),
            ('I', "idle"),
        ] {
            let line = format!(
                "1 (x) {ch} 0 1 1 0 -1 4194304 \
                0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 \
                18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 \
                0 0 0 0 0 0 0 0 0"
            );
            let s = parse(&line).unwrap();
            assert_eq!(s.state, ch, "state char {ch}");
        }
    }

    #[test]
    fn ticks_to_secs_zero() {
        assert_eq!(ticks_to_secs(0), 0.0);
    }

    #[test]
    fn ticks_to_secs_one_second() {
        // At 100 Hz, 100 ticks = 1.0 second.
        let secs = ticks_to_secs(100);
        // Actual Hz might be 250 on this kernel, so just check > 0 and < 2.
        assert!(secs > 0.0, "ticks_to_secs(100) must be > 0");
        assert!(secs <= 2.0, "ticks_to_secs(100) must be ≤ 2s");
    }

    #[test]
    fn missing_fields_returns_error() {
        assert!(parse("1 (x) S 0").is_err());
    }

    #[test]
    fn no_parens_returns_error() {
        assert!(parse("1 x S 0 1 1 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0").is_err());
    }

    #[test]
    fn read_current_process() {
        let pid = std::process::id();
        let s = Stat::read(pid).expect("read own /proc/stat");
        assert_eq!(s.pid, pid);
        assert!(s.num_threads >= 1);
        assert!(s.start_time > 0);
    }
}
