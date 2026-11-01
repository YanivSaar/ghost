//! /proc/{pid}/io — cumulative I/O byte counters.

use anyhow::{Context, Result};
use std::fs;

#[derive(Debug, Clone, Default)]
pub struct Io {
    pub rchar: u64,
    pub wchar: u64,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub syscr: u64,
    pub syscw: u64,
    pub cancelled_write_bytes: u64,
}

impl Io {
    pub fn read(pid: u32) -> Result<Self> {
        let raw = fs::read_to_string(format!("/proc/{pid}/io"))
            .with_context(|| format!("reading /proc/{pid}/io"))?;
        Ok(parse(&raw))
    }
}

pub(crate) fn parse(raw: &str) -> Io {
    let mut io = Io::default();
    for line in raw.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let v: u64 = val.trim().parse().unwrap_or(0);
        match key.trim() {
            "rchar"                  => io.rchar = v,
            "wchar"                  => io.wchar = v,
            "read_bytes"             => io.read_bytes = v,
            "write_bytes"            => io.write_bytes = v,
            "syscr"                  => io.syscr = v,
            "syscw"                  => io.syscw = v,
            "cancelled_write_bytes"  => io.cancelled_write_bytes = v,
            _ => {}
        }
    }
    io
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
rchar: 1048576\n\
wchar: 524288\n\
syscr: 256\n\
syscw: 128\n\
read_bytes: 4096\n\
write_bytes: 2048\n\
cancelled_write_bytes: 512\n";

    #[test]
    fn parses_all_fields() {
        let io = parse(SAMPLE);
        assert_eq!(io.rchar,                 1048576);
        assert_eq!(io.wchar,                 524288);
        assert_eq!(io.syscr,                 256);
        assert_eq!(io.syscw,                 128);
        assert_eq!(io.read_bytes,            4096);
        assert_eq!(io.write_bytes,           2048);
        assert_eq!(io.cancelled_write_bytes, 512);
    }

    #[test]
    fn empty_returns_default() {
        let io = parse("");
        assert_eq!(io.rchar, 0);
        assert_eq!(io.read_bytes, 0);
    }

    #[test]
    fn unknown_keys_ignored() {
        let io = parse("future_counter: 99\nrchar: 42\n");
        assert_eq!(io.rchar, 42);
    }

    #[test]
    fn read_current_process() {
        let pid = std::process::id();
        // io may be denied (EPERM) in some environments; just check it doesn't panic.
        let _ = Io::read(pid);
    }
}
