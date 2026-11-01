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

fn parse(raw: &str) -> Io {
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
