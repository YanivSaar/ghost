//! /proc/{pid}/wchan — the kernel symbol the task is currently sleeping in.

use anyhow::{Context, Result};
use std::fs;

pub fn read(pid: u32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/wchan"))
        .with_context(|| format!("reading /proc/{pid}/wchan"))?;
    let s = raw.trim();
    Ok(if s.is_empty() || s == "0" { "running".to_string() } else { s.to_string() })
}
