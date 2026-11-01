//! /proc/{pid}/maps and smaps_rollup readers.

use anyhow::{Context, Result};
use std::fs;

#[derive(Debug, Clone)]
pub struct MapRegion {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev: String,
    pub inode: u64,
    pub pathname: String,
}

impl MapRegion {
    pub fn size_kb(&self) -> u64 { (self.end - self.start) / 1024 }

    pub fn is_exec(&self) -> bool { self.perms.contains('x') }
    pub fn is_write(&self) -> bool { self.perms.contains('w') }
    pub fn is_anon(&self) -> bool { self.pathname.is_empty() || self.pathname == "[heap]" || self.pathname == "[stack]" }
}

#[derive(Debug, Clone, Default)]
pub struct SmasRollup {
    pub rss_kb: u64,
    pub pss_kb: u64,
    pub shared_clean_kb: u64,
    pub shared_dirty_kb: u64,
    pub private_clean_kb: u64,
    pub private_dirty_kb: u64,
    pub swap_kb: u64,
}

pub fn read_maps(pid: u32) -> Result<Vec<MapRegion>> {
    let raw = fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("reading /proc/{pid}/maps"))?;
    Ok(parse_maps(&raw))
}

pub fn read_smaps_rollup(pid: u32) -> Option<SmasRollup> {
    let raw = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    Some(parse_smaps_rollup(&raw))
}

fn parse_maps(raw: &str) -> Vec<MapRegion> {
    raw.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MapRegion> {
    let mut parts = line.splitn(6, ' ');
    let range   = parts.next()?;
    let perms   = parts.next()?.to_string();
    let offset  = u64::from_str_radix(parts.next()?, 16).ok()?;
    let dev     = parts.next()?.to_string();
    let inode   = parts.next()?.parse().ok()?;
    let pathname = parts.next().map(|s| s.trim().to_string()).unwrap_or_default();

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end   = u64::from_str_radix(end_s, 16).ok()?;

    Some(MapRegion { start, end, perms, offset, dev, inode, pathname })
}

fn parse_smaps_rollup(raw: &str) -> SmasRollup {
    let mut r = SmasRollup::default();
    for line in raw.lines() {
        let Some((key, val)) = line.split_once(':') else { continue };
        let v = parse_kb(val.trim());
        match key.trim() {
            "Rss"          => r.rss_kb = v,
            "Pss"          => r.pss_kb = v,
            "Shared_Clean" => r.shared_clean_kb = v,
            "Shared_Dirty" => r.shared_dirty_kb = v,
            "Private_Clean" => r.private_clean_kb = v,
            "Private_Dirty" => r.private_dirty_kb = v,
            "Swap"         => r.swap_kb = v,
            _ => {}
        }
    }
    r
}

fn parse_kb(val: &str) -> u64 {
    val.split_whitespace().next().and_then(|v| v.parse().ok()).unwrap_or(0)
}
