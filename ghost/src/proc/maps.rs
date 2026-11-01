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
    pub fn size_kb(&self) -> u64 {
        (self.end - self.start) / 1024
    }

    pub fn is_exec(&self) -> bool {
        self.perms.contains('x')
    }
    pub fn is_write(&self) -> bool {
        self.perms.contains('w')
    }
    pub fn is_anon(&self) -> bool {
        self.pathname.is_empty() || self.pathname == "[heap]" || self.pathname == "[stack]"
    }
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

pub(crate) fn parse_maps(raw: &str) -> Vec<MapRegion> {
    raw.lines().filter_map(parse_map_line).collect()
}

fn parse_map_line(line: &str) -> Option<MapRegion> {
    let mut parts = line.splitn(6, ' ');
    let range = parts.next()?;
    let perms = parts.next()?.to_string();
    let offset = u64::from_str_radix(parts.next()?, 16).ok()?;
    let dev = parts.next()?.to_string();
    let inode = parts.next()?.parse().ok()?;
    let pathname = parts
        .next()
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let (start_s, end_s) = range.split_once('-')?;
    let start = u64::from_str_radix(start_s, 16).ok()?;
    let end = u64::from_str_radix(end_s, 16).ok()?;

    Some(MapRegion {
        start,
        end,
        perms,
        offset,
        dev,
        inode,
        pathname,
    })
}

pub(crate) fn parse_smaps_rollup(raw: &str) -> SmasRollup {
    let mut r = SmasRollup::default();
    for line in raw.lines() {
        let Some((key, val)) = line.split_once(':') else {
            continue;
        };
        let v = parse_kb(val.trim());
        match key.trim() {
            "Rss" => r.rss_kb = v,
            "Pss" => r.pss_kb = v,
            "Shared_Clean" => r.shared_clean_kb = v,
            "Shared_Dirty" => r.shared_dirty_kb = v,
            "Private_Clean" => r.private_clean_kb = v,
            "Private_Dirty" => r.private_dirty_kb = v,
            "Swap" => r.swap_kb = v,
            _ => {}
        }
    }
    r
}

fn parse_kb(val: &str) -> u64 {
    val.split_whitespace()
        .next()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typical_maps() {
        let raw = "\
7f1a00000000-7f1a00001000 r-xp 00000000 fd:01 123456 /usr/lib/libc.so.6\n\
7f1a00001000-7f1a00002000 rw-p 00001000 fd:01 123456 /usr/lib/libc.so.6\n\
7f1a00002000-7f1a00003000 ---p 00000000 00:00 0 \n\
7fff00000000-7fff00010000 rwxp 00000000 00:00 0 [stack]\n";

        let regions = parse_maps(raw);
        assert_eq!(regions.len(), 4);

        let r0 = &regions[0];
        assert_eq!(r0.start, 0x7f1a00000000);
        assert_eq!(r0.end, 0x7f1a00001000);
        assert_eq!(r0.perms, "r-xp");
        assert_eq!(r0.inode, 123456);
        assert_eq!(r0.pathname, "/usr/lib/libc.so.6");
        assert!(r0.is_exec());
        assert!(!r0.is_write());
        assert_eq!(r0.size_kb(), 4);

        let r1 = &regions[1];
        assert!(r1.is_write());
        assert!(!r1.is_exec());

        // anonymous region (empty pathname)
        let r2 = &regions[2];
        assert_eq!(r2.pathname, "");
        assert!(r2.is_anon());

        // [stack] is treated as anon
        let r3 = &regions[3];
        assert_eq!(r3.pathname, "[stack]");
        assert!(r3.is_anon());
    }

    #[test]
    fn size_kb_correct() {
        let raw = "00400000-00401000 r-xp 00000000 fd:01 1 /bin/prog\n";
        let regions = parse_maps(raw);
        assert_eq!(regions[0].size_kb(), 4);
    }

    #[test]
    fn malformed_line_skipped() {
        let raw = "not-a-valid-line\n00400000-00401000 r-xp 0 fd:01 1 /x\n";
        let regions = parse_maps(raw);
        assert_eq!(regions.len(), 1);
    }

    #[test]
    fn parse_smaps_rollup_fields() {
        let raw = "\
00000000-ffffffff ---p 00000000 00:00 0\n\
Rss:            8192 kB\n\
Pss:            4096 kB\n\
Shared_Clean:    512 kB\n\
Shared_Dirty:    256 kB\n\
Private_Clean:   128 kB\n\
Private_Dirty:  1024 kB\n\
Swap:            768 kB\n";

        let r = parse_smaps_rollup(raw);
        assert_eq!(r.rss_kb, 8192);
        assert_eq!(r.pss_kb, 4096);
        assert_eq!(r.shared_clean_kb, 512);
        assert_eq!(r.shared_dirty_kb, 256);
        assert_eq!(r.private_clean_kb, 128);
        assert_eq!(r.private_dirty_kb, 1024);
        assert_eq!(r.swap_kb, 768);
    }

    #[test]
    fn read_current_process_maps() {
        let pid = std::process::id();
        let regions = read_maps(pid).expect("read own /proc/maps");
        assert!(!regions.is_empty(), "self must have at least one mapping");
        // At minimum the executable itself should have a text region.
        assert!(regions.iter().any(|r| r.is_exec()));
    }
}
