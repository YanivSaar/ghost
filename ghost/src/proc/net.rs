//! /proc/{pid}/net/tcp, tcp6, udp, udp6 — sockets with connection state.
//!
//! We find the inode numbers of the process's socket FDs, then look them up
//! in the net tables to retrieve addresses and state.

use anyhow::Result;
use std::collections::HashSet;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub local_addr: String,
    pub remote_addr: String,
    pub state: String,
    pub proto: &'static str,
    pub inode: u64,
}

pub fn read(pid: u32) -> Result<Vec<SocketEntry>> {
    // Gather the inode numbers of all socket FDs this pid holds.
    let socket_inodes = socket_inodes(pid);

    let mut entries = Vec::new();
    for (path, proto, is_v6) in [
        (format!("/proc/{pid}/net/tcp"), "tcp", false),
        (format!("/proc/{pid}/net/tcp6"), "tcp6", true),
        (format!("/proc/{pid}/net/udp"), "udp", false),
        (format!("/proc/{pid}/net/udp6"), "udp6", true),
    ] {
        if let Ok(raw) = fs::read_to_string(&path) {
            for entry in parse_net_file(&raw, proto, is_v6) {
                if socket_inodes.contains(&entry.inode) {
                    entries.push(entry);
                }
            }
        }
    }
    Ok(entries)
}

fn socket_inodes(pid: u32) -> HashSet<u64> {
    let mut set = HashSet::new();
    let dir = format!("/proc/{pid}/fd");
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            if let Ok(target) = fs::read_link(e.path()) {
                let s = target.to_string_lossy();
                if let Some(inode_s) = s.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                {
                    if let Ok(inode) = inode_s.parse::<u64>() {
                        set.insert(inode);
                    }
                }
            }
        }
    }
    set
}

fn parse_net_file(raw: &str, proto: &'static str, is_v6: bool) -> Vec<SocketEntry> {
    raw.lines()
        .skip(1)
        .filter_map(|line| parse_net_line(line, proto, is_v6))
        .collect()
}

fn parse_net_line(line: &str, proto: &'static str, is_v6: bool) -> Option<SocketEntry> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 10 {
        return None;
    }

    let local_addr = decode_addr(fields[1], is_v6)?;
    let remote_addr = decode_addr(fields[2], is_v6)?;
    let state_hex: u8 = u8::from_str_radix(fields[3], 16).ok()?;
    let state = tcp_state(state_hex);
    let inode: u64 = fields[9].parse().ok()?;

    Some(SocketEntry {
        local_addr,
        remote_addr,
        state: state.to_string(),
        proto,
        inode,
    })
}

fn decode_addr(hex: &str, is_v6: bool) -> Option<String> {
    let (addr_hex, port_hex) = hex.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;

    let addr = if is_v6 {
        // 32 hex chars, little-endian 32-bit words
        if addr_hex.len() != 32 {
            return None;
        }
        let mut words = [0u32; 4];
        for (i, w) in words.iter_mut().enumerate() {
            *w = u32::from_str_radix(&addr_hex[i * 8..(i + 1) * 8], 16)
                .ok()?
                .swap_bytes();
        }
        let bytes: [u8; 16] = unsafe { std::mem::transmute(words) };
        Ipv6Addr::from(bytes).to_string()
    } else {
        if addr_hex.len() != 8 {
            return None;
        }
        let raw = u32::from_str_radix(addr_hex, 16).ok()?.swap_bytes();
        Ipv4Addr::from(raw).to_string()
    };

    Some(format!("{addr}:{port}"))
}

fn tcp_state(n: u8) -> &'static str {
    match n {
        1 => "ESTABLISHED",
        2 => "SYN_SENT",
        3 => "SYN_RECV",
        4 => "FIN_WAIT1",
        5 => "FIN_WAIT2",
        6 => "TIME_WAIT",
        7 => "CLOSE",
        8 => "CLOSE_WAIT",
        9 => "LAST_ACK",
        10 => "LISTEN",
        11 => "CLOSING",
        12 => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helpers that expose private functions for testing.
    fn addr(hex: &str, is_v6: bool) -> Option<String> {
        decode_addr(hex, is_v6)
    }

    fn net_line(line: &str, proto: &'static str, is_v6: bool) -> Option<SocketEntry> {
        parse_net_line(line, proto, is_v6)
    }

    // ── decode_addr ───────────────────────────────────────────────────────────

    #[test]
    fn decode_loopback_listen() {
        // 0100007F:9C40 → 127.0.0.1:40000
        let a = addr("0100007F:9C40", false).unwrap();
        assert_eq!(a, "127.0.0.1:40000");
    }

    #[test]
    fn decode_any_zero_port() {
        // 00000000:0000 → 0.0.0.0:0
        let a = addr("00000000:0000", false).unwrap();
        assert_eq!(a, "0.0.0.0:0");
    }

    #[test]
    fn decode_addr_invalid_returns_none() {
        assert!(addr("GGGGGGGG:0000", false).is_none());
        assert!(addr("tooshort:80", false).is_none());
    }

    // ── tcp_state ─────────────────────────────────────────────────────────────

    #[test]
    fn tcp_state_known_values() {
        assert_eq!(tcp_state(1), "ESTABLISHED");
        assert_eq!(tcp_state(10), "LISTEN");
        assert_eq!(tcp_state(6), "TIME_WAIT");
        assert_eq!(tcp_state(0), "UNKNOWN");
        assert_eq!(tcp_state(99), "UNKNOWN");
    }

    // ── parse_net_line ────────────────────────────────────────────────────────

    #[test]
    fn parse_listen_line() {
        // Typical /proc/net/tcp LISTEN entry:
        // idx  local           remote         st  ...     uid  timeout  inode
        let line = "  0: 0100007F:1F40 00000000:0000 0A \
                    00000000:00000000 00:00000000 00000000   1000        0 99999 \
                    1 0000000000000000 100 0 0 10 0";
        let e = net_line(line, "tcp", false).unwrap();
        assert_eq!(e.local_addr, "127.0.0.1:8000");
        assert_eq!(e.remote_addr, "0.0.0.0:0");
        assert_eq!(e.state, "LISTEN");
        assert_eq!(e.proto, "tcp");
        assert_eq!(e.inode, 99999);
    }

    #[test]
    fn parse_established_line() {
        let line = "  1: 0101007F:D2F8 0101007F:1F40 01 \
                    00000000:00000000 00:00000000 00000000   1000        0 88888 \
                    1 0000000000000000 20 4 26 10 -1";
        let e = net_line(line, "tcp", false).unwrap();
        assert_eq!(e.state, "ESTABLISHED");
        assert_eq!(e.inode, 88888);
    }

    #[test]
    fn malformed_line_returns_none() {
        assert!(net_line("not a valid line at all", "tcp", false).is_none());
    }

    // ── socket_inodes (via read) ──────────────────────────────────────────────

    #[test]
    fn read_current_process_does_not_panic() {
        let pid = std::process::id();
        // The test process has no TCP sockets, so result may be empty — that's fine.
        let _ = read(pid);
    }
}
