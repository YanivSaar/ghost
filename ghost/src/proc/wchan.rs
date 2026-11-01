//! /proc/{pid}/wchan — the kernel symbol the task is currently sleeping in.

use anyhow::{Context, Result};
use std::fs;

pub fn read(pid: u32) -> Result<String> {
    let raw = fs::read_to_string(format!("/proc/{pid}/wchan"))
        .with_context(|| format!("reading /proc/{pid}/wchan"))?;
    Ok(normalise(&raw))
}

pub(crate) fn normalise(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() || s == "0" {
        "running".to_string()
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_string_means_running() {
        assert_eq!(normalise(""), "running");
    }

    #[test]
    fn zero_means_running() {
        assert_eq!(normalise("0"), "running");
    }

    #[test]
    fn zero_with_whitespace_means_running() {
        assert_eq!(normalise("  0  "), "running");
    }

    #[test]
    fn kernel_symbol_passed_through() {
        assert_eq!(normalise("do_epoll_wait"), "do_epoll_wait");
        assert_eq!(normalise("  futex_wait_queue_me  "), "futex_wait_queue_me");
    }

    #[test]
    fn read_current_process() {
        let pid = std::process::id();
        let w = read(pid).expect("read own wchan");
        // Must be either "running" or a non-empty symbol name.
        assert!(!w.is_empty());
    }
}
