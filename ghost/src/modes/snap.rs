//! snap: one-shot /proc portrait. No probes, no caps (ARCHITECTURE §9.1).

use crate::proc::{stat::ticks_to_secs, ProcSnapshot};
use anyhow::Result;

pub fn run(pid: u32) -> Result<()> {
    let snap = ProcSnapshot::collect(pid)?;
    print_snap(&snap);
    Ok(())
}

fn print_snap(s: &ProcSnapshot) {
    let st = &s.stat;
    let su = &s.status;

    // ── Header ───────────────────────────────────────────────────────────────
    println!("\x1b[1;36m━━━  ghost snap  ──  pid {}  ━━━\x1b[0m", st.pid);
    println!();

    // ── Identity ─────────────────────────────────────────────────────────────
    section("IDENTITY");
    kv("name", &su.name);
    kv("exe", &s.exe);
    kv("cwd", &s.cwd);
    kv("cmdline", &s.cmdline);
    kv("pid", &st.pid.to_string());
    kv("ppid", &st.ppid.to_string());
    kv("pgrp", &st.pgrp.to_string());
    kv("session", &st.session.to_string());
    println!();

    // ── State ────────────────────────────────────────────────────────────────
    section("STATE");
    kv("state", &format!("{} ({})", st.state, state_name(st.state)));
    kv("threads", &su.threads.to_string());
    kv("wchan", &s.wchan);
    kv("last cpu", &st.last_cpu.to_string());
    kv("priority", &st.priority.to_string());
    kv("nice", &st.nice.to_string());
    println!();

    // ── CPU time ─────────────────────────────────────────────────────────────
    section("CPU TIME");
    kv("user", &fmt_secs(ticks_to_secs(st.utime_ticks)));
    kv("system", &fmt_secs(ticks_to_secs(st.stime_ticks)));
    kv(
        "total",
        &fmt_secs(ticks_to_secs(st.utime_ticks + st.stime_ticks)),
    );
    println!();

    // ── Memory ───────────────────────────────────────────────────────────────
    section("MEMORY");
    kv("VmRSS", &fmt_kb(su.vm_rss_kb));
    kv("VmSize", &fmt_kb(su.vm_size_kb));
    kv("VmPeak", &fmt_kb(su.vm_peak_kb));
    kv("VmSwap", &fmt_kb(su.vm_swap_kb));
    kv("VmExe", &fmt_kb(su.vm_exe_kb));
    kv("VmLib", &fmt_kb(su.vm_lib_kb));
    if let Some(sm) = &s.smaps {
        kv("PSS", &fmt_kb(sm.pss_kb));
        kv("private dirty", &fmt_kb(sm.private_dirty_kb));
        kv("shared dirty", &fmt_kb(sm.shared_dirty_kb));
        kv("swap (smaps)", &fmt_kb(sm.swap_kb));
    }
    println!();

    // ── VM regions summary ───────────────────────────────────────────────────
    section("VM REGIONS");
    let total_kb: u64 = s.maps.iter().map(|m| m.size_kb()).sum();
    let exec_kb: u64 = s
        .maps
        .iter()
        .filter(|m| m.is_exec())
        .map(|m| m.size_kb())
        .sum();
    let write_kb: u64 = s
        .maps
        .iter()
        .filter(|m| m.is_write())
        .map(|m| m.size_kb())
        .sum();
    kv("regions", &s.maps.len().to_string());
    kv("total span", &fmt_kb(total_kb));
    kv("exec", &fmt_kb(exec_kb));
    kv("writable", &fmt_kb(write_kb));
    println!();

    // ── I/O ──────────────────────────────────────────────────────────────────
    section("I/O  (cumulative)");
    kv("read (logical)", &fmt_bytes(s.io.rchar));
    kv("write (logical)", &fmt_bytes(s.io.wchar));
    kv("read (storage)", &fmt_bytes(s.io.read_bytes));
    kv("write (storage)", &fmt_bytes(s.io.write_bytes));
    kv("read syscalls", &s.io.syscr.to_string());
    kv("write syscalls", &s.io.syscw.to_string());
    println!();

    // ── File descriptors ─────────────────────────────────────────────────────
    section("FILE DESCRIPTORS");
    kv("total", &s.fds.total.to_string());
    kv("files", &s.fds.files.to_string());
    kv("sockets", &s.fds.sockets.to_string());
    kv("pipes", &s.fds.pipes.to_string());
    kv("anon", &s.fds.anon.to_string());
    kv("other", &s.fds.other.to_string());
    println!();

    // ── Sockets ──────────────────────────────────────────────────────────────
    if !s.sockets.is_empty() {
        section("SOCKETS");
        println!("  {:<6}  {:<25}  {:<25}  state", "proto", "local", "remote");
        println!("  {}", "─".repeat(72));
        for sk in &s.sockets {
            println!(
                "  {:<6}  {:<25}  {:<25}  {}",
                sk.proto, sk.local_addr, sk.remote_addr, sk.state
            );
        }
        println!();
    }

    // ── Credentials / security ───────────────────────────────────────────────
    section("CREDENTIALS");
    kv(
        "uid (real/eff)",
        &format!("{} / {}", su.uid_real, su.uid_effective),
    );
    kv(
        "gid (real/eff)",
        &format!("{} / {}", su.gid_real, su.gid_effective),
    );
    kv("no_new_privs", &su.no_new_privs.to_string());
    kv("seccomp", seccomp_name(su.seccomp));
    println!();

    // ── Context switches ─────────────────────────────────────────────────────
    section("CONTEXT SWITCHES");
    kv("voluntary", &su.voluntary_ctxt_switches.to_string());
    kv("non-voluntary", &su.nonvoluntary_ctxt_switches.to_string());
    println!();

    println!("\x1b[2m(snapshot taken at this instant; re-run for a fresh portrait)\x1b[0m");
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn section(title: &str) {
    println!("\x1b[1;33m{title}\x1b[0m");
}

fn kv(key: &str, val: &str) {
    println!("  \x1b[2m{key:<20}\x1b[0m  {val}");
}

fn state_name(c: char) -> &'static str {
    match c {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk-wait",
        'Z' => "zombie",
        'T' => "stopped",
        't' => "traced",
        'X' => "dead",
        'I' => "idle",
        _ => "?",
    }
}

fn fmt_secs(s: f64) -> String {
    format!("{s:.3}s")
}

fn fmt_kb(kb: u64) -> String {
    if kb == 0 {
        return "0 B".into();
    }
    if kb < 1024 {
        return format!("{kb} KiB");
    }
    let mb = kb as f64 / 1024.0;
    if mb < 1024.0 {
        return format!("{mb:.1} MiB");
    }
    format!("{:.1} GiB", mb / 1024.0)
}

fn fmt_bytes(b: u64) -> String {
    if b < 1024 {
        return format!("{b} B");
    }
    let kb = b as f64 / 1024.0;
    if kb < 1024.0 {
        return format!("{kb:.1} KiB");
    }
    let mb = kb / 1024.0;
    if mb < 1024.0 {
        return format!("{mb:.1} MiB");
    }
    format!("{:.1} GiB", mb / 1024.0)
}

fn seccomp_name(n: u8) -> &'static str {
    match n {
        1 => "strict",
        2 => "filter",
        _ => "disabled",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_names_cover_known_codes() {
        assert_eq!(state_name('R'), "running");
        assert_eq!(state_name('S'), "sleeping");
        assert_eq!(state_name('D'), "disk-wait");
        assert_eq!(state_name('Z'), "zombie");
        assert_eq!(state_name('T'), "stopped");
        assert_eq!(state_name('t'), "traced");
        assert_eq!(state_name('X'), "dead");
        assert_eq!(state_name('I'), "idle");
        assert_eq!(state_name('?'), "?");
    }

    #[test]
    fn fmt_kb_tiered() {
        assert_eq!(fmt_kb(0), "0 B");
        assert_eq!(fmt_kb(512), "512 KiB");
        assert!(fmt_kb(2048).ends_with("MiB"));
        assert!(fmt_kb(2 * 1024 * 1024).ends_with("GiB"));
    }

    #[test]
    fn fmt_bytes_tiered() {
        assert!(fmt_bytes(100).ends_with("B"));
        assert!(fmt_bytes(2 * 1024).ends_with("KiB"));
        assert!(fmt_bytes(2 * 1024 * 1024).ends_with("MiB"));
        assert!(fmt_bytes(2u64 * 1024 * 1024 * 1024).ends_with("GiB"));
    }

    #[test]
    fn fmt_secs_has_three_decimals_and_s_suffix() {
        let s = fmt_secs(1.23456);
        assert!(s.ends_with("s"));
        assert!(s.contains("1.23"));
    }

    #[test]
    fn seccomp_names() {
        assert_eq!(seccomp_name(1), "strict");
        assert_eq!(seccomp_name(2), "filter");
        assert_eq!(seccomp_name(0), "disabled");
        assert_eq!(seccomp_name(99), "disabled");
    }

    #[test]
    fn snap_run_against_self_succeeds() {
        // Smoke-test the full /proc read path against our own pid.
        // Any environment with /proc should satisfy this; the function
        // prints to stdout and returns Ok.
        let pid = std::process::id();
        assert!(
            run(pid).is_ok(),
            "snap on self must succeed on a /proc-backed system"
        );
    }
}
