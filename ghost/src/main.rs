//! ghost — a process observatory for Linux.
//!
//! `ghost <pid>`                      instant /proc snapshot (Phase-1 default)
//! `ghost snap <pid>`                 same, explicit
//! `ghost tree <pid>`                 follow a process subtree
//! `ghost cgroup <path|unit>`         watch a cgroup / systemd unit
//! `ghost lock|catch|cold|jitter ...` individual lenses
//! `ghost replay <file.ghost>`        replay a recorded session
//!
//! See docs/ARCHITECTURE.md for the full design.

mod supervisor;
mod state;
mod target;
mod ebpf;
mod proc;
mod modes;
mod session;
mod tui;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(name = "ghost", version, about = "Attach to a process, and see everything.")]
struct Cli {
    /// PID to snapshot (shorthand for `ghost snap <pid>`).
    pid: Option<u32>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Tee the raw event stream to a .ghost session file.
    #[arg(long, global = true)]
    record: Option<String>,

    /// Run headless (no TUI); pair with --record / --duration.
    #[arg(long, global = true)]
    no_tui: bool,

    /// Initial TUI aesthetic (toggle at runtime with `v`).
    #[arg(long, global = true, value_enum, default_value_t = Theme::Dense)]
    theme: Theme,

    /// /proc poll cadence in milliseconds.
    #[arg(long, global = true, default_value_t = 500)]
    interval: u64,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Theme { Dense, Minimal }

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Instant /proc portrait (no eBPF, no caps).
    Snap { pid: u32 },
    /// Live dashboard (default lens).
    Watch { pid: u32 },
    /// Follow a process and all its descendants.
    Tree { pid: u32 },
    /// Watch every process in a cgroup or systemd unit.
    Cgroup { target: String },
    /// Lock contention map.
    Lock { pid: u32 },
    /// Arm a latency tripwire and capture the spike.
    Catch { pid: u32, #[arg(long)] above: String },
    /// Startup archaeology from execve to first work.
    Cold { cmd: Vec<String> },
    /// Attribute jitter to IRQ/NMI/preemption sources.
    Jitter { pid: u32 },
    /// Replay a recorded session.
    Replay { file: String, #[arg(long)] seek: Option<String> },
    /// Compare two recorded sessions.
    Diff { a: String, b: String },
}

/// Parse a short duration like "10ms", "500us", "1s", "250000ns" into nanoseconds.
/// Accepts suffixes: ns, us, µs, ms, s. Bare integers are interpreted as ns.
pub(crate) fn parse_duration_ns(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() { return Err("empty".into()); }

    let (num_str, mult): (&str, u64) =
        if let Some(rest) = s.strip_suffix("ns") { (rest, 1) }
        else if let Some(rest) = s.strip_suffix("us") { (rest, 1_000) }
        else if let Some(rest) = s.strip_suffix("µs") { (rest, 1_000) }
        else if let Some(rest) = s.strip_suffix("ms") { (rest, 1_000_000) }
        else if let Some(rest) = s.strip_suffix('s')  { (rest, 1_000_000_000) }
        else { (s, 1) };

    let n: u64 = num_str.trim().parse().map_err(|_| format!("invalid number '{num_str}'"))?;
    n.checked_mul(mult).ok_or_else(|| "overflow".into())
}

#[cfg(test)]
mod parse_tests {
    use super::parse_duration_ns;
    #[test] fn ns()     { assert_eq!(parse_duration_ns("500ns").unwrap(), 500); }
    #[test] fn us()     { assert_eq!(parse_duration_ns("500us").unwrap(), 500_000); }
    #[test] fn us_utf8(){ assert_eq!(parse_duration_ns("500µs").unwrap(), 500_000); }
    #[test] fn ms()     { assert_eq!(parse_duration_ns("10ms").unwrap(), 10_000_000); }
    #[test] fn s()      { assert_eq!(parse_duration_ns("2s").unwrap(), 2_000_000_000); }
    #[test] fn bare()   { assert_eq!(parse_duration_ns("1000").unwrap(), 1000); }
    #[test] fn empty()  { assert!(parse_duration_ns("").is_err()); }
    #[test] fn bad()    { assert!(parse_duration_ns("abc").is_err()); }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Some(Cmd::Snap { pid }) => modes::snap::run(pid),
        None => {
            let pid = cli.pid.unwrap_or_else(|| {
                eprintln!("ghost: a PID is required.  Usage: ghost <pid>");
                std::process::exit(1);
            });
            // Default: live watch dashboard. Falls back to proc-only if no eBPF caps.
            supervisor::run(pid, cli.record)
        }
        Some(Cmd::Watch  { pid }) => {
            supervisor::run(pid, cli.record)
        }
        Some(Cmd::Tree   { pid }) => {
            eprintln!("ghost: tree mode is Phase-3 (not yet implemented). Try: ghost snap {pid}");
            Ok(())
        }
        Some(Cmd::Cgroup { target }) => {
            eprintln!("ghost: cgroup mode is Phase-3 (not yet implemented). target={target}");
            Ok(())
        }
        Some(Cmd::Lock   { pid }) => supervisor::run_lock(pid, cli.record),
        Some(Cmd::Catch  { pid, above }) => {
            let threshold_ns = parse_duration_ns(&above).unwrap_or_else(|e| {
                eprintln!("ghost: --above: {e} (expected e.g. 10ms, 500us, 1s)");
                std::process::exit(1);
            });
            if threshold_ns == 0 {
                eprintln!("ghost: --above must be greater than zero");
                std::process::exit(1);
            }
            supervisor::run_catch(pid, cli.record, threshold_ns)
        }
        Some(Cmd::Cold   { cmd }) => supervisor::run_cold(cmd, cli.record),
        Some(Cmd::Jitter { pid }) => supervisor::run_jitter(pid, cli.record),
        Some(Cmd::Replay { file, .. }) => {
            eprintln!("ghost: replay is Phase-2 (not yet implemented). file={file}");
            Ok(())
        }
        Some(Cmd::Diff   { a, b }) => {
            eprintln!("ghost: diff is Phase-2 (not yet implemented). a={a} b={b}");
            Ok(())
        }
    }
}
