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
        Some(Cmd::Lock   { pid }) => {
            eprintln!("ghost: lock mode is Phase-3 (not yet implemented). Try: ghost snap {pid}");
            Ok(())
        }
        Some(Cmd::Catch  { pid, above }) => {
            eprintln!("ghost: catch mode is Phase-4 (not yet implemented). pid={pid} above={above}");
            Ok(())
        }
        Some(Cmd::Cold   { cmd }) => {
            eprintln!("ghost: cold mode is Phase-5 (not yet implemented). cmd={cmd:?}");
            Ok(())
        }
        Some(Cmd::Jitter { pid }) => {
            eprintln!("ghost: jitter mode is Phase-6 (not yet implemented). Try: ghost snap {pid}");
            Ok(())
        }
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
