//! ghost — a process observatory for Linux.
//!
//! `ghost <pid>`                      live watch dashboard (default)
//! `ghost snap <pid>`                 instant /proc snapshot, no eBPF
//! `ghost tree <pid>`                 follow a process subtree
//! `ghost cgroup <path|unit>`         watch a cgroup / systemd unit
//! `ghost lock|catch|cold|jitter ...` individual lenses
//! `ghost replay <file.ghost>`        replay a recorded session
//!
//! See docs/ARCHITECTURE.md (and the rendered architecture.html) for the full
//! design. This file is the Phase-0 CLI skeleton.

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
    /// PID to watch (shorthand for `ghost watch <pid>`).
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
    /// Lock contention map (barrier).
    Lock { pid: u32 },
    /// Arm a latency tripwire and capture the spike (wire).
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
    // TODO(phase 0): resolve target + modes, hand off to supervisor::run().
    eprintln!("ghost: Phase-0 skeleton. Parsed: {cli:?}");
    Ok(())
}
