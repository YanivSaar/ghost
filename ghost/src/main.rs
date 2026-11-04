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

use ghost::{modes, panic_hook, supervisor};

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "ghost",
    version,
    about = "Attach to a process, and see everything."
)]
struct Cli {
    /// PID to snapshot (shorthand for `ghost snap <pid>`).
    pid: Option<u32>,

    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Tee the raw event stream to a .ghost session file.
    #[arg(long, global = true)]
    record: Option<String>,

    /// Install the persistent watcher as a systemd service for the given
    /// target. Requires one of `--pid / --tree / --cgroup / --unit`.
    /// See `docs/DAEMON.md`.
    #[arg(long, conflicts_with = "uninstall")]
    install: bool,

    /// Tear down an installed ghost daemon. Without a target, removes every
    /// installed `ghost@*.service`. With `--purge`, also deletes the rotated
    /// log directory.
    #[arg(long)]
    uninstall: bool,

    /// Also delete `/var/log/ghost/<slug>/` on `--uninstall`. User data —
    /// off by default.
    #[arg(long, requires = "uninstall")]
    purge: bool,

    /// Print what install/uninstall would do without touching the system.
    #[arg(long)]
    dry_run: bool,

    /// Skip `systemctl` invocation on install/uninstall (e.g. WSL2 /
    /// containers / sandbox tests). Files are still written / removed.
    #[arg(long)]
    no_systemctl: bool,

    /// Target for `--install` / `--uninstall`: a PID.
    #[arg(long = "pid", group = "daemon_target")]
    daemon_pid: Option<u32>,

    /// Target for `--install` / `--uninstall`: a PID tree root.
    #[arg(long = "tree", group = "daemon_target")]
    daemon_tree: Option<u32>,

    /// Target for `--install` / `--uninstall`: a cgroup path.
    #[arg(long = "cgroup", group = "daemon_target")]
    daemon_cgroup: Option<String>,

    /// Target for `--install` / `--uninstall`: a systemd unit name.
    #[arg(long = "unit", group = "daemon_target")]
    daemon_unit: Option<String>,

    /// Rotation: max bytes per segment (default 100 MiB).
    #[arg(long, default_value_t = 100 * 1024 * 1024)]
    max_segment_bytes: u64,

    /// Rotation: keep this many rotated segments (default 10).
    #[arg(long, default_value_t = 10)]
    keep_segments: usize,

    /// Rotation: rotate after this many seconds, even if under size cap
    /// (default 86400 = 24h).
    #[arg(long, default_value_t = 24 * 60 * 60)]
    max_age_secs: u64,
}

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
    Catch {
        pid: u32,
        #[arg(long)]
        above: String,
    },
    /// Startup archaeology from execve to first work.
    Cold { cmd: Vec<String> },
    /// Attribute jitter to IRQ/NMI/preemption sources.
    Jitter { pid: u32 },
    /// Replay a recorded session.
    Replay {
        file: String,
        #[arg(long)]
        seek: Option<String>,
    },
    /// Compare two recorded sessions.
    Diff { a: String, b: String },
    /// Run as a persistent headless watcher. Invoked by the installed
    /// systemd unit; pass `--config` to point at the generated daemon.toml.
    /// You can also pass a target spec directly for ad-hoc runs.
    Daemon {
        #[arg(long)]
        config: Option<String>,
        #[arg(long)]
        pid: Option<u32>,
        #[arg(long)]
        tree: Option<u32>,
        #[arg(long)]
        cgroup: Option<String>,
        #[arg(long)]
        unit: Option<String>,
        /// Log dir override (ad-hoc; ignored when `--config` is passed).
        #[arg(long)]
        log_dir: Option<String>,
        #[arg(long, default_value_t = 100 * 1024 * 1024)]
        max_segment_bytes: u64,
        #[arg(long, default_value_t = 10)]
        keep_segments: usize,
        #[arg(long, default_value_t = 24 * 60 * 60)]
        max_age_secs: u64,
    },
    /// Scenario analyzer (RFC 0001): offline over a session file, or
    /// one-shot live via --pid + --duration.
    Analyze {
        /// Session file to analyze (positional). Omit for live mode.
        file: Option<String>,
        /// Live analyze: attach briefly to this pid, dump diagnoses, exit.
        #[arg(long)]
        pid: Option<u32>,
        /// How long to collect for in live mode (e.g. 10s, 500ms).
        #[arg(long, default_value = "10s")]
        duration: String,
        /// Emit JSON array (mutually exclusive with --jsonl).
        #[arg(long)]
        json: bool,
        /// Emit JSON Lines (mutually exclusive with --json).
        #[arg(long)]
        jsonl: bool,
        /// quiet | noisy
        #[arg(long, default_value = "quiet")]
        mode: String,
        /// Override config path. Omit for XDG default.
        #[arg(long)]
        config: Option<String>,
    },
}

/// Parse a short duration like "10ms", "500us", "1s", "250000ns" into nanoseconds.
/// Accepts suffixes: ns, us, µs, ms, s. Bare integers are interpreted as ns.
pub(crate) fn parse_duration_ns(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty".into());
    }

    let (num_str, mult): (&str, u64) = if let Some(rest) = s.strip_suffix("ns") {
        (rest, 1)
    } else if let Some(rest) = s.strip_suffix("us") {
        (rest, 1_000)
    } else if let Some(rest) = s.strip_suffix("µs") {
        (rest, 1_000)
    } else if let Some(rest) = s.strip_suffix("ms") {
        (rest, 1_000_000)
    } else if let Some(rest) = s.strip_suffix('s') {
        (rest, 1_000_000_000)
    } else {
        (s, 1)
    };

    let n: u64 = num_str
        .trim()
        .parse()
        .map_err(|_| format!("invalid number '{num_str}'"))?;
    n.checked_mul(mult).ok_or_else(|| "overflow".into())
}

fn main() -> anyhow::Result<()> {
    // Install the terminal-reset panic hook *before* anything else can
    // panic. If we die after this point, the user still gets a usable
    // shell back.
    panic_hook::install();

    let cli = Cli::parse();

    // Top-level install/uninstall shortcuts: these don't attach, they just
    // write (or remove) the systemd unit + config. They're mutually exclusive
    // with any subcommand (enforced by clap).
    if cli.install || cli.uninstall {
        return handle_install_uninstall(&cli);
    }

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
        Some(Cmd::Watch { pid }) => supervisor::run(pid, cli.record),
        Some(Cmd::Tree { pid }) => supervisor::run_tree(pid, cli.record),
        Some(Cmd::Cgroup { target }) => supervisor::run_cgroup(target, cli.record),
        Some(Cmd::Lock { pid }) => supervisor::run_lock(pid, cli.record),
        Some(Cmd::Catch { pid, above }) => {
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
        Some(Cmd::Cold { cmd }) => supervisor::run_cold(cmd, cli.record),
        Some(Cmd::Jitter { pid }) => supervisor::run_jitter(pid, cli.record),
        Some(Cmd::Replay { file, seek }) => supervisor::run_replay(file, seek),
        Some(Cmd::Diff { a, b }) => supervisor::run_diff(a, b),
        Some(Cmd::Daemon {
            config,
            pid,
            tree,
            cgroup,
            unit,
            log_dir,
            max_segment_bytes,
            keep_segments,
            max_age_secs,
        }) => {
            use ghost::modes::daemon::DaemonConfig;
            use ghost::session::dir_writer::RotationConfig;
            use std::time::Duration;

            let cfg = if let Some(path) = config {
                let s = std::fs::read_to_string(&path)
                    .map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?;
                DaemonConfig::from_toml(&s)?
            } else {
                let target = pick_target(pid, tree, cgroup, unit)
                    .ok_or_else(|| anyhow::anyhow!(
                        "ghost daemon: supply --config OR exactly one of --pid/--tree/--cgroup/--unit",
                    ))?;
                let slug = target.slug();
                let log_dir = log_dir.map(std::path::PathBuf::from).unwrap_or_else(|| {
                    let layout = ghost::modes::daemon::Layout::resolve();
                    layout.log_dir.join(slug)
                });
                DaemonConfig {
                    target,
                    log_dir,
                    rotation: RotationConfig {
                        max_segment_bytes,
                        keep_segments,
                        max_age: Duration::from_secs(max_age_secs),
                    },
                }
            };
            ghost::modes::daemon::run(cfg)
        }
        Some(Cmd::Analyze {
            file,
            pid,
            duration,
            json,
            jsonl,
            mode,
            config,
        }) => {
            if json && jsonl {
                eprintln!("ghost: --json and --jsonl are mutually exclusive");
                std::process::exit(1);
            }
            let fmt = if json {
                ghost::modes::analyze::Format::Json
            } else if jsonl {
                ghost::modes::analyze::Format::Jsonl
            } else {
                ghost::modes::analyze::Format::Plain
            };
            let an_mode = match mode.as_str() {
                "noisy" => ghost::analyze::Mode::Noisy,
                _ => ghost::analyze::Mode::Quiet,
            };
            ghost::modes::analyze::run(ghost::modes::analyze::Args {
                file,
                pid,
                duration,
                format: fmt,
                mode: an_mode,
                config,
            })
        }
    }
}

fn pick_target(
    pid: Option<u32>,
    tree: Option<u32>,
    cgroup: Option<String>,
    unit: Option<String>,
) -> Option<ghost::modes::daemon::DaemonTarget> {
    use ghost::modes::daemon::DaemonTarget;
    match (pid, tree, cgroup, unit) {
        (Some(p), None, None, None) => Some(DaemonTarget::Pid(p)),
        (None, Some(p), None, None) => Some(DaemonTarget::Tree(p)),
        (None, None, Some(c), None) => Some(DaemonTarget::Cgroup(c)),
        (None, None, None, Some(u)) => Some(DaemonTarget::Unit(u)),
        _ => None,
    }
}

fn handle_install_uninstall(cli: &Cli) -> anyhow::Result<()> {
    use ghost::modes::daemon::{install, uninstall, InstallArgs, UninstallArgs};
    use ghost::session::dir_writer::RotationConfig;
    use std::time::Duration;

    let target = pick_target(
        cli.daemon_pid,
        cli.daemon_tree,
        cli.daemon_cgroup.clone(),
        cli.daemon_unit.clone(),
    );

    if cli.install {
        let target = target.ok_or_else(|| {
            anyhow::anyhow!(
                "ghost --install: pass one of --pid N | --tree N | --cgroup PATH | --unit NAME",
            )
        })?;
        let args = InstallArgs {
            target,
            rotation: RotationConfig {
                max_segment_bytes: cli.max_segment_bytes,
                keep_segments: cli.keep_segments,
                max_age: Duration::from_secs(cli.max_age_secs),
            },
            dry_run: cli.dry_run,
            no_systemctl: cli.no_systemctl,
        };
        let name = install(args)?;
        eprintln!("ghost: installed {name}");
        Ok(())
    } else {
        let args = UninstallArgs {
            target,
            purge_logs: cli.purge,
            dry_run: cli.dry_run,
            no_systemctl: cli.no_systemctl,
        };
        let removed = uninstall(args)?;
        if removed.is_empty() {
            eprintln!("ghost: no daemon units found to remove");
        } else {
            for s in removed {
                eprintln!("ghost: removed {s}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod parse_tests {
    use super::parse_duration_ns;
    #[test]
    fn ns() {
        assert_eq!(parse_duration_ns("500ns").unwrap(), 500);
    }
    #[test]
    fn us() {
        assert_eq!(parse_duration_ns("500us").unwrap(), 500_000);
    }
    #[test]
    fn us_utf8() {
        assert_eq!(parse_duration_ns("500µs").unwrap(), 500_000);
    }
    #[test]
    fn ms() {
        assert_eq!(parse_duration_ns("10ms").unwrap(), 10_000_000);
    }
    #[test]
    fn s() {
        assert_eq!(parse_duration_ns("2s").unwrap(), 2_000_000_000);
    }
    #[test]
    fn bare() {
        assert_eq!(parse_duration_ns("1000").unwrap(), 1000);
    }
    #[test]
    fn empty() {
        assert!(parse_duration_ns("").is_err());
    }
    #[test]
    fn bad() {
        assert!(parse_duration_ns("abc").is_err());
    }
}
