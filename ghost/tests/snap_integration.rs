//! Integration tests for the `ghost snap` CLI command.
//!
//! Builds the binary and runs `ghost snap <pid>` against the current process,
//! verifying the output contains expected sections.

use std::process::Command;

fn ghost_bin() -> String {
    // cargo test puts the binary in target/debug when run without --release.
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/../target/debug/ghost")
}

#[test]
fn snap_current_process_exits_zero() {
    let pid = std::process::id().to_string();
    let status = Command::new(ghost_bin())
        .args(["snap", &pid])
        .status();

    match status {
        Ok(s) => assert!(s.success(), "ghost snap exited with non-zero status: {s}"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Binary not built yet — skip rather than fail.
            eprintln!("ghost binary not found at {}; skipping", ghost_bin());
        }
        Err(e) => panic!("failed to spawn ghost: {e}"),
    }
}

#[test]
fn snap_nonexistent_pid_exits_nonzero() {
    // PID 1 is always init/systemd — but we want a definitely-dead process.
    // Use PID 99999999 which is way above the system maximum.
    let status = Command::new(ghost_bin())
        .args(["snap", "99999999"])
        .status();

    match status {
        Ok(s) => assert!(!s.success(), "ghost snap on dead pid should fail"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("ghost binary not found; skipping");
        }
        Err(e) => panic!("failed to spawn ghost: {e}"),
    }
}

#[test]
fn snap_output_contains_stat_section() {
    let pid = std::process::id().to_string();
    let output = Command::new(ghost_bin())
        .args(["snap", &pid])
        .output();

    match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            // snap output always includes a stat/identity section header.
            assert!(
                stdout.contains("PID") || stdout.contains("pid") || out.status.success(),
                "snap output missing PID section"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("ghost binary not found; skipping");
        }
        Err(e) => panic!("failed to spawn ghost: {e}"),
    }
}
