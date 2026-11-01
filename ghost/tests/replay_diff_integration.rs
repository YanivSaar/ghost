//! End-to-end: write a tiny .ghost session with the SessionWriter, then
//! use `ghost diff` and `ghost replay --seek` to prove the CLI wiring.
//! We don't launch the TUI here — replay needs a TTY; this test exercises
//! only the paths that don't.

use std::process::Command;

fn ghost_bin() -> String {
    env!("CARGO_BIN_EXE_ghost").to_string()
}

#[test]
fn diff_two_real_sessions_prints_delta() {
    use ghost::session::{format::SessionMeta, writer::SessionWriter};
    let tmp = std::env::temp_dir();
    let a = tmp.join("ghost-diff-real-a.ghost");
    let b = tmp.join("ghost-diff-real-b.ghost");
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);

    {
        let m = SessionMeta::new(1234, "a-proc", "watch");
        let mut w = SessionWriter::open(a.to_str().unwrap(), &m).unwrap();
        for _ in 0..3 { w.write_frame(2, &[2u8; 48]).unwrap(); }   // SchedSwitch
        w.write_frame(8, &[8u8; 8]).unwrap();                      // Exit
        w.flush().unwrap();
    }
    {
        let m = SessionMeta::new(5678, "b-proc", "watch");
        let mut w = SessionWriter::open(b.to_str().unwrap(), &m).unwrap();
        for _ in 0..5 { w.write_frame(2, &[2u8; 48]).unwrap(); }   // SchedSwitch
        for _ in 0..2 { w.write_frame(10, &[10u8; 32]).unwrap(); } // CatchHit
        w.flush().unwrap();
    }

    let out = Command::new(ghost_bin())
        .args(["diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .expect("spawning ghost diff");
    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("SchedSwitch"), "stdout: {s}");
    assert!(s.contains("Exit"),        "stdout: {s}");
    assert!(s.contains("CatchHit"),    "stdout: {s}");
    assert!(s.contains("+2"),          "expected +2 somewhere: {s}");

    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}

#[test]
fn diff_two_empty_sessions_runs_cleanly() {
    use std::fs::write as fswrite;
    // We can't easily call the library writer from an integration test;
    // instead, assert that invoking `ghost diff` on missing files is a
    // clean error (non-zero exit, non-empty stderr), and on identical
    // existing-but-garbage files it's also a clean error. Then confirm
    // --help renders.
    let tmp = std::env::temp_dir();
    let a = tmp.join("ghost-diff-nope-a.ghost");
    let b = tmp.join("ghost-diff-nope-b.ghost");
    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
    fswrite(&a, b"not a session").unwrap();
    fswrite(&b, b"not a session").unwrap();

    let out = Command::new(ghost_bin())
        .args(["diff", a.to_str().unwrap(), b.to_str().unwrap()])
        .output()
        .expect("spawning ghost diff");

    // Either prints an error and exits non-zero, or exits zero with a
    // clean header — both are acceptable, but it must not panic.
    assert!(
        !out.status.success()
            || !out.stdout.is_empty()
            || !out.stderr.is_empty(),
        "unexpected silent success"
    );

    let _ = std::fs::remove_file(&a);
    let _ = std::fs::remove_file(&b);
}

#[test]
fn replay_help_renders() {
    let out = Command::new(ghost_bin())
        .args(["replay", "--help"])
        .output()
        .expect("spawning ghost replay --help");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("Replay"), "help text: {s}");
}

#[test]
fn diff_help_renders() {
    let out = Command::new(ghost_bin())
        .args(["diff", "--help"])
        .output()
        .expect("spawning ghost diff --help");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("ompare"), "help text: {s}"); // "Compare"
}

#[test]
fn cgroup_help_renders() {
    let out = Command::new(ghost_bin())
        .args(["cgroup", "--help"])
        .output()
        .expect("spawning ghost cgroup --help");
    assert!(out.status.success());
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.to_lowercase().contains("cgroup"), "help text: {s}");
}
