//! Integration tests for `ebpf::consumer::dispatch_event` /
//! `dispatch_capture` — the ring-buffer unmarshal path.
//!
//! Each dispatcher takes a raw byte slice (first byte = `EventKind`) and
//! applies the record to `AppState` via `unsafe { read_unaligned }`.
//! The property we lock down here is: *any* undersized / wrong-kind /
//! junk bytes must result in `AppState` being either unchanged or
//! updated only for the matching path — never a panic, never an OOB
//! read, never a wrong field in state.

use std::sync::{Arc, RwLock};

use ghost::ebpf::consumer::{dispatch_capture, dispatch_event};
use ghost::state::AppState;
use ghost_common::{CatchRecord, EventKind, ExitRecord, SchedSwitchRecord};

fn fresh_state(pid: u32) -> Arc<RwLock<AppState>> {
    Arc::new(RwLock::new(AppState::new(pid, "test".into())))
}

fn as_bytes<T: Copy>(v: &T) -> Vec<u8> {
    let p = v as *const T as *const u8;
    let n = std::mem::size_of::<T>();
    unsafe { std::slice::from_raw_parts(p, n) }.to_vec()
}

// ── dispatch_event ──────────────────────────────────────────────────────────

#[test]
fn sched_switch_voluntary_increments_voluntary_ctx() {
    let st = fresh_state(1);
    let rec = SchedSwitchRecord {
        kind: EventKind::SchedSwitch as u8,
        involuntary: 0,
        _pad: [0; 2],
        pid: 1,
        tid: 1,
        _pad2: 0,
        ts_ns: 100,
        next_pid: 2,
        _pad3: 0,
        next_comm: [0; 16],
    };
    dispatch_event(&as_bytes(&rec), &st);
    let s = st.read().unwrap();
    assert_eq!(s.watch.voluntary_ctx, 1);
    assert_eq!(s.watch.involuntary_ctx, 0);
}

#[test]
fn sched_switch_involuntary_increments_involuntary_ctx() {
    let st = fresh_state(1);
    let rec = SchedSwitchRecord {
        kind: EventKind::SchedSwitch as u8,
        involuntary: 1,
        _pad: [0; 2],
        pid: 1,
        tid: 1,
        _pad2: 0,
        ts_ns: 100,
        next_pid: 2,
        _pad3: 0,
        next_comm: [0; 16],
    };
    dispatch_event(&as_bytes(&rec), &st);
    let s = st.read().unwrap();
    assert_eq!(s.watch.involuntary_ctx, 1);
    assert_eq!(s.watch.voluntary_ctx, 0);
}

#[test]
fn exit_matching_pid_sets_target_gone() {
    let st = fresh_state(42);
    let rec = ExitRecord {
        kind: EventKind::Exit as u8,
        _pad: [0; 3],
        pid: 42,
    };
    dispatch_event(&as_bytes(&rec), &st);
    assert!(st.read().unwrap().target_gone);
}

#[test]
fn exit_mismatched_pid_leaves_target_present() {
    let st = fresh_state(42);
    let rec = ExitRecord {
        kind: EventKind::Exit as u8,
        _pad: [0; 3],
        pid: 1234, // not our pid
    };
    dispatch_event(&as_bytes(&rec), &st);
    assert!(!st.read().unwrap().target_gone);
}

#[test]
fn empty_bytes_is_a_noop() {
    let st = fresh_state(1);
    dispatch_event(&[], &st);
    dispatch_capture(&[], &st);
    let s = st.read().unwrap();
    assert_eq!(s.watch.voluntary_ctx, 0);
    assert_eq!(s.watch.involuntary_ctx, 0);
    assert!(!s.target_gone);
    assert_eq!(s.catch.total_hits, 0);
}

#[test]
fn unknown_kind_is_a_noop() {
    let st = fresh_state(1);
    // Byte 0xFF — not any defined EventKind.
    let junk = [0xFFu8; 64];
    dispatch_event(&junk, &st);
    dispatch_capture(&junk, &st);
    let s = st.read().unwrap();
    assert_eq!(s.watch.voluntary_ctx, 0);
    assert_eq!(s.watch.involuntary_ctx, 0);
    assert!(!s.target_gone);
    assert_eq!(s.catch.total_hits, 0);
}

#[test]
fn undersized_sched_switch_is_a_noop() {
    let st = fresh_state(1);
    // Just the kind byte + one extra, well under size_of::<SchedSwitchRecord>.
    let short = [EventKind::SchedSwitch as u8, 0u8];
    dispatch_event(&short, &st);
    let s = st.read().unwrap();
    assert_eq!(s.watch.voluntary_ctx, 0);
    assert_eq!(s.watch.involuntary_ctx, 0);
}

#[test]
fn undersized_exit_is_a_noop() {
    let st = fresh_state(42);
    let short = [EventKind::Exit as u8, 0u8, 0u8];
    dispatch_event(&short, &st);
    assert!(!st.read().unwrap().target_gone);
}

// ── dispatch_capture ────────────────────────────────────────────────────────

#[test]
fn capture_hit_appends_to_recent_hits() {
    let st = fresh_state(7);
    let rec = CatchRecord {
        kind: EventKind::CatchHit as u8,
        _pad: [0; 3],
        pid: 7,
        tid: 7,
        nr: 1, // write
        ts_ns: 500,
        delta_ns: 10_000_000, // 10 ms
    };
    dispatch_capture(&as_bytes(&rec), &st);
    let s = st.read().unwrap();
    assert_eq!(s.catch.total_hits, 1);
    assert_eq!(s.catch.max_delta_ns, 10_000_000);
    assert_eq!(s.catch.recent_hits.len(), 1);
    assert_eq!(s.catch.recent_hits[0].delta_ns, 10_000_000);
    assert_eq!(s.catch.recent_hits[0].nr, 1);
}

#[test]
fn capture_wrong_kind_is_a_noop() {
    let st = fresh_state(7);
    // Build what *looks* like a CatchRecord but mark it as SchedSwitch instead.
    let mut rec = CatchRecord {
        kind: EventKind::SchedSwitch as u8, // deliberately wrong
        _pad: [0; 3],
        pid: 7,
        tid: 7,
        nr: 1,
        ts_ns: 500,
        delta_ns: 10_000_000,
    };
    rec.kind = EventKind::SchedSwitch as u8;
    dispatch_capture(&as_bytes(&rec), &st);
    assert_eq!(st.read().unwrap().catch.total_hits, 0);
}

#[test]
fn capture_undersized_is_a_noop() {
    let st = fresh_state(7);
    let short = [EventKind::CatchHit as u8, 0, 0, 0];
    dispatch_capture(&short, &st);
    assert_eq!(st.read().unwrap().catch.total_hits, 0);
}
