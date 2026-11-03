//! Property-based round-trip tests for `SessionWriter → SessionReader`.
//!
//! For any randomly generated sequence of event frames, the reader must
//! yield exactly the same `(kind, body)` tuples in the same order; the
//! header round-trips its `SessionMeta` fields losslessly; and corrupt
//! headers never panic — they produce an `Err`.
//!
//! `PROPTEST_CASES` defaults to 256; CI can override with the env var.

use ghost::session::{format::SessionMeta, reader::SessionReader, writer::SessionWriter};
use proptest::prelude::*;

fn tmp_path(tag: &str) -> String {
    format!(
        "{}/ghost-proptest-{}-{}-{}.ghost",
        std::env::temp_dir().display(),
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    )
}

/// Pair of (kind_byte, body_bytes). Kinds are kept inside the real
/// discriminant range (1..=10, see `EventKind`) so the fuzz surface is
/// representative. Bodies are 0..512 bytes — long enough to exercise
/// LZ4 overhead, short enough to keep each run cheap.
fn frame_strategy() -> impl Strategy<Value = (u8, Vec<u8>)> {
    (1u8..=10, proptest::collection::vec(any::<u8>(), 0..512))
}

fn frames_strategy() -> impl Strategy<Value = Vec<(u8, Vec<u8>)>> {
    proptest::collection::vec(frame_strategy(), 0..32)
}

proptest! {
    /// For any legal frame stream, writer→reader yields the same stream.
    #[test]
    fn roundtrip_preserves_frames(frames in frames_strategy()) {
        let path = tmp_path("rt");
        let meta = SessionMeta::new(1234, "proptest", "watch");
        {
            let mut w = SessionWriter::open(&path, &meta).unwrap();
            for (kind, body) in &frames {
                w.write_frame(*kind, body).unwrap();
            }
            w.flush().unwrap();
        }

        let mut r = SessionReader::open(&path).unwrap();
        for (expected_kind, expected_body) in &frames {
            let (kind, _delta, body) = r
                .next_frame()
                .expect("read ok")
                .expect("frame present");
            prop_assert_eq!(kind, *expected_kind);
            prop_assert_eq!(body, expected_body.clone());
        }
        prop_assert!(r.next_frame().unwrap().is_none(), "expected EOF after all frames");

        let _ = std::fs::remove_file(&path);
    }

    /// Reader must not panic on arbitrary byte input. Any input either
    /// opens successfully (unlikely but legal for a well-formed prefix)
    /// or produces an Err.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let path = tmp_path("fuzz");
        std::fs::write(&path, &bytes).unwrap();

        // Catch any panic as a test failure rather than crashing the harness.
        let outcome = std::panic::catch_unwind(|| {
            if let Ok(mut r) = SessionReader::open(&path) {
                for _ in 0..64 {
                    match r.next_frame() {
                        Ok(Some(_)) => continue,
                        Ok(None) | Err(_) => break,
                    }
                }
            }
        });
        prop_assert!(outcome.is_ok(), "SessionReader panicked on {} bytes", bytes.len());

        let _ = std::fs::remove_file(&path);
    }

    /// Meta fields survive a round trip verbatim.
    #[test]
    fn meta_round_trips(
        pid in 1u32..=u32::MAX,
        comm in "[a-zA-Z0-9_-]{1,16}",
        mode in prop::sample::select(vec!["snap", "watch", "lock", "catch", "cold", "jitter", "tree", "cgroup"]),
    ) {
        let path = tmp_path("meta");
        let meta = SessionMeta::new(pid, comm.clone(), mode);
        {
            let mut w = SessionWriter::open(&path, &meta).unwrap();
            w.flush().unwrap();
        }
        let r = SessionReader::open(&path).unwrap();
        prop_assert_eq!(r.meta.pid, pid);
        prop_assert_eq!(r.meta.comm, comm);
        prop_assert_eq!(r.meta.mode, mode);

        let _ = std::fs::remove_file(&path);
    }
}
