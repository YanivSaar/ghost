//! Fuzz the `.ghost` session reader against arbitrary bytes.
//!
//! Session files come from other machines (and the `--record` path can
//! produce them locally for later `ghost replay / diff`), so the reader
//! is the one meaningful untrusted-input entry point in the tool. The
//! bounds added in the stability PR (`MAX_META_LEN`, `MAX_FRAME_LEN`)
//! and the magic/version checks must hold against *any* byte string.
//!
//! The property is: no input causes a panic, abort, or unbounded
//! allocation — any malformed file must land on an `Err` or an `Ok(None)`
//! at EOF.
//!
//! Run with:
//!     cargo +nightly fuzz run session_reader
//!
//! Seed corpus: drop a few real `.ghost` recordings into
//! `fuzz/corpus/session_reader/` before the first run.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::io::Write;

use ghost::session::reader::SessionReader;

fuzz_target!(|data: &[u8]| {
    // Write the fuzzer input to a tempfile; the reader is path-based.
    let dir = std::env::temp_dir().join("ghost-fuzz-sessions");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(format!("fuzz-{:x}.ghost", std::process::id()));
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = f.write_all(data);
        let _ = f.flush();
    } else {
        return;
    }

    // Open + drain every frame. Any panic / abort fails the fuzz run.
    if let Ok(mut r) = SessionReader::open(path.to_str().unwrap()) {
        // Cap at 10 000 frames so a legitimately huge legit file still
        // terminates. A real-world replay is bounded by file size anyway.
        for _ in 0..10_000 {
            match r.next_frame() {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    let _ = std::fs::remove_file(&path);
});
