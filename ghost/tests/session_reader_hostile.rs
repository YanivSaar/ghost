//! Hostile-input integration tests for `SessionReader`.
//!
//! The session reader is the only untrusted-input entry point in the
//! tool: a `.ghost` file handed to `ghost replay` / `ghost diff` is
//! arbitrary bytes. These tests exercise every rejection path:
//!   * bad magic
//!   * unsupported version
//!   * oversized `meta_len` (above `MAX_META_LEN = 1 MiB`)
//!   * oversized `clen` (above `MAX_FRAME_LEN = 64 MiB`)
//!   * truncated meta
//!   * truncated frame header
//!   * truncated frame body
//!   * valid header, invalid JSON meta
//!   * valid header + valid meta, corrupt LZ4 frame body

use ghost::session::reader::SessionReader;
use std::io::Write;

const MAGIC: &[u8; 8] = b"GHOST000";
const VERSION: u32 = 1;

fn tmp(tag: &str) -> String {
    format!(
        "{}/ghost-hostile-{}-{}-{}.ghost",
        std::env::temp_dir().display(),
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    )
}

fn write_file(path: &str, bytes: &[u8]) {
    let mut f = std::fs::File::create(path).unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
}

#[test]
fn open_nonexistent_errors() {
    let r = SessionReader::open("/this/does/not/exist/for/ghost/test.ghost");
    assert!(r.is_err(), "nonexistent file must error");
}

#[test]
fn bad_magic_rejected() {
    let p = tmp("badmagic");
    // Right length but wrong magic.
    write_file(
        &p,
        b"NOTGHOST\x01\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00{}",
    );
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "bad magic must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn unsupported_version_rejected() {
    let p = tmp("badver");
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&999u32.to_le_bytes()); // bad version
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&0u64.to_le_bytes()); // meta_len
    write_file(&p, &buf);
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "unsupported version must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn oversized_meta_len_rejected() {
    let p = tmp("bigmeta");
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
                                                // 2 MiB (above MAX_META_LEN = 1 MiB)
    buf.extend_from_slice(&(2u64 * 1024 * 1024).to_le_bytes());
    write_file(&p, &buf);
    let r = SessionReader::open(&p);
    assert!(
        r.is_err(),
        "oversized meta_len must error without allocating"
    );
    let msg = format!("{:#}", r.err().unwrap());
    assert!(
        msg.contains("exceeds") || msg.contains("length"),
        "error should mention the length cap: {msg}"
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn truncated_meta_rejected() {
    let p = tmp("truncmeta");
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&64u64.to_le_bytes()); // claim 64 bytes of meta
    buf.extend_from_slice(&[0u8; 32]); // but only provide 32
    write_file(&p, &buf);
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "truncated meta must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn invalid_json_meta_rejected() {
    let p = tmp("badjson");
    let garbage = b"\xff\xff\xff\xff\xff\xff\xff\xff";
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&(garbage.len() as u64).to_le_bytes());
    buf.extend_from_slice(garbage);
    write_file(&p, &buf);
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "invalid JSON meta must error");
    let _ = std::fs::remove_file(&p);
}

/// Build a well-formed header + minimal valid JSON meta, so the opener
/// succeeds. Returns the serialised prefix.
fn valid_header_prefix() -> Vec<u8> {
    let meta = br#"{"pid":1,"comm":"t","mode":"watch","start_ns":1,"hostname":"h"}"#;
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&VERSION.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes()); // reserved
    buf.extend_from_slice(&(meta.len() as u64).to_le_bytes());
    buf.extend_from_slice(meta);
    buf
}

#[test]
fn well_formed_header_then_eof_is_fine() {
    let p = tmp("ok_hdr");
    write_file(&p, &valid_header_prefix());
    let mut r = SessionReader::open(&p).expect("header should parse");
    assert!(r.next_frame().unwrap().is_none(), "no frames = EOF");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn oversized_clen_rejected() {
    let p = tmp("bigclen");
    let mut buf = valid_header_prefix();
    // Frame header: kind(1) + ts_delta(4) + len(4). Set len > 64 MiB.
    buf.push(2u8);
    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_delta
    buf.extend_from_slice(&(128u32 * 1024 * 1024).to_le_bytes()); // 128 MiB > 64 MiB
    write_file(&p, &buf);
    let mut r = SessionReader::open(&p).expect("header should parse");
    let n = r.next_frame();
    assert!(n.is_err(), "oversized clen must error without allocating");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn truncated_frame_header_errors_or_eof() {
    let p = tmp("truncfhdr");
    let mut buf = valid_header_prefix();
    // Provide only 5 bytes of the 9-byte frame header.
    buf.extend_from_slice(&[1u8, 0, 0, 0, 0]);
    write_file(&p, &buf);
    let mut r = SessionReader::open(&p).expect("header should parse");
    let n = r.next_frame();
    // Reader may surface this as an Err (unexpected EOF mid-header) or
    // as Ok(None) (EOF classified as end-of-stream); either is correct
    // so long as it doesn't panic and doesn't claim a frame.
    match &n {
        Ok(None) | Err(_) => {}
        Ok(Some(_)) => panic!("truncated frame header must not yield a frame, got {n:?}"),
    }
    let _ = std::fs::remove_file(&p);
}

#[test]
fn truncated_frame_body_errors() {
    let p = tmp("truncfbody");
    let mut buf = valid_header_prefix();
    // Frame header claims 64 compressed bytes, but we provide only 16.
    buf.push(2u8);
    buf.extend_from_slice(&0u32.to_le_bytes()); // ts_delta
    buf.extend_from_slice(&64u32.to_le_bytes()); // claim 64 bytes
    buf.extend_from_slice(&[0u8; 16]);
    write_file(&p, &buf);
    let mut r = SessionReader::open(&p).expect("header should parse");
    let n = r.next_frame();
    assert!(n.is_err(), "truncated frame body must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn corrupt_lz4_frame_body_errors() {
    let p = tmp("badlz4");
    let mut buf = valid_header_prefix();
    // Frame of plausible length (16 bytes of zeros is not valid LZ4
    // size-prepended output).
    buf.push(2u8);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&[0u8; 16]);
    write_file(&p, &buf);
    let mut r = SessionReader::open(&p).expect("header should parse");
    let n = r.next_frame();
    assert!(n.is_err(), "corrupt LZ4 body must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn empty_file_rejected() {
    let p = tmp("empty");
    write_file(&p, b"");
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "empty file must error");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn magic_only_prefix_rejected() {
    let p = tmp("magiconly");
    write_file(&p, MAGIC);
    let r = SessionReader::open(&p);
    assert!(r.is_err(), "magic without version/meta must error");
    let _ = std::fs::remove_file(&p);
}
