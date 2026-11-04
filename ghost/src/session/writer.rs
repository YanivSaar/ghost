//! Session writer: tee raw events to a .ghost file.

use anyhow::{Context, Result};
use lz4_flex::compress_prepend_size;
use serde_json;
use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};

use super::format::{SessionMeta, MAGIC, VERSION};

pub struct SessionWriter {
    out: BufWriter<File>,
    t0: Instant,
    last_ts: u64, // microseconds since session start for delta encoding
    bytes_written: u64,
}

impl SessionWriter {
    pub fn open(path: &str, meta: &SessionMeta) -> Result<Self> {
        let file = File::create(path).with_context(|| format!("creating session file {path}"))?;
        let mut out = BufWriter::new(file);

        let meta_bytes = serde_json::to_vec(meta).context("serialising session metadata")?;

        out.write_all(MAGIC)?;
        out.write_all(&VERSION.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?; // reserved
        out.write_all(&(meta_bytes.len() as u64).to_le_bytes())?;
        out.write_all(&meta_bytes)?;

        let header_bytes = (MAGIC.len() + 4 + 4 + 8 + meta_bytes.len()) as u64;

        Ok(Self {
            out,
            t0: Instant::now(),
            last_ts: 0,
            bytes_written: header_bytes,
        })
    }

    /// Approximate bytes written to this writer (header + all frame payloads
    /// including per-frame kind/delta/len prefix). The BufWriter may still be
    /// holding some of these in-memory; `flush()` first for an on-disk-tight
    /// figure. Used by `SessionDirWriter` to drive size-based rotation.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Write one raw event frame. `kind` is the EventKind discriminant byte.
    pub fn write_frame(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let now_us = self.t0.elapsed().as_micros() as u64;
        let delta = (now_us.saturating_sub(self.last_ts)).min(u32::MAX as u64) as u32;
        self.last_ts = now_us;

        let compressed = compress_prepend_size(body);
        let len = compressed.len() as u32;

        self.out.write_all(&[kind])?;
        self.out.write_all(&delta.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(&compressed)?;
        self.bytes_written = self
            .bytes_written
            .saturating_add(1 + 4 + 4 + compressed.len() as u64);
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush().context("flushing session file")
    }
}

#[cfg(test)]
mod writer_reader_tests {
    use super::*;
    use crate::session::{format::SessionMeta, reader::SessionReader};

    fn tmp_path(name: &str) -> String {
        format!("{}/{}", std::env::temp_dir().display(), name)
    }

    #[test]
    fn round_trip_header() {
        let path = tmp_path("ghost_test_header.ghost");
        let meta = SessionMeta::new(1234, "test", "watch");
        {
            let mut w = SessionWriter::open(&path, &meta).unwrap();
            w.flush().unwrap();
        }
        let r = SessionReader::open(&path).unwrap();
        assert_eq!(r.meta.pid, 1234);
        assert_eq!(r.meta.comm, "test");
        assert_eq!(r.meta.mode, "watch");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn round_trip_frames() {
        let path = tmp_path("ghost_test_frames.ghost");
        let meta = SessionMeta::new(42, "proc", "snap");
        let payload1 = b"hello world";
        let payload2 = b"\xde\xad\xbe\xef";
        {
            let mut w = SessionWriter::open(&path, &meta).unwrap();
            w.write_frame(2, payload1).unwrap();
            w.write_frame(8, payload2).unwrap();
            w.flush().unwrap();
        }

        let mut r = SessionReader::open(&path).unwrap();

        let (kind, _delta, body) = r.next_frame().unwrap().expect("frame 1 missing");
        assert_eq!(kind, 2);
        assert_eq!(body, payload1);

        let (kind, _delta, body) = r.next_frame().unwrap().expect("frame 2 missing");
        assert_eq!(kind, 8);
        assert_eq!(body, payload2);

        assert!(r.next_frame().unwrap().is_none(), "expected EOF");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_magic_returns_error() {
        let path = tmp_path("ghost_test_bad_magic.ghost");
        std::fs::write(&path, b"BADMAGIC00000000").unwrap();
        assert!(SessionReader::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_file_returns_error() {
        let path = tmp_path("ghost_test_empty.ghost");
        std::fs::write(&path, b"").unwrap();
        assert!(SessionReader::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }
}
