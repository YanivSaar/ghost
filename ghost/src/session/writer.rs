//! Session writer: tee raw events to a .ghost file.

use std::{
    fs::File,
    io::{BufWriter, Write},
    time::Instant,
};
use anyhow::{Context, Result};
use lz4_flex::compress_prepend_size;
use serde_json;

use super::format::{MAGIC, VERSION, SessionMeta};

pub struct SessionWriter {
    out:      BufWriter<File>,
    t0:       Instant,
    last_ts:  u64,   // microseconds since session start for delta encoding
}

impl SessionWriter {
    pub fn open(path: &str, meta: &SessionMeta) -> Result<Self> {
        let file = File::create(path)
            .with_context(|| format!("creating session file {path}"))?;
        let mut out = BufWriter::new(file);

        let meta_bytes = serde_json::to_vec(meta).context("serialising session metadata")?;

        out.write_all(MAGIC)?;
        out.write_all(&VERSION.to_le_bytes())?;
        out.write_all(&0u32.to_le_bytes())?;             // reserved
        out.write_all(&(meta_bytes.len() as u64).to_le_bytes())?;
        out.write_all(&meta_bytes)?;

        Ok(Self { out, t0: Instant::now(), last_ts: 0 })
    }

    /// Write one raw event frame. `kind` is the EventKind discriminant byte.
    pub fn write_frame(&mut self, kind: u8, body: &[u8]) -> Result<()> {
        let now_us = self.t0.elapsed().as_micros() as u64;
        let delta  = (now_us.saturating_sub(self.last_ts)).min(u32::MAX as u64) as u32;
        self.last_ts = now_us;

        let compressed = compress_prepend_size(body);
        let len = compressed.len() as u32;

        self.out.write_all(&[kind])?;
        self.out.write_all(&delta.to_le_bytes())?;
        self.out.write_all(&len.to_le_bytes())?;
        self.out.write_all(&compressed)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        self.out.flush().context("flushing session file")
    }
}
