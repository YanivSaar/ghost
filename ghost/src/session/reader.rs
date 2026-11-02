//! Session reader: sequential playback of a .ghost file.

use anyhow::{bail, Context, Result};
use lz4_flex::decompress_size_prepended;
use serde_json;
use std::{
    fs::File,
    io::{BufReader, Read},
};

use super::format::{SessionMeta, MAGIC, VERSION};

// Session files come from other machines / untrusted sources. Clamp the
// per-field allocations we're willing to make from a header's size word
// so a corrupted or hostile file can't demand gigabytes before we even
// see any data.
const MAX_META_LEN: usize = 1 << 20; // 1 MiB JSON header
const MAX_FRAME_LEN: usize = 64 << 20; // 64 MiB per compressed frame

pub struct SessionReader {
    inner: BufReader<File>,
    pub meta: SessionMeta,
}

impl SessionReader {
    pub fn open(path: &str) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("opening session file {path}"))?;
        let mut r = BufReader::new(file);

        let mut magic = [0u8; 8];
        r.read_exact(&mut magic)?;
        if &magic != MAGIC {
            bail!("{path}: not a ghost session file (bad magic)");
        }

        let mut ver_bytes = [0u8; 4];
        r.read_exact(&mut ver_bytes)?;
        let ver = u32::from_le_bytes(ver_bytes);
        if ver != VERSION {
            bail!("{path}: unsupported version {ver}");
        }

        let mut _reserved = [0u8; 4];
        r.read_exact(&mut _reserved)?;

        let mut meta_len_bytes = [0u8; 8];
        r.read_exact(&mut meta_len_bytes)?;
        let meta_len = u64::from_le_bytes(meta_len_bytes) as usize;
        if meta_len > MAX_META_LEN {
            bail!("{path}: metadata length {meta_len} exceeds {MAX_META_LEN}");
        }

        let mut meta_bytes = vec![0u8; meta_len];
        r.read_exact(&mut meta_bytes)?;
        let meta: SessionMeta =
            serde_json::from_slice(&meta_bytes).context("deserialising session metadata")?;

        Ok(Self { inner: r, meta })
    }

    /// Read the next frame. Returns `(kind, ts_delta_us, raw_body)` or None at EOF.
    pub fn next_frame(&mut self) -> Result<Option<(u8, u32, Vec<u8>)>> {
        let mut header = [0u8; 9]; // kind(1) + ts_delta(4) + len(4)
        match self.inner.read_exact(&mut header) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let kind = header[0];
        let ts_delta = u32::from_le_bytes(header[1..5].try_into().unwrap());
        let clen = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        if clen > MAX_FRAME_LEN {
            bail!("session frame length {clen} exceeds {MAX_FRAME_LEN}");
        }

        let mut compressed = vec![0u8; clen];
        self.inner.read_exact(&mut compressed)?;
        let body = decompress_size_prepended(&compressed).context("decompressing frame body")?;

        Ok(Some((kind, ts_delta, body)))
    }
}
