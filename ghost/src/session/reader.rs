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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{format::SessionMeta, writer::SessionWriter};
    use proptest::prelude::*;

    fn tmp(name: &str) -> String {
        format!("{}/{}", std::env::temp_dir().display(), name)
    }

    #[test]
    fn malformed_meta_length_rejected() {
        // Craft a header with meta_len = MAX_META_LEN + 1 → must error.
        let path = tmp("ghost_rdr_bad_meta.ghost");
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&((MAX_META_LEN + 1) as u64).to_le_bytes());
        std::fs::write(&path, &buf).unwrap();
        assert!(SessionReader::open(&path).is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_frame_length_rejected_on_read() {
        // Valid header + one frame with clen = MAX_FRAME_LEN + 1.
        let path = tmp("ghost_rdr_bad_frame.ghost");
        let meta = SessionMeta::new(1, "x", "watch");
        {
            let mut w = SessionWriter::open(&path, &meta).unwrap();
            w.flush().unwrap();
        }
        // Append a fake frame header pointing at a huge body.
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(&[1u8]).unwrap(); // kind
        f.write_all(&0u32.to_le_bytes()).unwrap(); // ts_delta
        f.write_all(&((MAX_FRAME_LEN + 1) as u32).to_le_bytes())
            .unwrap();
        drop(f);
        let mut r = SessionReader::open(&path).unwrap();
        assert!(r.next_frame().is_err());
        let _ = std::fs::remove_file(&path);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn round_trip_random_frames(frames in proptest::collection::vec(
            (0u8..=10, proptest::collection::vec(any::<u8>(), 0..256)),
            0..32)) {
            let path = tmp("ghost_rdr_rt.ghost");
            let meta = SessionMeta::new(1, "rt", "watch");
            {
                let mut w = SessionWriter::open(&path, &meta).unwrap();
                for (k, body) in &frames {
                    w.write_frame(*k, body).unwrap();
                }
                w.flush().unwrap();
            }
            let mut r = SessionReader::open(&path).unwrap();
            for (expect_k, expect_body) in &frames {
                let (k, _d, body) = r.next_frame().unwrap().expect("frame");
                prop_assert_eq!(k, *expect_k);
                prop_assert_eq!(body, expect_body.clone());
            }
            prop_assert!(r.next_frame().unwrap().is_none());
            let _ = std::fs::remove_file(&path);
        }
    }
}
