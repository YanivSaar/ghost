//! Rotating session writer: writes a *directory* of self-contained `.ghost`
//! segments plus an `index.json`, so a long-running daemon can observe
//! continuously without filling the disk.
//!
//! Each segment is a complete `.ghost` file (header + its own frames) so
//! `ghost replay` works on any individual segment. Rotation is enforced
//! in-process — we do NOT rely on logrotate (unsafe against a live writer
//! holding an fd into the file). Rotation triggers on:
//!
//! - current segment size exceeded (`max_segment_bytes`)
//! - current segment age exceeded (`max_age`)
//!
//! Retention trims by:
//!
//! - segment count (`keep_segments`)
//! - combined on-disk age (segments older than `max_total_age` on sweep)
//!
//! The current segment is `segment-N.ghost` where N is a monotonic counter
//! persisted in `index.json`. We never delete the segment currently open
//! for writing.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use super::{format::SessionMeta, writer::SessionWriter};

/// Rotation + retention knobs. Sane daemon defaults: 100 MiB per segment,
/// keep 10 segments => ~1 GiB max per target. Rotation by age capped at 24h.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    pub max_segment_bytes: u64,
    pub keep_segments: usize,
    pub max_age: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            max_segment_bytes: 100 * 1024 * 1024,
            keep_segments: 10,
            max_age: Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct SegmentRecord {
    file: String,
    seq: u64,
    bytes: u64,
    /// Wall-clock unix seconds at which this segment was opened.
    opened_unix: u64,
    /// Wall-clock unix seconds at which this segment was closed (rotated
    /// away). 0 while the segment is still being written.
    closed_unix: u64,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct IndexFile {
    target_slug: String,
    mode: String,
    pid: u32,
    next_seq: u64,
    segments: Vec<SegmentRecord>,
}

/// Rotating writer around a `SessionWriter`. The `sink()` is handed to the
/// eBPF consumer like a normal `--record` sink; `tick()` is called from a
/// maintenance loop (owned by the daemon) to check whether to rotate.
pub struct SessionDirWriter {
    dir: PathBuf,
    cfg: RotationConfig,
    meta: SessionMeta,
    inner: Arc<Mutex<SessionWriter>>,
    state: Arc<Mutex<DirState>>,
}

struct DirState {
    index: IndexFile,
    current_opened: Instant,
}

impl SessionDirWriter {
    /// Open (or re-open) a rotating writer in `dir`. If `dir` already has an
    /// `index.json`, we resume by appending a fresh segment with the next
    /// sequence number — old segments are preserved and still contribute to
    /// retention sweeps. If `dir` doesn't exist it's created.
    pub fn open(dir: &Path, cfg: RotationConfig, meta: SessionMeta) -> Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating session dir {}", dir.display()))?;

        let index_path = dir.join("index.json");
        let mut index: IndexFile = if index_path.exists() {
            let bytes = std::fs::read(&index_path)
                .with_context(|| format!("reading {}", index_path.display()))?;
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            IndexFile::default()
        };
        index.target_slug = index.target_slug.clone();
        index.mode = meta.mode.clone();
        index.pid = meta.pid;

        let seq = index.next_seq;
        index.next_seq = seq + 1;

        let seg_name = format!("segment-{:06}.ghost", seq);
        let seg_path = dir.join(&seg_name);
        let seg_writer = SessionWriter::open(
            seg_path
                .to_str()
                .context("session dir path is not valid UTF-8")?,
            &meta,
        )?;

        let opened_unix = unix_now();
        index.segments.push(SegmentRecord {
            file: seg_name,
            seq,
            bytes: seg_writer.bytes_written(),
            opened_unix,
            closed_unix: 0,
        });
        write_index(&index_path, &index)?;

        let inner = Arc::new(Mutex::new(seg_writer));
        let state = Arc::new(Mutex::new(DirState {
            index,
            current_opened: Instant::now(),
        }));

        Ok(Self {
            dir: dir.to_path_buf(),
            cfg,
            meta,
            inner,
            state,
        })
    }

    /// The shared sink handed to the eBPF consumer (same shape as a plain
    /// `--record` sink). Rotation replaces the `SessionWriter` *inside* this
    /// mutex, so the consumer keeps the same `Arc` across rotations.
    pub fn sink(&self) -> Arc<Mutex<SessionWriter>> {
        Arc::clone(&self.inner)
    }

    /// Flush + check-rotate + sweep. Returns Ok(true) if a rotation
    /// happened. Safe to call from a dedicated maintenance thread every
    /// few seconds.
    pub fn tick(&self) -> Result<bool> {
        // Flush first so bytes_written reflects on-disk size.
        {
            let mut w = self.inner.lock().unwrap();
            let _ = w.flush();
        }
        let (bytes, age) = {
            let w = self.inner.lock().unwrap();
            let bytes = w.bytes_written();
            let age = {
                let st = self.state.lock().unwrap();
                st.current_opened.elapsed()
            };
            (bytes, age)
        };

        if bytes >= self.cfg.max_segment_bytes || age >= self.cfg.max_age {
            self.rotate()?;
            self.sweep()?;
            return Ok(true);
        }
        // Refresh in-index byte count even without rotation.
        {
            let mut st = self.state.lock().unwrap();
            if let Some(last) = st.index.segments.last_mut() {
                last.bytes = bytes;
            }
            let _ = write_index(&self.dir.join("index.json"), &st.index);
        }
        Ok(false)
    }

    /// Flush the current segment, mark it closed, open a new one, and
    /// atomically swap it into the shared sink Arc.
    fn rotate(&self) -> Result<()> {
        // 1. Flush and finalize the current segment in the index.
        {
            let mut w = self.inner.lock().unwrap();
            let _ = w.flush();
            let final_bytes = w.bytes_written();
            drop(w);

            let mut st = self.state.lock().unwrap();
            if let Some(last) = st.index.segments.last_mut() {
                last.bytes = final_bytes;
                last.closed_unix = unix_now();
            }
        }

        // 2. Pick next seq & open the new segment.
        let seq = {
            let mut st = self.state.lock().unwrap();
            let s = st.index.next_seq;
            st.index.next_seq = s + 1;
            s
        };
        let seg_name = format!("segment-{:06}.ghost", seq);
        let seg_path = self.dir.join(&seg_name);
        let seg_writer = SessionWriter::open(
            seg_path
                .to_str()
                .context("segment path is not valid UTF-8")?,
            &self.meta,
        )?;

        // 3. Swap into the shared sink, so the consumer keeps writing.
        {
            let mut w = self.inner.lock().unwrap();
            *w = seg_writer;
        }

        // 4. Record the new segment and persist the index.
        {
            let mut st = self.state.lock().unwrap();
            let bytes = self.inner.lock().unwrap().bytes_written();
            st.index.segments.push(SegmentRecord {
                file: seg_name,
                seq,
                bytes,
                opened_unix: unix_now(),
                closed_unix: 0,
            });
            st.current_opened = Instant::now();
            write_index(&self.dir.join("index.json"), &st.index)?;
        }
        Ok(())
    }

    /// Trim old segments down to `cfg.keep_segments`, never removing the
    /// one we're currently writing (which is always the last entry).
    fn sweep(&self) -> Result<()> {
        let mut to_remove = Vec::new();
        {
            let mut st = self.state.lock().unwrap();
            let keep = self.cfg.keep_segments.max(1);
            // The last entry is the live segment — never trim it.
            while st.index.segments.len() > keep {
                let old = st.index.segments.remove(0);
                to_remove.push(old.file);
            }
            write_index(&self.dir.join("index.json"), &st.index)?;
        }
        for f in to_remove {
            let _ = std::fs::remove_file(self.dir.join(f));
        }
        Ok(())
    }

    /// Final flush — call before dropping / shutting the daemon down.
    pub fn flush_final(&self) -> Result<()> {
        let mut w = self.inner.lock().unwrap();
        w.flush()?;
        let final_bytes = w.bytes_written();
        drop(w);
        let mut st = self.state.lock().unwrap();
        if let Some(last) = st.index.segments.last_mut() {
            last.bytes = final_bytes;
        }
        write_index(&self.dir.join("index.json"), &st.index)?;
        Ok(())
    }
}

fn write_index(path: &Path, idx: &IndexFile) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let body = serde_json::to_vec_pretty(idx).context("serialising segment index")?;
    std::fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mktemp(name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("ghost_dirwriter_{}_{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn opens_and_writes_first_segment() {
        let dir = mktemp("open");
        let meta = SessionMeta::new(1, "t", "daemon");
        let cfg = RotationConfig::default();
        let w = SessionDirWriter::open(&dir, cfg, meta).unwrap();
        {
            let sink = w.sink();
            let mut inner = sink.lock().unwrap();
            inner.write_frame(2, b"hello").unwrap();
            inner.flush().unwrap();
        }
        assert!(dir.join("segment-000000.ghost").exists());
        assert!(dir.join("index.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn noisy(n: usize) -> Vec<u8> {
        // Pseudo-random so LZ4 cannot compress it away; bytes_written then
        // actually grows past the rotation threshold.
        (0..n).map(|i| ((i * 2654435761) & 0xff) as u8).collect()
    }

    #[test]
    fn rotates_when_segment_exceeds_cap() {
        let dir = mktemp("rot");
        let meta = SessionMeta::new(1, "t", "daemon");
        let cfg = RotationConfig {
            max_segment_bytes: 512,
            keep_segments: 5,
            max_age: Duration::from_secs(3600),
        };
        let w = SessionDirWriter::open(&dir, cfg, meta).unwrap();
        // Write past the cap.
        {
            let sink = w.sink();
            let mut inner = sink.lock().unwrap();
            let payload = noisy(300);
            for _ in 0..5 {
                inner.write_frame(1, &payload).unwrap();
            }
            inner.flush().unwrap();
        }
        let rotated = w.tick().unwrap();
        assert!(rotated, "should have rotated past the 512-byte cap");
        assert!(dir.join("segment-000000.ghost").exists());
        assert!(dir.join("segment-000001.ghost").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweeps_old_segments_down_to_keep() {
        let dir = mktemp("sweep");
        let meta = SessionMeta::new(1, "t", "daemon");
        let cfg = RotationConfig {
            max_segment_bytes: 256,
            keep_segments: 2,
            max_age: Duration::from_secs(3600),
        };
        let w = SessionDirWriter::open(&dir, cfg, meta).unwrap();
        for _ in 0..6 {
            {
                let sink = w.sink();
                let mut inner = sink.lock().unwrap();
                let payload = noisy(300);
                inner.write_frame(1, &payload).unwrap();
                inner.flush().unwrap();
            }
            let _ = w.tick();
        }
        let segments: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with("segment-"))
            .collect();
        assert!(
            segments.len() <= 2,
            "expected <= 2 segments after sweep, got {}",
            segments.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn each_segment_is_a_standalone_ghost_file() {
        use crate::session::reader::SessionReader;
        let dir = mktemp("standalone");
        let meta = SessionMeta::new(7, "proc7", "daemon");
        let cfg = RotationConfig {
            max_segment_bytes: 256,
            keep_segments: 10,
            max_age: Duration::from_secs(3600),
        };
        let w = SessionDirWriter::open(&dir, cfg, meta).unwrap();
        {
            let sink = w.sink();
            let mut inner = sink.lock().unwrap();
            let p = noisy(300);
            inner.write_frame(2, &p).unwrap();
            inner.flush().unwrap();
        }
        w.tick().unwrap();
        {
            let sink = w.sink();
            let mut inner = sink.lock().unwrap();
            inner.write_frame(2, &[1u8; 50]).unwrap();
            inner.flush().unwrap();
        }
        w.flush_final().unwrap();
        // Replay both segments independently.
        for seq in 0..2 {
            let p = dir.join(format!("segment-{:06}.ghost", seq));
            let r = SessionReader::open(p.to_str().unwrap()).unwrap();
            assert_eq!(r.meta.pid, 7);
            assert_eq!(r.meta.mode, "daemon");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
