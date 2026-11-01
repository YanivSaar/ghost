//! Cgroup target (v2 default). Seed PID_SET from `cgroup.procs`; new
//! children are picked up for free by the in-kernel fork tracepoint.
//!
//! Accepted target spellings:
//!   /sys/fs/cgroup/system.slice/foo.service   — absolute path
//!   system.slice/foo.service                  — relative path under /sys/fs/cgroup
//!   /system.slice/foo.service                 — same, leading slash tolerated
//!
//! Systemd unit resolution (`foo.service` → `/system.slice/foo.service`) is
//! deliberately NOT done here; it requires talking to systemd and is better
//! as a follow-up. Users who want "the unit's cgroup" should pass the path
//! that `systemctl show -p ControlGroup <unit>` prints.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

pub struct CgroupTarget {
    /// Absolute cgroup directory on disk.
    pub path:    PathBuf,
    /// Short label suitable for the TUI header.
    pub label:   String,
    /// PIDs currently in the cgroup. Seeded from `<path>/cgroup.procs`.
    pub members: Vec<u32>,
}

impl CgroupTarget {
    pub fn attach(spec: &str) -> Result<Self> {
        let path = resolve(spec)?;
        if !path.is_dir() {
            return Err(anyhow!("ghost cgroup: {} is not a directory", path.display()));
        }

        let procs_file = path.join("cgroup.procs");
        let members = read_procs(&procs_file)
            .with_context(|| format!("reading {}", procs_file.display()))?;

        let label = path.strip_prefix(CGROUP_ROOT)
            .map(|p| format!("/{}", p.display()))
            .unwrap_or_else(|_| path.display().to_string());

        Ok(Self { path, label, members })
    }

    /// Re-read `cgroup.procs` so new processes can be added to the eBPF
    /// PID_SET (fork propagation covers *children of tracked PIDs*, but
    /// a wholly new sibling added to the cgroup directly needs a reseed).
    pub fn refresh_members(&mut self) -> Result<Vec<u32>> {
        let new = read_procs(&self.path.join("cgroup.procs"))?;
        self.members = new.clone();
        Ok(new)
    }
}

fn resolve(spec: &str) -> Result<PathBuf> {
    let p = Path::new(spec);
    if p.is_absolute() {
        return Ok(p.to_path_buf());
    }
    let trimmed = spec.trim_start_matches('/');
    Ok(Path::new(CGROUP_ROOT).join(trimmed))
}

fn read_procs(path: &Path) -> Result<Vec<u32>> {
    let txt = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in txt.lines() {
        let s = line.trim();
        if s.is_empty() { continue; }
        if let Ok(pid) = s.parse::<u32>() {
            out.push(pid);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_absolute() {
        let p = resolve("/sys/fs/cgroup/foo").unwrap();
        assert_eq!(p, PathBuf::from("/sys/fs/cgroup/foo"));
    }

    #[test]
    fn resolve_relative_prepends_root() {
        let p = resolve("system.slice/foo.service").unwrap();
        assert_eq!(p, PathBuf::from("/sys/fs/cgroup/system.slice/foo.service"));
    }

    #[test]
    fn resolve_leading_slash_tolerated() {
        let p = resolve("/system.slice/foo.service").unwrap();
        assert_eq!(p, PathBuf::from("/system.slice/foo.service"));
    }

    #[test]
    fn attach_nonexistent_fails() {
        let r = CgroupTarget::attach("ghost-nonexistent-xyz-12345");
        assert!(r.is_err());
    }

    #[test]
    fn read_procs_parses_lines() {
        use std::io::Write;
        let dir = tempdir().unwrap();
        let p = dir.path().join("cgroup.procs");
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "123").unwrap();
        writeln!(f, "456").unwrap();
        writeln!(f, "").unwrap();
        writeln!(f, "junk").unwrap();
        writeln!(f, "789").unwrap();
        let v = read_procs(&p).unwrap();
        assert_eq!(v, vec![123u32, 456, 789]);
    }

    // Tiny temp-dir helper so the test doesn't need the `tempfile` crate.
    struct TempDir(PathBuf);
    impl TempDir { fn path(&self) -> &Path { &self.0 } }
    impl Drop for TempDir { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    fn tempdir() -> std::io::Result<TempDir> {
        let base = std::env::temp_dir()
            .join(format!("ghost-cgroup-{}-{}",
                std::process::id(),
                std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&base)?;
        Ok(TempDir(base))
    }
}
