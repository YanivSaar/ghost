//! Cgroup target (v2 default). Seed PID_SET from `cgroup.procs`; new
//! children are picked up for free by the in-kernel fork tracepoint.
//!
//! Accepted target spellings:
//!   /sys/fs/cgroup/system.slice/foo.service   — absolute path
//!   system.slice/foo.service                  — relative path under /sys/fs/cgroup
//!   /system.slice/foo.service                 — same, leading slash tolerated
//!   foo.service / foo.scope / foo@1.slice     — systemd unit name, resolved
//!     via `systemctl show -p ControlGroup --value <unit>`.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, Context, Result};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Systemd unit suffixes we try to resolve.
const UNIT_SUFFIXES: &[&str] = &[
    ".service", ".scope", ".slice", ".socket", ".timer", ".mount", ".path", ".target",
];

pub struct CgroupTarget {
    /// Absolute cgroup directory on disk.
    pub path: PathBuf,
    /// Short label suitable for the TUI header.
    pub label: String,
    /// PIDs currently in the cgroup. Seeded from `<path>/cgroup.procs`.
    pub members: Vec<u32>,
}

impl CgroupTarget {
    pub fn attach(spec: &str) -> Result<Self> {
        let path = resolve(spec)?;
        if !path.is_dir() {
            return Err(anyhow!(
                "ghost cgroup: {} is not a directory",
                path.display()
            ));
        }

        let procs_file = path.join("cgroup.procs");
        let members =
            read_procs(&procs_file).with_context(|| format!("reading {}", procs_file.display()))?;

        let label = path
            .strip_prefix(CGROUP_ROOT)
            .map(|p| format!("/{}", p.display()))
            .unwrap_or_else(|_| path.display().to_string());

        Ok(Self {
            path,
            label,
            members,
        })
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
    // Rule 1: path-shaped input (contains a '/') is treated as a path.
    if spec.contains('/') {
        let p = Path::new(spec);
        if p.is_absolute() {
            return Ok(p.to_path_buf());
        }
        return Ok(Path::new(CGROUP_ROOT).join(spec.trim_start_matches('/')));
    }

    // Rule 2: looks like a systemd unit → ask systemd.
    if is_unit_name(spec) {
        if let Some(cg) = resolve_systemd_unit(spec)? {
            // systemctl returns the kernel-relative path, e.g. "/system.slice/foo.service".
            return Ok(Path::new(CGROUP_ROOT).join(cg.trim_start_matches('/')));
        }
        return Err(anyhow!(
            "ghost cgroup: systemctl could not resolve unit {spec} (is systemd running?)"
        ));
    }

    // Rule 3: bare name — assume it's a direct child of /sys/fs/cgroup.
    Ok(Path::new(CGROUP_ROOT).join(spec))
}

fn is_unit_name(s: &str) -> bool {
    UNIT_SUFFIXES.iter().any(|suf| s.ends_with(suf))
}

/// Shell out to systemctl. Returns Ok(Some(path)) on success, Ok(None) if
/// systemctl ran but gave no path (unit unknown), Err if systemctl is missing
/// or failed. The `--value` flag strips the `ControlGroup=` prefix.
fn resolve_systemd_unit(unit: &str) -> Result<Option<String>> {
    let out = Command::new("systemctl")
        .args(["show", "-p", "ControlGroup", "--value", unit])
        .output()
        .with_context(|| format!("spawning systemctl for unit {unit}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "systemctl show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(s))
}

fn read_procs(path: &Path) -> Result<Vec<u32>> {
    let txt = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for line in txt.lines() {
        let s = line.trim();
        if s.is_empty() {
            continue;
        }
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
    fn is_unit_name_matches_known_suffixes() {
        assert!(is_unit_name("foo.service"));
        assert!(is_unit_name("foo.scope"));
        assert!(is_unit_name("my@0.slice"));
        assert!(is_unit_name("foo.socket"));
        assert!(is_unit_name("foo.timer"));
        assert!(is_unit_name("foo.mount"));
        assert!(is_unit_name("foo.path"));
        assert!(is_unit_name("foo.target"));
        assert!(!is_unit_name("plain-name"));
        assert!(!is_unit_name("foo/bar"));
        assert!(!is_unit_name("foo.random"));
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
        writeln!(f).unwrap();
        writeln!(f, "junk").unwrap();
        writeln!(f, "789").unwrap();
        let v = read_procs(&p).unwrap();
        assert_eq!(v, vec![123u32, 456, 789]);
    }

    // Tiny temp-dir helper so the test doesn't need the `tempfile` crate.
    struct TempDir(PathBuf);
    impl TempDir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn tempdir() -> std::io::Result<TempDir> {
        let base = std::env::temp_dir().join(format!(
            "ghost-cgroup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&base)?;
        Ok(TempDir(base))
    }
}
