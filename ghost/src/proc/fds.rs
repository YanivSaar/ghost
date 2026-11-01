//! /proc/{pid}/fd enumerator — open descriptors classified by type.

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FdInfo {
    pub number: u32,
    pub kind: FdKind,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdKind {
    File,
    Socket,
    Pipe,
    AnonymousInode,
    Device,
    Other,
}

impl FdKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            FdKind::File           => "file",
            FdKind::Socket         => "socket",
            FdKind::Pipe           => "pipe",
            FdKind::AnonymousInode => "anon_inode",
            FdKind::Device         => "device",
            FdKind::Other          => "other",
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct FdSummary {
    pub fds: Vec<FdInfo>,
    pub total: usize,
    pub files: usize,
    pub sockets: usize,
    pub pipes: usize,
    pub anon: usize,
    pub other: usize,
}

pub fn read(pid: u32) -> Result<FdSummary> {
    let dir = format!("/proc/{pid}/fd");
    let entries = fs::read_dir(&dir)
        .with_context(|| format!("reading {dir}"))?;

    let mut summary = FdSummary::default();

    for entry in entries.flatten() {
        let Ok(num) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };

        let link_path = PathBuf::from(format!("/proc/{pid}/fd/{num}"));
        let target = fs::read_link(&link_path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<unreadable>".to_string());

        let kind = classify(&target);
        match kind {
            FdKind::File           => summary.files += 1,
            FdKind::Socket         => summary.sockets += 1,
            FdKind::Pipe           => summary.pipes += 1,
            FdKind::AnonymousInode => summary.anon += 1,
            _                      => summary.other += 1,
        }
        summary.total += 1;
        summary.fds.push(FdInfo { number: num, kind, target });
    }

    summary.fds.sort_by_key(|f| f.number);
    Ok(summary)
}

pub(crate) fn classify(target: &str) -> FdKind {
    if target.starts_with("socket:") {
        FdKind::Socket
    } else if target.starts_with("pipe:") {
        FdKind::Pipe
    } else if target.starts_with("anon_inode:") {
        FdKind::AnonymousInode
    } else if target.starts_with('/') {
        if target.starts_with("/dev/") {
            FdKind::Device
        } else {
            FdKind::File
        }
    } else {
        FdKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_socket() {
        assert_eq!(classify("socket:[12345]"),   FdKind::Socket);
    }

    #[test]
    fn classify_pipe() {
        assert_eq!(classify("pipe:[67890]"),     FdKind::Pipe);
    }

    #[test]
    fn classify_anon_inode() {
        assert_eq!(classify("anon_inode:eventfd"), FdKind::AnonymousInode);
        assert_eq!(classify("anon_inode:[timerfd]"), FdKind::AnonymousInode);
    }

    #[test]
    fn classify_regular_file() {
        assert_eq!(classify("/etc/hosts"),       FdKind::File);
        assert_eq!(classify("/proc/self/maps"),  FdKind::File);
    }

    #[test]
    fn classify_device() {
        assert_eq!(classify("/dev/null"),        FdKind::Device);
        assert_eq!(classify("/dev/pts/0"),       FdKind::Device);
    }

    #[test]
    fn classify_other() {
        assert_eq!(classify("(deleted)"),        FdKind::Other);
        assert_eq!(classify(""),                 FdKind::Other);
    }

    #[test]
    fn fd_kind_as_str() {
        assert_eq!(FdKind::File.as_str(),           "file");
        assert_eq!(FdKind::Socket.as_str(),         "socket");
        assert_eq!(FdKind::Pipe.as_str(),           "pipe");
        assert_eq!(FdKind::AnonymousInode.as_str(), "anon_inode");
        assert_eq!(FdKind::Device.as_str(),         "device");
        assert_eq!(FdKind::Other.as_str(),          "other");
    }

    #[test]
    fn read_current_process_fds() {
        let pid = std::process::id();
        let summary = read(pid).expect("read own /proc/fd");
        // stdin/stdout/stderr should always be open
        assert!(summary.total >= 3);
    }
}
