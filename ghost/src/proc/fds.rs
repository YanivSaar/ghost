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

fn classify(target: &str) -> FdKind {
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
