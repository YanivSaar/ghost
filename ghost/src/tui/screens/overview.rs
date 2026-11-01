//! Overview dashboard: watch-mode layout (ARCHITECTURE §10).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, TableState},
    Frame,
};

use crate::state::AppState;
use super::super::widgets;

/// Dense layout: identity header + sparkline + syscall table + sched bar.
pub fn render_dense(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // identity header
            Constraint::Length(4),   // CPU sparkline
            Constraint::Min(8),      // syscall table
            Constraint::Length(3),   // sched switches + status bar
            Constraint::Length(1),   // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_sparkline(f, chunks[1], state);
    render_syscall_table(f, chunks[2], state, table_state);
    render_sched_bar(f, chunks[3], state);
    render_keybind_bar(f, chunks[4], state);
}

/// Minimal layout: header + syscall table only.
pub fn render_minimal(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_syscall_table(f, chunks[1], state, table_state);
    render_keybind_bar(f, chunks[2], state);
}

// ── sub-renderers ─────────────────────────────────────────────────────────────

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let ebpf_badge = if state.ebpf_ok {
        Span::styled(" eBPF ", Style::default().fg(Color::Black).bg(Color::Green))
    } else {
        Span::styled(" proc ", Style::default().fg(Color::Black).bg(Color::Yellow))
    };

    let gone_badge = if state.target_gone {
        Span::styled(" GONE ", Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("", Style::default())
    };

    let threads = state.snap.as_ref().map(|s| s.status.threads).unwrap_or(0);
    let rss = state.snap.as_ref().map(|s| s.status.vm_rss_kb).unwrap_or(0);

    let label = state.target_label.as_deref().map(|l| format!(" [ {l} ] ")).unwrap_or_default();

    let line = Line::from(vec![
        Span::styled(format!(" {} ", state.comm), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(format!("pid:{} ", state.pid)),
        Span::styled(label, Style::default().fg(Color::Magenta)),
        Span::raw(format!("threads:{threads}  ")),
        Span::raw(format!("rss:{} ", fmt_kb(rss))),
        ebpf_badge,
        Span::raw(" "),
        gone_badge,
    ]);

    let para = Paragraph::new(line)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(para, area);
}

fn render_sparkline(f: &mut Frame, area: Rect, state: &AppState) {
    let history: Vec<f32> = state.watch.cpu_history.iter().copied().collect();
    widgets::cpu_sparkline(f, area, &history, "CPU %");
}

fn render_syscall_table(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    // Convert SyscallKey/SyscallStat into display tuples.
    let rows: Vec<(u32, &'static str, u64, u64, u64)> = state.watch.top_syscalls.iter().map(|(k, v)| {
        let total_ms = v.total_ns / 1_000_000;
        let max_ms_micro = v.max_ns / 1_000;  // show in µs for precision
        (k.nr, syscall_name(k.nr), v.count, total_ms, max_ms_micro)
    }).collect();

    widgets::syscall_table(f, area, &rows, ts);
}

fn render_sched_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let vol   = state.watch.voluntary_ctx;
    let invol = state.watch.involuntary_ctx;
    let total = vol + invol;
    let pct = if total > 0 { invol * 100 / total } else { 0 };

    let dropped = if state.watch.events_dropped > 0 {
        format!("  ⚠ dropped:{}", state.watch.events_dropped)
    } else {
        String::new()
    };

    let text = format!(
        " ctx-switches  voluntary:{vol}  involuntary:{invol}  preempt%:{pct}{}",
        dropped
    );
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::TOP))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}

fn render_keybind_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let ebpf_err = state.ebpf_error.as_deref().unwrap_or("");
    let err_span = if !ebpf_err.is_empty() {
        Span::styled(format!("  {ebpf_err}"), Style::default().fg(Color::Red))
    } else {
        Span::raw("")
    };

    widgets::status_bar(f, area, vec![
        Span::raw("  q:quit  v:toggle-view  ↑↓:scroll"),
        err_span,
    ]);
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn fmt_kb(kb: u64) -> String {
    if kb < 1024 { format!("{kb}K") }
    else { format!("{:.1}M", kb as f64 / 1024.0) }
}

fn syscall_name(nr: u32) -> &'static str {
    match nr {
        0 => "read",       1 => "write",      2 => "open",
        3 => "close",      4 => "stat",       5 => "fstat",
        6 => "lstat",      7 => "poll",       8 => "lseek",
        9 => "mmap",       10 => "mprotect",  11 => "munmap",
        12 => "brk",       13 => "rt_sigaction", 14 => "rt_sigprocmask",
        17 => "pread64",   18 => "pwrite64",  19 => "readv",
        20 => "writev",    21 => "access",    23 => "select",
        24 => "sched_yield", 28 => "madvise", 32 => "dup",
        33 => "dup2",      35 => "nanosleep", 38 => "setitimer",
        39 => "getpid",    41 => "socket",    42 => "connect",
        43 => "accept",    44 => "sendto",    45 => "recvfrom",
        46 => "sendmsg",   47 => "recvmsg",   48 => "shutdown",
        49 => "bind",      50 => "listen",    51 => "getsockname",
        52 => "getpeername", 54 => "setsockopt", 55 => "getsockopt",
        56 => "clone",     57 => "fork",      59 => "execve",
        60 => "exit",      61 => "wait4",     62 => "kill",
        63 => "uname",     72 => "fcntl",     73 => "flock",
        74 => "fsync",     78 => "getdents",  79 => "getcwd",
        80 => "chdir",     82 => "rename",    83 => "mkdir",
        87 => "unlink",    89 => "readlink",  96 => "gettimeofday",
        97 => "getrlimit", 102 => "getuid",   104 => "getgid",
        105 => "setuid",   106 => "setgid",   107 => "geteuid",
        108 => "getegid",  110 => "getppid",  111 => "getpgrp",
        186 => "gettid",   202 => "futex",    218 => "set_tid_address",
        228 => "clock_gettime", 230 => "clock_nanosleep",
        231 => "exit_group", 232 => "epoll_wait", 233 => "epoll_ctl",
        234 => "tgkill",   249 => "fallocate", 257 => "openat",
        262 => "newfstatat", 267 => "readlinkat", 269 => "faccessat",
        270 => "pselect6", 271 => "ppoll",    281 => "epoll_pwait",
        290 => "accept4",  291 => "signalfd4", 292 => "eventfd2",
        293 => "epoll_create1", 302 => "prlimit64", 316 => "renameat2",
        318 => "getrandom", 334 => "rseq",
        _ => "?",
    }
}
