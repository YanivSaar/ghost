//! Cold-start timeline screen: ordered first-syscall waterfall from the
//! launched child (ARCHITECTURE §9.5, §10).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::state::AppState;
use super::super::widgets;

pub fn render_dense(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header
            Constraint::Length(3),  // totals
            Constraint::Min(8),     // timeline
            Constraint::Length(1),  // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_totals(f, chunks[1], state);
    render_timeline(f, chunks[2], state, table_state);
    render_keybind_bar(f, chunks[3], state);
}

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
    render_timeline(f, chunks[1], state, table_state);
    render_keybind_bar(f, chunks[2], state);
}

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let ebpf_badge = if state.ebpf_ok {
        Span::styled(" eBPF ", Style::default().fg(Color::Black).bg(Color::Green))
    } else {
        Span::styled(" proc ", Style::default().fg(Color::Black).bg(Color::Yellow))
    };
    let gone_badge = if state.target_gone {
        let txt = match state.cold.exit_status {
            Some(c) => format!(" EXIT {} ", c),
            None    => " GONE ".to_string(),
        };
        Span::styled(txt, Style::default().fg(Color::White).bg(Color::Red).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" running ", Style::default().fg(Color::Black).bg(Color::Cyan))
    };

    let line = Line::from(vec![
        Span::styled(" cold ",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
        Span::raw(format!("pid:{}  ", state.pid)),
        Span::styled(state.cold.cmdline.as_str(),
            Style::default().fg(Color::Cyan)),
        Span::raw("  "),
        ebpf_badge,
        Span::raw(" "),
        gone_badge,
    ]);
    let para = Paragraph::new(line)
        .block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(para, area);
}

fn render_totals(f: &mut Frame, area: Rect, state: &AppState) {
    let distinct = state.cold.timeline.len();
    let total_calls: u64 = state.cold.timeline.iter().map(|(_, _, c)| c).sum();
    let since_launch_us: u64 = state.cold.timeline.iter()
        .map(|(_, ts, _)| ts.saturating_sub(state.cold.launch_ts_ns))
        .max().unwrap_or(0) / 1_000;

    let text = format!(
        " distinct-syscalls:{distinct}  total-calls:{total_calls}  observed-window:{since_launch_us}µs"
    );
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::TOP))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}

fn render_timeline(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("+µs").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("NR").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("SYSCALL").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        Cell::from("CALLS").style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    ]).height(1);

    let launch = state.cold.launch_ts_ns;
    let rows: Vec<Row> = state.cold.timeline.iter().take(200).map(|(nr, first_ts, count)| {
        let delta_us = first_ts.saturating_sub(launch) / 1_000;
        Row::new(vec![
            Cell::from(Span::styled(format!("+{delta_us}"),
                Style::default().fg(Color::Cyan))),
            Cell::from(nr.to_string()),
            Cell::from(syscall_name(*nr)),
            Cell::from(count.to_string()),
        ])
    }).collect();

    let table = Table::new(rows, [
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(22),
        Constraint::Length(10),
    ])
    .header(header)
    .block(Block::default().title("Startup timeline — syscall first-seen order").borders(Borders::ALL))
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, ts);
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

fn syscall_name(nr: u32) -> &'static str {
    match nr {
        0 => "read", 1 => "write", 2 => "open", 3 => "close",
        4 => "stat", 5 => "fstat", 6 => "lstat", 7 => "poll",
        9 => "mmap", 10 => "mprotect", 11 => "munmap", 12 => "brk",
        13 => "rt_sigaction", 14 => "rt_sigprocmask",
        17 => "pread64", 20 => "writev", 21 => "access",
        35 => "nanosleep", 39 => "getpid", 41 => "socket",
        42 => "connect", 56 => "clone", 59 => "execve",
        60 => "exit", 61 => "wait4", 72 => "fcntl",
        78 => "getdents", 79 => "getcwd", 89 => "readlink",
        96 => "gettimeofday", 102 => "getuid", 158 => "arch_prctl",
        202 => "futex", 218 => "set_tid_address", 231 => "exit_group",
        232 => "epoll_wait", 233 => "epoll_ctl", 257 => "openat",
        262 => "newfstatat", 267 => "readlinkat", 273 => "set_robust_list",
        281 => "epoll_pwait", 293 => "epoll_create1",
        302 => "prlimit64", 318 => "getrandom", 334 => "rseq",
        _ => "?",
    }
}
