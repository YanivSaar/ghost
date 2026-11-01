//! Catch screen: a scrolling list of the newest latency tripwire breaches
//! (ARCHITECTURE §9.4, §10).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use super::super::widgets;
use crate::state::AppState;

pub fn render_dense(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(3), // totals bar
            Constraint::Min(8),    // hits table
            Constraint::Length(1), // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_totals(f, chunks[1], state);
    render_hit_table(f, chunks[2], state, table_state);
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
    render_hit_table(f, chunks[1], state, table_state);
    render_keybind_bar(f, chunks[2], state);
}

// ── sub-renderers ─────────────────────────────────────────────────────────

fn render_header(f: &mut Frame, area: Rect, state: &AppState) {
    let ebpf_badge = if state.ebpf_ok {
        Span::styled(" eBPF ", Style::default().fg(Color::Black).bg(Color::Green))
    } else {
        Span::styled(
            " proc ",
            Style::default().fg(Color::Black).bg(Color::Yellow),
        )
    };
    let gone_badge = if state.target_gone {
        Span::styled(
            " GONE ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled("", Style::default())
    };

    let threshold_us = state.catch.threshold_ns / 1_000;
    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", state.comm),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("pid:{}  ", state.pid)),
        Span::styled(
            "[ catch ]",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  above:{}µs  ", threshold_us)),
        ebpf_badge,
        Span::raw(" "),
        gone_badge,
    ]);
    let para = Paragraph::new(line).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(para, area);
}

fn render_totals(f: &mut Frame, area: Rect, state: &AppState) {
    let max_us = state.catch.max_delta_ns / 1_000;
    let text = format!(
        " hits:{}  max:{}µs  showing:{}",
        state.catch.total_hits,
        max_us,
        state.catch.recent_hits.len(),
    );
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::TOP))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}

fn render_hit_table(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("TIME ns").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TID").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("SYSCALL").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("DELTA µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .catch
        .recent_hits
        .iter()
        .map(|h| {
            let delta_us = h.delta_ns / 1_000;
            Row::new(vec![
                Cell::from(format!("{}", h.ts_ns)),
                Cell::from(h.tid.to_string()),
                Cell::from(format!("{} ({})", syscall_name(h.nr), h.nr)),
                Cell::from(Span::styled(
                    delta_us.to_string(),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(20),
            Constraint::Length(8),
            Constraint::Length(24),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Latency tripwire — newest first")
            .borders(Borders::ALL),
    )
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
    widgets::status_bar(
        f,
        area,
        vec![Span::raw("  q:quit  v:toggle-view  ↑↓:scroll"), err_span],
    );
}

// Minimal syscall-name map; mirrors overview.rs. Kept local so the two can
// diverge if catch wants to show, say, families (fs/net/mem/ipc) later.
fn syscall_name(nr: u32) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        7 => "poll",
        9 => "mmap",
        11 => "munmap",
        17 => "pread64",
        18 => "pwrite64",
        35 => "nanosleep",
        41 => "socket",
        42 => "connect",
        43 => "accept",
        44 => "sendto",
        45 => "recvfrom",
        46 => "sendmsg",
        47 => "recvmsg",
        56 => "clone",
        59 => "execve",
        61 => "wait4",
        74 => "fsync",
        202 => "futex",
        230 => "clock_nanosleep",
        232 => "epoll_wait",
        257 => "openat",
        262 => "newfstatat",
        271 => "ppoll",
        281 => "epoll_pwait",
        290 => "accept4",
        _ => "?",
    }
}
