//! Lock contention screen: top futex addresses by total wait-time
//! (ARCHITECTURE §9.3, §10).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::state::AppState;

pub fn render_dense(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(3), // totals bar
            Constraint::Min(8),    // lock table
            Constraint::Length(1), // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_totals(f, chunks[1], state);
    render_lock_table(f, chunks[2], state, table_state);
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
    render_lock_table(f, chunks[1], state, table_state);
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

    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", state.comm),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("pid:{}  ", state.pid)),
        Span::styled(
            "[ lock ]",
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        ebpf_badge,
        Span::raw(" "),
        gone_badge,
    ]);

    let para = Paragraph::new(line).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(para, area);
}

fn render_totals(f: &mut Frame, area: Rect, state: &AppState) {
    let waits = state.lock.total_waits;
    let total_ms = state.lock.total_wait_ns / 1_000_000;
    let avg_us = if waits > 0 {
        state.lock.total_wait_ns / waits / 1_000
    } else {
        0
    };

    let text = format!(
        " futex waits:{waits}  total:{total_ms}ms  avg:{avg_us}µs  tracked-addrs:{}",
        state.lock.top_locks.len()
    );
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::TOP))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}

fn render_lock_table(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("ADDR").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("WAITS").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TOTAL ms").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAX µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("AVG µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .lock
        .top_locks
        .iter()
        .map(|(addr, s)| {
            let total_ms = s.total_wait_ns / 1_000_000;
            let max_us = s.max_wait_ns / 1_000;
            let avg_us = if s.waits > 0 {
                s.total_wait_ns / s.waits / 1_000
            } else {
                0
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("0x{:x}", addr),
                    Style::default().fg(Color::Cyan),
                )),
                Cell::from(s.waits.to_string()),
                Cell::from(total_ms.to_string()),
                Cell::from(max_us.to_string()),
                Cell::from(avg_us.to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Top futex addresses by wait time")
            .borders(Borders::ALL),
    )
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, ts);
}
