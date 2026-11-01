//! Jitter attribution screen: hardirq + softirq time stolen from the target
//! while it was on-CPU (ARCHITECTURE §9.6, §10).

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
            Constraint::Min(6),    // tables (split 50/50 horizontally)
            Constraint::Length(1), // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_totals(f, chunks[1], state);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[2]);
    render_hard_table(f, cols[0], state, table_state);
    render_soft_table(f, cols[1], state);

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
    render_hard_table(f, chunks[1], state, table_state);
    render_keybind_bar(f, chunks[2], state);
}

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
            "[ jitter ]",
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
    let hard_us = state.jitter.total_irq_ns / 1_000;
    let soft_us = state.jitter.total_softirq_ns / 1_000;
    let invol = state.jitter.involuntary_ctx;

    let text = format!(" hardirq:{hard_us}µs  softirq:{soft_us}µs  preempt-ctx:{invol}");
    let para = Paragraph::new(text)
        .block(Block::default().borders(Borders::TOP))
        .style(Style::default().fg(Color::DarkGray));
    f.render_widget(para, area);
}

fn render_hard_table(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    let header = Row::new(vec![
        Cell::from("IRQ").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("HITS").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TOTAL µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAX µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .jitter
        .hard_irqs
        .iter()
        .take(20)
        .map(|(irq, s)| {
            Row::new(vec![
                Cell::from(irq.to_string()),
                Cell::from(s.count.to_string()),
                Cell::from((s.total_ns / 1_000).to_string()),
                Cell::from((s.max_ns / 1_000).to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Hardirqs on target CPU")
            .borders(Borders::ALL),
    )
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, ts);
}

fn render_soft_table(f: &mut Frame, area: Rect, state: &AppState) {
    let header = Row::new(vec![
        Cell::from("SOFTIRQ").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("HITS").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TOTAL µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAX µs").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let rows: Vec<Row> = state
        .jitter
        .soft_irqs
        .iter()
        .take(10)
        .map(|(vec_nr, s)| {
            Row::new(vec![
                Cell::from(softirq_name(*vec_nr)),
                Cell::from(s.count.to_string()),
                Cell::from((s.total_ns / 1_000).to_string()),
                Cell::from((s.max_ns / 1_000).to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Softirqs on target CPU")
            .borders(Borders::ALL),
    );

    f.render_widget(table, area);
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

/// Softirq vec_nr names (kernel include/trace/events/irq.h).
fn softirq_name(vec_nr: u32) -> &'static str {
    match vec_nr {
        0 => "HI",
        1 => "TIMER",
        2 => "NET_TX",
        3 => "NET_RX",
        4 => "BLOCK",
        5 => "IRQ_POLL",
        6 => "TASKLET",
        7 => "SCHED",
        8 => "HRTIMER",
        9 => "RCU",
        _ => "?",
    }
}
