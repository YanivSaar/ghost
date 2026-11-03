//! Analyze screen (RFC 0001): current diagnoses + 10-min history.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table, TableState},
    Frame,
};

use crate::analyze::{AnalyzerState, Confidence, Severity};
use crate::state::AppState;

/// Dense = full RFC-0001 layout; minimal = current only.
pub fn render_dense(f: &mut Frame, st: &AppState, ts: &mut TableState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),  // header
            Constraint::Min(5),     // current
            Constraint::Length(10), // history
            Constraint::Length(1),  // keybind bar
        ])
        .split(area);
    render_header(f, chunks[0], st);
    render_current(f, chunks[1], &st.analyze, ts);
    render_history(f, chunks[2], &st.analyze);
    render_keybar(f, chunks[3]);
}

pub fn render_minimal(f: &mut Frame, st: &AppState, ts: &mut TableState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(1),
        ])
        .split(area);
    render_header(f, chunks[0], st);
    render_current(f, chunks[1], &st.analyze, ts);
    render_keybar(f, chunks[2]);
}

fn render_header(f: &mut Frame, area: Rect, st: &AppState) {
    let a = &st.analyze;
    let mode = match a.mode {
        crate::analyze::Mode::Quiet => "quiet",
        crate::analyze::Mode::Noisy => "noisy",
    };
    let text = Line::from(vec![
        Span::styled(
            " analyze ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("  pid {} ({})", st.pid, st.comm)),
        Span::raw(format!("   mode: {}   tick: {}", mode, a.tick)),
    ]);
    let status = a.config_source.status_line();
    let block = Block::default()
        .borders(Borders::BOTTOM)
        .title(Span::raw(status));
    let p = Paragraph::new(text).block(block);
    f.render_widget(p, area);
}

fn render_current(f: &mut Frame, area: Rect, a: &AnalyzerState, ts: &mut TableState) {
    let header = Row::new(vec!["id", "sev", "conf", "headline"]).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::Gray)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = a
        .current
        .iter()
        .map(|d| {
            Row::new(vec![
                d.id.to_string(),
                d.severity.label().to_string(),
                d.confidence.label().to_string(),
                d.headline.clone(),
            ])
            .style(sev_style(d.severity, d.confidence))
        })
        .collect();
    let widths = [
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Min(10),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .title("What's happening"),
    );
    f.render_stateful_widget(table, area, ts);
}

fn render_history(f: &mut Frame, area: Rect, a: &AnalyzerState) {
    let header = Row::new(vec!["ticks", "id", "sev", "headline"]).style(
        Style::default()
            .fg(Color::Black)
            .bg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
    );
    let rows: Vec<Row> = a
        .history
        .iter()
        .rev()
        .take(20)
        .map(|h| {
            Row::new(vec![
                format!("{}..{}", h.first_tick, h.last_tick),
                h.id.to_string(),
                h.severity.label().to_string(),
                h.headline.clone(),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(12),
        Constraint::Length(22),
        Constraint::Length(8),
        Constraint::Min(10),
    ];
    let table = Table::new(rows, widths).header(header).block(
        Block::default().borders(Borders::ALL).title(format!(
            "History (last {} entries, 10 min ring)",
            a.history.len()
        )),
    );
    f.render_widget(table, area);
}

fn render_keybar(f: &mut Frame, area: Rect) {
    let p = Paragraph::new(Line::from(vec![
        Span::styled(" a ", Style::default().bg(Color::DarkGray)),
        Span::raw(" analyze "),
        Span::styled(" n ", Style::default().bg(Color::DarkGray)),
        Span::raw(" noisy "),
        Span::styled(" q ", Style::default().bg(Color::DarkGray)),
        Span::raw(" quiet "),
        Span::styled(" v ", Style::default().bg(Color::DarkGray)),
        Span::raw(" dense "),
    ]));
    f.render_widget(p, area);
}

fn sev_style(s: Severity, _c: Confidence) -> Style {
    match s {
        Severity::Warning => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        Severity::Notice => Style::default().fg(Color::Yellow),
        Severity::Info => Style::default().fg(Color::White),
    }
}
