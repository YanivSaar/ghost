//! Shared TUI widgets: sparkline helper, top-N syscall table, status bar.

use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Row, Sparkline, Table, TableState},
    Frame,
};

/// Render a CPU% sparkline in `area`. `history` is newest-last.
pub fn cpu_sparkline(f: &mut Frame, area: Rect, history: &[f32], title: &str) {
    let data: Vec<u64> = history.iter().map(|v| (*v as u64).min(100)).collect();
    let spark = Sparkline::default()
        .block(Block::default().title(title).borders(Borders::NONE))
        .data(&data)
        .style(Style::default().fg(Color::Cyan));
    f.render_widget(spark, area);
}

/// Render a top-N syscall table. Returns a new `TableState` with selection preserved.
pub fn syscall_table(
    f: &mut Frame,
    area: Rect,
    rows: &[(u32, &str, u64, u64, u64)], // (nr, name, count, total_ms, max_ms)
    state: &mut TableState,
) {
    let header = Row::new(vec![
        Cell::from("NR").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("NAME").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("COUNT").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("TOTAL ms").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Cell::from("MAX ms").style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    ])
    .height(1);

    let table_rows: Vec<Row> = rows
        .iter()
        .map(|(nr, name, count, total_ms, max_ms)| {
            Row::new(vec![
                Cell::from(nr.to_string()),
                Cell::from(Span::styled(*name, Style::default().fg(Color::Cyan))),
                Cell::from(count.to_string()),
                Cell::from(format!("{total_ms:.1}")),
                Cell::from(format!("{max_ms:.3}")),
            ])
        })
        .collect();

    let table = Table::new(
        table_rows,
        [
            ratatui::layout::Constraint::Length(6),
            ratatui::layout::Constraint::Min(20),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Length(10),
            ratatui::layout::Constraint::Length(10),
        ],
    )
    .header(header)
    .block(
        Block::default()
            .title("Top syscalls by CPU time")
            .borders(Borders::ALL),
    )
    .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_stateful_widget(table, area, state);
}

/// One-line status bar at the bottom of the screen.
pub fn status_bar(f: &mut Frame, area: Rect, spans: Vec<Span<'_>>) {
    let line = Line::from(spans);
    f.render_widget(
        ratatui::widgets::Paragraph::new(line).style(Style::default().bg(Color::DarkGray)),
        area,
    );
}
