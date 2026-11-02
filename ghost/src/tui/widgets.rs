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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn with_test_frame<F: FnOnce(&mut Frame, Rect)>(w: u16, h: u16, body: F) {
        let backend = TestBackend::new(w, h);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| {
            let area = f.area();
            body(f, area);
        })
        .unwrap();
    }

    #[test]
    fn cpu_sparkline_renders_empty_without_panic() {
        with_test_frame(40, 3, |f, area| {
            cpu_sparkline(f, area, &[], "idle");
        });
    }

    #[test]
    fn cpu_sparkline_clamps_values_above_100() {
        with_test_frame(40, 3, |f, area| {
            cpu_sparkline(f, area, &[0.0, 25.0, 50.0, 75.0, 100.0, 150.0], "cpu");
        });
    }

    #[test]
    fn syscall_table_renders_zero_rows() {
        with_test_frame(80, 8, |f, area| {
            let mut st = TableState::default();
            syscall_table(f, area, &[], &mut st);
        });
    }

    #[test]
    fn syscall_table_renders_sample_rows() {
        with_test_frame(80, 8, |f, area| {
            let mut st = TableState::default();
            let rows: Vec<(u32, &str, u64, u64, u64)> = vec![
                (0, "read", 10, 5, 1),
                (1, "write", 7, 3, 2),
                (202, "futex", 500, 1234, 42),
            ];
            syscall_table(f, area, &rows, &mut st);
        });
    }

    #[test]
    fn status_bar_renders_empty_and_populated() {
        with_test_frame(60, 1, |f, area| {
            status_bar(f, area, vec![]);
        });
        with_test_frame(60, 1, |f, area| {
            status_bar(
                f,
                area,
                vec![
                    Span::raw("q:quit  "),
                    Span::styled("WARN", Style::default().fg(Color::Red)),
                ],
            );
        });
    }
}
