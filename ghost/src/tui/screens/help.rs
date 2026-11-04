//! Help overlay + startup nudge (RFC: in-TUI view switching).
//!
//! `render_overlay` draws a centred modal listing every key binding
//! on top of whatever lens is active; `render_nudge` is a one-line
//! "press ? for help" ribbon that auto-dismisses after a few seconds.

use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph},
    Frame,
};

/// Centered modal with every binding.
pub fn render_overlay(f: &mut Frame) {
    let area = f.area();
    let w = area.width.min(60);
    let h: u16 = 18;
    let x = (area.width.saturating_sub(w)) / 2;
    let y = (area.height.saturating_sub(h)) / 2;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let lines = vec![
        row("w / 1", "watch (default live dashboard)"),
        row("s / 2", "snap  (/proc portrait)"),
        row("l / 3", "lock  (futex contention)"),
        row("t / 4", "catch (latency tripwire)"),
        row("j / 5", "jitter (IRQ attribution)"),
        row("a / 6", "analyze (scenario diagnoses)"),
        Line::from(""),
        row("n", "analyze: noisy / quiet"),
        row("f", "analyze: cycle confidence floor"),
        row("+ / -", "catch: double / halve threshold"),
        row("v", "dense / minimal view"),
        row("↑ ↓ / wheel", "scroll table"),
        row("mouse click", "footer tab → switch view"),
        Line::from(""),
        row("?  F1", "toggle this help"),
        row("q  Ctrl+C", "quit"),
    ];
    let p = Paragraph::new(lines).alignment(Alignment::Left).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" ghost — keybindings ")
            .style(Style::default().bg(Color::Black)),
    );
    f.render_widget(p, rect);
}

/// Thin bottom ribbon shown on first startup (dismissed on any key or
/// after a short timeout). Rendered as the LAST row of the frame on top
/// of the mode-tabs bar — the nudge takes priority for the first few
/// seconds so new users see "press ? for help" instead of a quiet tab
/// strip. Only shown when there's at least a tabs row underneath; falls
/// back silently on tiny terminals.
pub fn render_nudge(f: &mut Frame) {
    let area = f.area();
    if area.height < 2 {
        return;
    }
    let bar = Rect {
        x: 0,
        y: area.height.saturating_sub(1),
        width: area.width,
        height: 1,
    };
    f.render_widget(Clear, bar);
    let text = Line::from(vec![Span::styled(
        " press ? for help  —  w s l t j a to switch view ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    )]);
    f.render_widget(Paragraph::new(text), bar);
}

fn row(key: &'static str, help: &'static str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<14}", key),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(help),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn overlay_renders_without_panic() {
        let backend = TestBackend::new(100, 30);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(render_overlay).unwrap();
    }

    #[test]
    fn nudge_renders_without_panic() {
        let backend = TestBackend::new(100, 10);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(render_nudge).unwrap();
    }
}
