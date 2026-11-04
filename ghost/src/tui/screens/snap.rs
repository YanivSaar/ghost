//! Snap view: a static /proc portrait inside the TUI.
//!
//! No eBPF, no history, no live aggregates — just the fields that were
//! captured on the last `ProcSnapshot::collect` tick. Reachable at any
//! time by pressing `s` from any other view.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::state::AppState;

pub fn render(f: &mut Frame, st: &AppState) {
    let area = f.area();
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // identity header
            Constraint::Min(6),    // body
            Constraint::Length(1), // reserved for shared mode_tabs
        ])
        .split(area);

    render_header(f, chunks[0], st);
    render_body(f, chunks[1], st);
}

fn render_header(f: &mut Frame, area: Rect, st: &AppState) {
    let badge = Span::styled(
        " snap ",
        Style::default()
            .fg(Color::Black)
            .bg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    );
    let line = Line::from(vec![
        badge,
        Span::raw(format!("  pid {} ({})", st.pid, st.comm)),
    ]);
    f.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::BOTTOM)),
        area,
    );
}

fn render_body(f: &mut Frame, area: Rect, st: &AppState) {
    let Some(snap) = st.snap.as_ref() else {
        f.render_widget(
            Paragraph::new("snap: no /proc snapshot yet (waiting for the first poller tick)")
                .block(Block::default().borders(Borders::ALL).title("snap")),
            area,
        );
        return;
    };

    let mut lines: Vec<Line> = Vec::new();
    lines.push(row("state", &snap.stat.state.to_string()));
    lines.push(row("ppid", &snap.stat.ppid.to_string()));
    lines.push(row("threads", &snap.status.threads.to_string()));
    lines.push(row(
        "cpu ticks (u+s)",
        &format!("{} + {}", snap.stat.utime_ticks, snap.stat.stime_ticks),
    ));
    lines.push(row(
        "priority / nice",
        &format!("{} / {}", snap.stat.priority, snap.stat.nice),
    ));
    lines.push(row(
        "majflt / minflt",
        &format!("{} / {}", snap.stat.majflt, snap.stat.minflt),
    ));
    lines.push(row("VmRSS", &format!("{} kB", snap.status.vm_rss_kb)));
    lines.push(row("VmSize", &format!("{} kB", snap.status.vm_size_kb)));
    lines.push(row("VmSwap", &format!("{} kB", snap.status.vm_swap_kb)));
    lines.push(row(
        "ctx switches (v / n)",
        &format!(
            "{} / {}",
            snap.status.voluntary_ctxt_switches, snap.status.nonvoluntary_ctxt_switches
        ),
    ));
    lines.push(row("oom_score", &snap.oom_score.to_string()));
    lines.push(row(
        "sched run_ns / wait_ns",
        &format!("{} / {}", snap.sched_run_ns, snap.sched_wait_ns),
    ));
    lines.push(row("wchan", &snap.wchan));
    lines.push(row("exe", &snap.exe));
    lines.push(row("cwd", &snap.cwd));
    if !snap.cmdline.is_empty() {
        lines.push(row("cmdline", &snap.cmdline));
    }

    let p = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title("/proc portrait (last tick)"),
    );
    f.render_widget(p, area);
}

fn row(k: &'static str, v: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {:<22}", k),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(v.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn renders_without_snapshot() {
        let st = AppState::new(1, "x".into());
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        term.draw(|f| render(f, &st)).unwrap();
    }
}
