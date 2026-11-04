//! Overview dashboard: watch-mode layout (ARCHITECTURE §10).

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, TableState},
    Frame,
};

use super::super::widgets;
use crate::state::AppState;
use crate::tui::syscalls::syscall_name;

/// Dense layout: identity header + sparkline + syscall table + sched bar.
pub fn render_dense(f: &mut Frame, state: &AppState, table_state: &mut TableState) {
    let area = f.area();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // identity header
            Constraint::Length(4), // CPU sparkline
            Constraint::Min(8),    // syscall table
            Constraint::Length(3), // sched switches + status bar
            Constraint::Length(1), // keybind bar
        ])
        .split(area);

    render_header(f, chunks[0], state);
    render_sparkline(f, chunks[1], state);
    render_syscall_table(f, chunks[2], state, table_state);
    render_sched_bar(f, chunks[3], state);
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
}

// ── sub-renderers ─────────────────────────────────────────────────────────────

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

    let threads = state.snap.as_ref().map(|s| s.status.threads).unwrap_or(0);
    let rss = state.snap.as_ref().map(|s| s.status.vm_rss_kb).unwrap_or(0);

    let label = state
        .target_label
        .as_deref()
        .map(|l| format!(" [ {l} ] "))
        .unwrap_or_default();

    let line = Line::from(vec![
        Span::styled(
            format!(" {} ", state.comm),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!("pid:{} ", state.pid)),
        Span::styled(label, Style::default().fg(Color::Magenta)),
        Span::raw(format!("threads:{threads}  ")),
        Span::raw(format!("rss:{} ", fmt_kb(rss))),
        ebpf_badge,
        Span::raw(" "),
        gone_badge,
    ]);

    let para = Paragraph::new(line).block(Block::default().borders(Borders::BOTTOM));
    f.render_widget(para, area);
}

fn render_sparkline(f: &mut Frame, area: Rect, state: &AppState) {
    let history: Vec<f32> = state.watch.cpu_history.iter().copied().collect();
    widgets::cpu_sparkline(f, area, &history, "CPU %");
}

fn render_syscall_table(f: &mut Frame, area: Rect, state: &AppState, ts: &mut TableState) {
    // Convert SyscallKey/SyscallStat into display tuples.
    let rows: Vec<(u32, &'static str, u64, u64, u64)> = state
        .watch
        .top_syscalls
        .iter()
        .map(|(k, v)| {
            let total_ms = v.total_ns / 1_000_000;
            let max_ms_micro = v.max_ns / 1_000; // show in µs for precision
            (k.nr, syscall_name(k.nr), v.count, total_ms, max_ms_micro)
        })
        .collect();

    widgets::syscall_table(f, area, &rows, ts);
}

fn render_sched_bar(f: &mut Frame, area: Rect, state: &AppState) {
    let vol = state.watch.voluntary_ctx;
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

// ── helpers ───────────────────────────────────────────────────────────────────

fn fmt_kb(kb: u64) -> String {
    if kb < 1024 {
        format!("{kb}K")
    } else {
        format!("{:.1}M", kb as f64 / 1024.0)
    }
}
