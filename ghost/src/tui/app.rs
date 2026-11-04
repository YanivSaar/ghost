//! Render loop + input (ARCHITECTURE §10).
//!
//! Enters raw mode, sets up a Drop guard that restores the terminal on
//! panic or signal, then drives a ~30 fps render loop. Probes mouse
//! capability at startup and enables clickable elements only when supported.

use std::{
    io::{self, Stdout, Write},
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::Result;
use crossterm::{
    cursor::MoveTo,
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
        MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, Clear, ClearType, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};
use ratatui::{backend::CrosstermBackend, widgets::TableState, Terminal};

use crate::{
    state::{ActiveMode, AppState},
    tui::{
        screens::{analyze, catch, cold, help, jitter, lock, overview, snap},
        widgets::ModeTabHit,
    },
};

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    mouse: bool,
    dense: bool,
    table_state: TableState,
    show_help: bool,
    /// Hit regions emitted by the last `mode_tabs()` render; the mouse
    /// handler consumes them to map a click to a mode switch.
    tab_hits: Vec<ModeTabHit>,
    /// When Some, show a brief "press ? for help" nudge until this
    /// deadline. Cleared on any keypress.
    nudge_until: Option<Instant>,
}

impl Tui {
    pub fn init() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();

        // Enter alt screen FIRST, before any probe or render. Otherwise
        // the mouse-probe escape sequences land on the main screen and
        // stay visible underneath / after ghost exits.
        execute!(stdout, EnterAlternateScreen)?;

        // Probe mouse support from inside the alt screen so any
        // response bytes don't pollute the user's shell scrollback.
        let mouse = probe_mouse(&mut stdout);
        if mouse {
            execute!(stdout, EnableMouseCapture)?;
        }

        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        // Blank the alt screen so the first ratatui draw starts from a
        // known-clean state (terminals that silently refuse the alt
        // screen would otherwise bleed previous output through).
        terminal.clear()?;

        Ok(Self {
            terminal,
            mouse,
            dense: true,
            table_state: TableState::default(),
            show_help: false,
            tab_hits: Vec::new(),
            // Default nudge: 2.5 s after startup, dismissed on any key.
            nudge_until: Some(Instant::now() + Duration::from_millis(2500)),
        })
    }

    /// Drive the render + input loop until exit is requested or `stop` is set.
    pub fn run(
        &mut self,
        state: Arc<RwLock<AppState>>,
        stop: Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        loop {
            // Render frame.
            {
                let st = state.read().unwrap();
                let dense = self.dense;
                let ts = &mut self.table_state;
                let show_help = self.show_help;
                let show_nudge = self
                    .nudge_until
                    .map(|t| Instant::now() < t)
                    .unwrap_or(false);
                let hits_slot = &mut self.tab_hits;
                self.terminal.draw(|f| {
                    match (st.mode, dense) {
                        (ActiveMode::Lock, true) => lock::render_dense(f, &st, ts),
                        (ActiveMode::Lock, false) => lock::render_minimal(f, &st, ts),
                        (ActiveMode::Catch, true) => catch::render_dense(f, &st, ts),
                        (ActiveMode::Catch, false) => catch::render_minimal(f, &st, ts),
                        (ActiveMode::Cold, true) => cold::render_dense(f, &st, ts),
                        (ActiveMode::Cold, false) => cold::render_minimal(f, &st, ts),
                        (ActiveMode::Jitter, true) => jitter::render_dense(f, &st, ts),
                        (ActiveMode::Jitter, false) => jitter::render_minimal(f, &st, ts),
                        (ActiveMode::Analyze, true) => analyze::render_dense(f, &st, ts),
                        (ActiveMode::Analyze, false) => analyze::render_minimal(f, &st, ts),
                        (ActiveMode::Snap, _) => snap::render(f, &st),
                        (_, true) => overview::render_dense(f, &st, ts),
                        (_, false) => overview::render_minimal(f, &st, ts),
                    }
                    // Shared bottom tab-bar + hit-region capture.
                    *hits_slot = crate::tui::widgets::mode_tabs(f, st.mode);
                    if show_help {
                        help::render_overlay(f);
                    } else if show_nudge {
                        help::render_nudge(f);
                    }
                })?;
            }

            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Poll input (30 fps = ~33ms).
            if event::poll(Duration::from_millis(33))? {
                match event::read()? {
                    Event::Key(key) => {
                        self.nudge_until = None;
                        if self.handle_key_action(key, &state, &stop) {
                            break;
                        }
                    }
                    Event::Mouse(me) => {
                        self.handle_mouse(me, &state);
                    }
                    Event::Resize(_, _) => {
                        self.terminal.autoresize()?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Returns true if the loop should exit now.
    fn handle_key_action(
        &mut self,
        key: KeyEvent,
        state: &Arc<RwLock<AppState>>,
        stop: &Arc<std::sync::atomic::AtomicBool>,
    ) -> bool {
        // Help overlay swallows Esc + ? to dismiss.
        if self.show_help {
            match (key.code, key.modifiers) {
                (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    return true;
                }
                (KeyCode::Esc, _)
                | (KeyCode::Char('?'), _)
                | (KeyCode::F(1), _)
                | (KeyCode::Char('h'), _) => {
                    self.show_help = false;
                }
                _ => {}
            }
            return false;
        }

        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                stop.store(true, std::sync::atomic::Ordering::Relaxed);
                return true;
            }

            // View switching — letters.
            (KeyCode::Char('w'), _) | (KeyCode::Char('1'), _) => {
                state.write().unwrap().mode = ActiveMode::Watch;
            }
            (KeyCode::Char('s'), _) | (KeyCode::Char('2'), _) => {
                state.write().unwrap().mode = ActiveMode::Snap;
            }
            (KeyCode::Char('l'), _) | (KeyCode::Char('3'), _) => {
                state.write().unwrap().mode = ActiveMode::Lock;
            }
            (KeyCode::Char('t'), _) | (KeyCode::Char('4'), _) => {
                // Catch: seed a sensible threshold if the user hadn't armed
                // one at startup, so the view actually fires events.
                let mut st = state.write().unwrap();
                st.mode = ActiveMode::Catch;
                if st.catch.threshold_ns == 0 {
                    st.catch.threshold_ns = 10_000_000; // 10 ms default
                }
            }
            (KeyCode::Char('j'), _) | (KeyCode::Char('5'), _) => {
                state.write().unwrap().mode = ActiveMode::Jitter;
            }
            (KeyCode::Char('a'), _) | (KeyCode::Char('6'), _) => {
                state.write().unwrap().mode = ActiveMode::Analyze;
            }

            // Help overlay.
            (KeyCode::Char('?'), _) | (KeyCode::F(1), _) | (KeyCode::Char('h'), _) => {
                self.show_help = true;
            }

            // Analyze-screen controls.
            (KeyCode::Char('n'), _) => {
                let mut s = state.write().unwrap();
                s.analyze.mode = match s.analyze.mode {
                    crate::analyze::Mode::Quiet => crate::analyze::Mode::Noisy,
                    crate::analyze::Mode::Noisy => crate::analyze::Mode::Quiet,
                };
            }
            (KeyCode::Char('f'), _) => {
                let mut s = state.write().unwrap();
                s.analyze.global_floor = cycle_floor(s.analyze.global_floor);
            }

            // Catch threshold tuning (double / halve).
            (KeyCode::Char('+'), _) | (KeyCode::Char('='), _) => {
                let mut s = state.write().unwrap();
                if s.mode == ActiveMode::Catch {
                    let v = s.catch.threshold_ns.max(100_000).saturating_mul(2);
                    s.catch.threshold_ns = v.min(10_000_000_000); // cap 10 s
                }
            }
            (KeyCode::Char('-'), _) => {
                let mut s = state.write().unwrap();
                if s.mode == ActiveMode::Catch {
                    let v = (s.catch.threshold_ns / 2).max(100_000);
                    s.catch.threshold_ns = v;
                }
            }

            (KeyCode::Char('v'), _) => {
                self.dense = !self.dense;
            }
            (KeyCode::Down, _) => {
                let i = self.table_state.selected().map(|i| i + 1).unwrap_or(0);
                self.table_state.select(Some(i));
            }
            (KeyCode::Up, _) => {
                let i = self
                    .table_state
                    .selected()
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.table_state.select(Some(i));
            }
            _ => {}
        }
        false
    }

    fn handle_mouse(&mut self, me: MouseEvent, state: &Arc<RwLock<AppState>>) {
        self.nudge_until = None;
        match me.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                // Hit-test against the last mode_tabs() layout.
                for hit in &self.tab_hits {
                    if me.row == hit.row && me.column >= hit.col_start && me.column < hit.col_end {
                        let mut st = state.write().unwrap();
                        st.mode = hit.mode;
                        if hit.mode == ActiveMode::Catch && st.catch.threshold_ns == 0 {
                            st.catch.threshold_ns = 10_000_000;
                        }
                        return;
                    }
                }
            }
            MouseEventKind::ScrollDown => {
                let i = self.table_state.selected().map(|i| i + 1).unwrap_or(0);
                self.table_state.select(Some(i));
            }
            MouseEventKind::ScrollUp => {
                let i = self
                    .table_state
                    .selected()
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.table_state.select(Some(i));
            }
            _ => {}
        }
    }
}

fn cycle_floor(c: Option<crate::analyze::Confidence>) -> Option<crate::analyze::Confidence> {
    use crate::analyze::Confidence::*;
    match c {
        None => Some(Low),
        Some(Low) => Some(Medium),
        Some(Medium) => Some(High),
        Some(High) => None,
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        // Reverse order of init: show cursor + disable mouse WHILE the
        // alt screen is still active, then leave the alt screen (which
        // restores the main screen), then drop raw mode.
        let _ = self.terminal.show_cursor();
        if self.mouse {
            let _ = execute!(self.terminal.backend_mut(), DisableMouseCapture);
        }
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = disable_raw_mode();

        // Belt-and-braces: on terminals that silently no-op the alt
        // screen (common on WSL / Windows Terminal defaults, some tmux
        // configs), LeaveAlternateScreen is also a no-op and the TUI
        // content stays on screen, with the next prompt landing inside
        // our status row. Clearing the visible region + homing the
        // cursor fixes both the "alt screen worked" (harmless redraw)
        // and the "alt screen was a no-op" (wipes residue) cases.
        let mut out = io::stdout();
        let _ = execute!(out, Clear(ClearType::All), MoveTo(0, 0));
        let _ = out.flush();
    }
}

/// Try enabling mouse capture; if the terminal refuses, disable it and carry on.
fn probe_mouse(stdout: &mut Stdout) -> bool {
    execute!(stdout, EnableMouseCapture).is_ok()
        && execute!(stdout, DisableMouseCapture).is_ok()
        // Re-check: if disable worked, enable is supported.
        && execute!(stdout, EnableMouseCapture).is_ok()
}

#[cfg(test)]
mod tests {
    use crate::state::{ActiveMode, AppState};
    use crate::tui::screens;
    use ratatui::{backend::TestBackend, Terminal};

    #[test]
    fn screen_dispatch_renders_every_mode_without_panic() {
        // Tui itself owns real stdout + raw mode, which TestBackend can't
        // model. The valuable coverage here is the screen-dispatch arm
        // we call in Tui::run — exercise the same decisions directly.
        let backend = TestBackend::new(80, 24);
        let mut term = Terminal::new(backend).unwrap();
        let modes = [
            ActiveMode::Watch,
            ActiveMode::Snap,
            ActiveMode::Lock,
            ActiveMode::Catch,
            ActiveMode::Cold,
            ActiveMode::Jitter,
            ActiveMode::Analyze,
        ];
        for m in modes {
            for dense in [true, false] {
                let mut st = AppState::new(1234, "test".into());
                st.mode = m;
                let mut ts = ratatui::widgets::TableState::default();
                term.draw(|f| match (st.mode, dense) {
                    (ActiveMode::Lock, true) => screens::lock::render_dense(f, &st, &mut ts),
                    (ActiveMode::Lock, false) => screens::lock::render_minimal(f, &st, &mut ts),
                    (ActiveMode::Catch, true) => screens::catch::render_dense(f, &st, &mut ts),
                    (ActiveMode::Catch, false) => screens::catch::render_minimal(f, &st, &mut ts),
                    (ActiveMode::Cold, true) => screens::cold::render_dense(f, &st, &mut ts),
                    (ActiveMode::Cold, false) => screens::cold::render_minimal(f, &st, &mut ts),
                    (ActiveMode::Jitter, true) => screens::jitter::render_dense(f, &st, &mut ts),
                    (ActiveMode::Jitter, false) => screens::jitter::render_minimal(f, &st, &mut ts),
                    (ActiveMode::Analyze, true) => screens::analyze::render_dense(f, &st, &mut ts),
                    (ActiveMode::Analyze, false) => {
                        screens::analyze::render_minimal(f, &st, &mut ts)
                    }
                    (ActiveMode::Snap, _) => screens::snap::render(f, &st),
                    (_, true) => screens::overview::render_dense(f, &st, &mut ts),
                    (_, false) => screens::overview::render_minimal(f, &st, &mut ts),
                })
                .unwrap_or_else(|e| panic!("render failed for {m:?} dense={dense}: {e}"));
            }
        }
    }

    #[test]
    fn mode_tabs_are_rendered_and_hit_regions_cover_every_mode() {
        use crate::tui::widgets::mode_tabs;
        let backend = TestBackend::new(120, 10);
        let mut term = Terminal::new(backend).unwrap();
        let mut hits = Vec::new();
        term.draw(|f| {
            hits = mode_tabs(f, ActiveMode::Watch);
        })
        .unwrap();
        // One hit per visible lens (Snap/Watch/Lock/Catch/Jitter/Analyze).
        assert!(hits.len() >= 6, "expected ≥6 tab hits, got {}", hits.len());
    }
}
