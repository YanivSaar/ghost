//! Render loop + input (ARCHITECTURE §10).
//!
//! Enters raw mode, sets up a Drop guard that restores the terminal on
//! panic or signal, then drives a ~30 fps render loop. Probes mouse
//! capability at startup and enables clickable elements only when supported.

use std::{
    io::{self, Stdout},
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, widgets::TableState, Terminal};

use crate::{
    state::{ActiveMode, AppState},
    tui::screens::{analyze, catch, cold, jitter, lock, overview},
};

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    mouse: bool,
    dense: bool,
    table_state: TableState,
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
                self.terminal.draw(|f| match (st.mode, dense) {
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
                    (_, true) => overview::render_dense(f, &st, ts),
                    (_, false) => overview::render_minimal(f, &st, ts),
                })?;
            }

            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            // Poll input (30 fps = ~33ms).
            if event::poll(Duration::from_millis(33))? {
                match event::read()? {
                    Event::Key(key) => match self.handle_key(key) {
                        KeyAction::Quit => {
                            stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
                        KeyAction::GotoAnalyze => {
                            state.write().unwrap().mode = ActiveMode::Analyze;
                        }
                        KeyAction::ToggleAnalyzeMode => {
                            let mut s = state.write().unwrap();
                            s.analyze.mode = match s.analyze.mode {
                                crate::analyze::Mode::Quiet => crate::analyze::Mode::Noisy,
                                crate::analyze::Mode::Noisy => crate::analyze::Mode::Quiet,
                            };
                        }
                        KeyAction::CycleConfidenceFloor => {
                            // Session-only cycle (persisted to AnalyzerState).
                            let mut s = state.write().unwrap();
                            s.analyze.global_floor = cycle_floor(s.analyze.global_floor);
                        }
                        KeyAction::None => {}
                    },
                    Event::Resize(_, _) => {
                        self.terminal.autoresize()?;
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn handle_key(&mut self, key: KeyEvent) -> KeyAction {
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                KeyAction::Quit
            }
            (KeyCode::Char('a'), _) => KeyAction::GotoAnalyze,
            (KeyCode::Char('n'), _) => KeyAction::ToggleAnalyzeMode,
            (KeyCode::Char('f'), _) => KeyAction::CycleConfidenceFloor,
            (KeyCode::Char('v'), _) => {
                self.dense = !self.dense;
                KeyAction::None
            }
            (KeyCode::Down, _) => {
                let i = self.table_state.selected().map(|i| i + 1).unwrap_or(0);
                self.table_state.select(Some(i));
                KeyAction::None
            }
            (KeyCode::Up, _) => {
                let i = self
                    .table_state
                    .selected()
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.table_state.select(Some(i));
                KeyAction::None
            }
            _ => KeyAction::None,
        }
    }
}

enum KeyAction {
    None,
    Quit,
    GotoAnalyze,
    ToggleAnalyzeMode,
    CycleConfidenceFloor,
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
                    (_, true) => screens::overview::render_dense(f, &st, &mut ts),
                    (_, false) => screens::overview::render_minimal(f, &st, &mut ts),
                })
                .unwrap_or_else(|e| panic!("render failed for {m:?} dense={dense}: {e}"));
            }
        }
    }
}
