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
    tui::screens::{catch, cold, jitter, lock, overview},
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

        let mouse = probe_mouse(&mut stdout);

        execute!(stdout, EnterAlternateScreen)?;
        if mouse {
            execute!(stdout, EnableMouseCapture)?;
        }

        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

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
                    Event::Key(key) => {
                        if self.handle_key(key) {
                            stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            break;
                        }
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

    /// Returns true if the user requested quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Char('q'), _) | (KeyCode::Char('c'), KeyModifiers::CONTROL) => true,

            (KeyCode::Char('v'), _) => {
                self.dense = !self.dense;
                false
            }
            (KeyCode::Down, _) => {
                let i = self.table_state.selected().map(|i| i + 1).unwrap_or(0);
                self.table_state.select(Some(i));
                false
            }
            (KeyCode::Up, _) => {
                let i = self
                    .table_state
                    .selected()
                    .map(|i| i.saturating_sub(1))
                    .unwrap_or(0);
                self.table_state.select(Some(i));
                false
            }
            _ => false,
        }
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        if self.mouse {
            let _ = execute!(self.terminal.backend_mut(), DisableMouseCapture);
        }
        let _ = self.terminal.show_cursor();
    }
}

/// Try enabling mouse capture; if the terminal refuses, disable it and carry on.
fn probe_mouse(stdout: &mut Stdout) -> bool {
    execute!(stdout, EnableMouseCapture).is_ok()
        && execute!(stdout, DisableMouseCapture).is_ok()
        // Re-check: if disable worked, enable is supported.
        && execute!(stdout, EnableMouseCapture).is_ok()
}
