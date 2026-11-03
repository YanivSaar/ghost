//! Panic hook that restores the terminal before the backtrace prints.
//!
//! The TUI entered raw mode + alt screen + (sometimes) mouse capture.
//! `Tui::drop` reverses all of that on normal exit, but a panic can
//! unwind past the Drop guard — leaving the user with a broken raw-mode
//! terminal they must `reset` by hand. Installing a `std::panic::set_hook`
//! before the TUI starts means the terminal always resets, whether we
//! exit cleanly or via panic.
//!
//! The reset is unconditional (we don't track whether mouse was enabled)
//! because the ioctls are idempotent on failure: disabling mouse that
//! wasn't enabled is a no-op, same for the other primitives.

use crossterm::{
    event::DisableMouseCapture,
    execute,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
};
use std::io::{self, Write};
use std::sync::Once;

static INSTALLED: Once = Once::new();

/// Chain a terminal-reset ahead of the default panic hook. Idempotent:
/// safe to call more than once from main / tests.
pub fn install() {
    INSTALLED.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            reset_terminal();
            default_hook(info);
        }));
    });
}

/// Best-effort: swallow every error. The reset primitives are
/// independent, so a failed `disable_raw_mode` must not block the
/// other steps.
pub fn reset_terminal() {
    let mut stdout = io::stdout();
    let _ = disable_raw_mode();
    let _ = execute!(stdout, LeaveAlternateScreen);
    let _ = execute!(stdout, DisableMouseCapture);
    // Make the cursor visible — the TUI hid it.
    let _ = execute!(stdout, crossterm::cursor::Show);
    let _ = stdout.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_terminal_does_not_panic_outside_a_tty() {
        // Running under `cargo test` stdout is a pipe — the ioctls will
        // fail; the function must swallow and return normally.
        reset_terminal();
    }

    #[test]
    fn install_is_idempotent() {
        install();
        install();
        // No assertion needed; the point is it doesn't double-wrap or panic.
    }
}
