//! Graceful shutdown via `signal-hook`.
//!
//! The TUI already handles Ctrl-C (crossterm reports it as a key event
//! in raw mode, not a signal). What this module adds is a bridge for
//! externally-delivered SIGTERM / SIGINT (think `kill -TERM`, systemd
//! `TimeoutStopSec` shutdown, parent process cleanup) — flipping the
//! shared `stop: Arc<AtomicBool>` so every supervisor loop unwinds
//! cleanly through its Drop guards.
//!
//! `signal_hook::flag::register` writes the flag from an
//! async-signal-safe context (atomic store only; no allocations, no
//! locks), so this is safe to install early in `main`.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};

/// Register SIGINT + SIGTERM to flip `stop` to `true`. Idempotent:
/// re-registration is a no-op per signal-hook contract (each successive
/// register is layered; we accept the layering).
pub fn install_shutdown(stop: &Arc<AtomicBool>) -> Result<()> {
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(stop))
        .context("registering SIGINT handler")?;
    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(stop))
        .context("registering SIGTERM handler")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn install_shutdown_registers_without_error() {
        let stop = Arc::new(AtomicBool::new(false));
        install_shutdown(&stop).expect("install SIGINT+SIGTERM");
        // Not flipped by install itself.
        assert!(!stop.load(Ordering::Relaxed));
    }

    #[test]
    fn signal_delivery_flips_stop() {
        // Deliver SIGTERM to ourselves and prove the handler flips it.
        // We register with a fresh Arc so a previous test's registration
        // can't shadow this one's observation.
        let stop = Arc::new(AtomicBool::new(false));
        install_shutdown(&stop).expect("install");
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        // The signal is delivered synchronously by `raise(3)`, so the
        // flag must be set before we return.
        assert!(
            stop.load(Ordering::Relaxed),
            "SIGTERM should have flipped the stop flag"
        );
    }
}
