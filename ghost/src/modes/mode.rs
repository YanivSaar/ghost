//! The extension point. A new lens is a new `impl Mode` + a screen; nothing
//! else in the system needs to know it exists (ARCHITECTURE §12).

use ghost_common::EventKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModeId {
    Snap,
    Watch,
    Lock,
    Catch,
    Cold,
    Jitter,
}

/// A probe this mode needs attached; the loader attaches the union across modes.
#[derive(Clone, Copy, Debug)]
pub enum Probe {
    RawTracepoint(&'static str),
    Tracepoint(&'static str, &'static str),
    Kprobe(&'static str),
    Kretprobe(&'static str),
    Uprobe {
        object: &'static str,
        symbol: &'static str,
    },
}

/// Immutable snapshot a mode hands the render thread each frame.
/// Concrete per-lens payloads live in `state.rs` (WatchState, LockLensState,
/// CatchLensState, …); this struct is just the discriminant the TUI
/// dispatches on when it doesn't already know the mode from `AppState.mode`.
pub struct ModeView {
    pub id: ModeId,
}

pub trait Mode: Send {
    fn id(&self) -> ModeId;
    fn probes(&self) -> &'static [Probe];
    /// Hot path. No allocation.
    fn on_event(&mut self, kind: EventKind, bytes: &[u8], now: u64);
    /// Periodic decay / windowing.
    fn tick(&mut self, now: u64);
    fn view(&self) -> ModeView;
    /// Reset aggregates (replay seek, --clear).
    fn reset(&mut self);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn mode_id_variants_are_distinct() {
        let mut s = HashSet::new();
        for id in [
            ModeId::Snap,
            ModeId::Watch,
            ModeId::Lock,
            ModeId::Catch,
            ModeId::Cold,
            ModeId::Jitter,
        ] {
            assert!(s.insert(id), "duplicate ModeId: {id:?}");
        }
    }

    #[test]
    fn mode_id_equality_and_copy() {
        let a = ModeId::Snap;
        let b = a; // Copy
        assert_eq!(a, b);
        assert_ne!(ModeId::Snap, ModeId::Watch);
    }

    #[test]
    fn probe_debug_preserves_identifiers() {
        let p = Probe::Tracepoint("sched", "sched_switch");
        let d = format!("{p:?}");
        assert!(d.contains("sched_switch"), "debug lost the symbol: {d}");
        assert!(d.contains("sched"), "debug lost the category: {d}");
    }

    #[test]
    fn probe_variants_covered() {
        // Compile-time check: every variant can be constructed; also a
        // smoke test that the Debug impl doesn't blow up for any shape.
        let _ = format!("{:?}", Probe::RawTracepoint("x"));
        let _ = format!("{:?}", Probe::Tracepoint("x", "y"));
        let _ = format!("{:?}", Probe::Kprobe("x"));
        let _ = format!("{:?}", Probe::Kretprobe("x"));
        let _ = format!(
            "{:?}",
            Probe::Uprobe {
                object: "libc.so",
                symbol: "malloc",
            }
        );
    }

    #[test]
    fn mode_view_carries_discriminant() {
        let v = ModeView { id: ModeId::Lock };
        assert_eq!(v.id, ModeId::Lock);
    }
}
