//! The extension point. A new lens is a new `impl Mode` + a screen; nothing
//! else in the system needs to know it exists (ARCHITECTURE §12).

use ghost_common::EventKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ModeId { Snap, Watch, Lock, Catch, Cold, Jitter }

/// A probe this mode needs attached; the loader attaches the union across modes.
#[derive(Clone, Copy, Debug)]
pub enum Probe {
    RawTracepoint(&'static str),
    Tracepoint(&'static str, &'static str),
    Kprobe(&'static str),
    Kretprobe(&'static str),
    Uprobe { object: &'static str, symbol: &'static str },
}

/// Immutable snapshot a mode hands the render thread each frame.
pub struct ModeView {
    pub id: ModeId,
    // TODO(phase 2+): concrete per-mode view-model payloads.
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
