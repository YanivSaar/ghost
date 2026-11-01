//! The six lenses (ARCHITECTURE §9). Each `impl Mode` declares its probes,
//! folds events into its own state, and produces a screen view-model.
pub mod catch;
pub mod cold;
pub mod jitter;
pub mod lock;
pub mod mode;
pub mod snap;
pub mod watch;
