//! The six lenses (ARCHITECTURE §9). Each `impl Mode` declares its probes,
//! folds events into its own state, and produces a screen view-model.
pub mod mode;
pub mod snap;
pub mod watch;
pub mod lock;
pub mod catch;
pub mod cold;
pub mod jitter;
