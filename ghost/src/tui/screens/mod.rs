//! One module per lens. Live screens (`overview`, `lock`, `catch`,
//! `cold`, `jitter`, `analyze`) expose `render_dense` + `render_minimal`;
//! `snap` has a single layout; `help` draws the overlay + first-attach
//! nudge over whichever screen is active.
pub mod analyze;
pub mod catch;
pub mod cold;
pub mod help;
pub mod jitter;
pub mod lock;
pub mod overview;
pub mod snap;
