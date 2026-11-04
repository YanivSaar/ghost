//! One module per screen (overview, syscalls, memory, locks, network, scheduler,
//! catch, startup, jitter, session/tree). Each renders both dense + minimal. TODO.
pub mod analyze;
pub mod catch;
pub mod cold;
pub mod help;
pub mod jitter;
pub mod lock;
pub mod overview;
pub mod snap;
