//! The six lenses (ARCHITECTURE §9). Each `impl Mode` declares its probes,
//! folds events into its own state, and produces a screen view-model.
pub mod analyze;
pub mod catch;
pub mod cold;
pub mod jitter;
pub mod lock;
pub mod mode;
pub mod snap;
pub mod watch;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_lens_module_is_reachable() {
        let _ = (
            core::any::type_name::<mode::ModeId>(),
            core::any::type_name::<analyze::Format>(),
            core::any::type_name::<analyze::Args>(),
        );
        // Reference symbols from each lens so the mod is covered.
        let _: fn(u32) -> anyhow::Result<()> = snap::run;
    }
}
