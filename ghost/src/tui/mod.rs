//! Terminal UI: dual dense/minimal aesthetics over one data model, a screen
//! graph, detected mouse support, and a render loop decoupled from data
//! acquisition (ARCHITECTURE §10).
pub mod app;
pub mod screens;
pub mod syscalls;
pub mod widgets;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tui_submodules_resolve() {
        let _ = core::any::type_name::<app::Tui>();
        let _: fn(u32) -> &'static str = syscalls::syscall_name;
    }
}
