//! Target resolution + the tracked PID set (ARCHITECTURE §4).
pub mod cgroup;
pub mod cmd;
pub mod pid;
pub mod tree;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_submodules_resolve() {
        let _ = core::any::type_name::<pid::PidTarget>();
        let _ = core::any::type_name::<cgroup::CgroupTarget>();
        let _ = core::any::type_name::<tree::TreeTarget>();
        let _ = core::any::type_name::<cmd::CmdHandle>();
    }
}
