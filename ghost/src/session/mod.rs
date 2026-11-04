//! Record / replay (ARCHITECTURE §8). .ghost = header + JSON metadata +
//! LZ4-framed raw event stream + per-second seek index.
pub mod dir_writer;
pub mod format;
pub mod reader;
pub mod writer;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mod_paths_resolve() {
        let _ = core::any::type_name::<format::SessionMeta>();
        let _ = core::any::type_name::<reader::SessionReader>();
        let _ = core::any::type_name::<writer::SessionWriter>();
    }
}
