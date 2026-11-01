//! Record / replay (ARCHITECTURE §8). .ghost = header + JSON metadata +
//! LZ4-framed raw event stream + per-second seek index.
pub mod format;
pub mod writer;
pub mod reader;
