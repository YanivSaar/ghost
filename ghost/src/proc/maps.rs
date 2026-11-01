//! /proc reader: `maps`. Hand-rolled parse (stable format, reused buffers,
//! graceful on missing fields); any read may ENOENT if the target exits (§7). TODO.
