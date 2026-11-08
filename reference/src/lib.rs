//! Executable reference for the Bitcoin consensus specification.
//!
//! This crate contains no hand-written consensus code. `build.rs` assembles it from the normative
//! Rust blocks in `spec/*.md`; read the chapters, not the generated files.

#![allow(clippy::all)]
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/chapters.rs"));
