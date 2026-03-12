//! Winoxide execution engine.
//!
//! Loads Windows PE executables, resolves their imports against
//! Rust-implemented DLLs, and provides the runtime environment.

#![allow(non_snake_case)]

pub mod api_table;
pub mod vfs;
pub mod process_env;
pub mod engine;
