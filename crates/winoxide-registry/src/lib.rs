//! Windows Registry implementation.
//!
//! The registry is a hierarchical key-value database used by Windows for
//! configuration, application settings, and system state.
//!
//! Winoxide stores it as an in-memory tree, persisted to disk as a simple
//! binary format (not the Windows hive format — we use our own for simplicity).

pub mod hive;
pub mod api;

pub use hive::*;
pub use api::*;
