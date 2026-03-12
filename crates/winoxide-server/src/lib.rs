//! Winoxide kernel object server.
//!
//! This is the equivalent of Wine's wineserver — a separate process that manages
//! kernel objects (handles, synchronization primitives, process/thread state,
//! window message queues, registry, etc.)
//!
//! In Winoxide, this is implemented in safe Rust with an async event loop.

pub mod object;
pub mod handle;
pub mod process;
pub mod thread;
pub mod sync;
pub mod connection;

use winoxide_types::NTSTATUS;

/// Result type for server operations.
pub type ServerResult<T> = Result<T, NTSTATUS>;
