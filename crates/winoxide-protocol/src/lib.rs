//! Wine server protocol definitions for Winoxide.
//!
//! Defines the request/reply message types for communication between
//! ntdll (client) and the kernel object server (wineserver equivalent).

#![allow(non_camel_case_types)]

pub mod types;
pub mod requests;

pub use types::*;
pub use requests::*;
