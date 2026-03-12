//! Windows NT type definitions for the Winoxide compatibility layer.
//!
//! These types mirror the Windows NT kernel API types with `#[repr(C)]`
//! layout compatibility. Derived from Wine's header files (winnt.h, winternl.h).

#![allow(non_camel_case_types, non_snake_case)]

pub mod primitives;
pub mod ntdef;
pub mod ntstatus;
pub mod peb;
pub mod teb;

pub use primitives::*;
pub use ntdef::*;
pub use ntstatus::*;
