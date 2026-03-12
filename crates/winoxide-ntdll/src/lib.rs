//! Winoxide ntdll — NT system call implementations.
//!
//! This crate provides the Unix-side implementations of NT system calls.
//! Each Nt* function translates Windows semantics to Linux syscalls,
//! communicating with the winoxide-server for kernel object management.

#![allow(non_snake_case)]

pub mod file;
pub mod sync;
pub mod process;
pub mod memory;

use winoxide_types::*;
