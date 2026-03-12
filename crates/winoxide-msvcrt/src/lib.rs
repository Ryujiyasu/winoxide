//! Microsoft Visual C Runtime — msvcrt.dll / ucrtbase.dll equivalent.
//!
//! Provides the C standard library functions that Windows executables link against:
//! stdio (printf, puts, fprintf), stdlib (malloc, free, exit),
//! string (strlen, strcpy, memcpy), math, and CRT initialization.

#![allow(non_snake_case)]

pub mod stdio;
pub mod stdlib;
pub mod string;
pub mod crt;
