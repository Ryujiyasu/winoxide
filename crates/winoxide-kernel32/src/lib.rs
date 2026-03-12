//! Win32 kernel API — kernel32.dll / kernelbase.dll equivalent.
//!
//! This crate implements the Win32 "base" APIs:
//! - File I/O (CreateFile, ReadFile, WriteFile, CloseHandle)
//! - Process/thread management (CreateProcess, GetCurrentProcess, ExitProcess)
//! - Memory (VirtualAlloc, VirtualFree, HeapAlloc, HeapFree)
//! - Synchronization (CreateEvent, WaitForSingleObject, CreateMutex)
//! - Console I/O (WriteConsole, ReadConsole)
//! - String/locale functions (GetModuleFileName, GetLastError, SetLastError)
//! - Registry forwarding (RegOpenKeyEx, etc.)

#![allow(non_snake_case)]

pub mod file;
pub mod process;
pub mod memory;
pub mod sync;
pub mod console;
pub mod error;
pub mod module;
