//! Win32 synchronization — CreateEvent, WaitForSingleObject, CreateMutex, etc.
//! Stub implementations for now.

use crate::error::*;

pub type HANDLE = isize;
pub const WAIT_OBJECT_0: u32 = 0;
pub const WAIT_TIMEOUT: u32 = 258;
pub const WAIT_FAILED: u32 = 0xFFFFFFFF;
pub const INFINITE: u32 = 0xFFFFFFFF;

/// WaitForSingleObject — stub.
pub fn WaitForSingleObject(_handle: HANDLE, _milliseconds: u32) -> u32 {
    // TODO: implement via server select
    WAIT_OBJECT_0
}

/// WaitForMultipleObjects — stub.
pub fn WaitForMultipleObjects(
    _handles: &[HANDLE],
    _wait_all: bool,
    _milliseconds: u32,
) -> u32 {
    WAIT_OBJECT_0
}
