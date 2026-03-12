//! GetLastError / SetLastError — per-thread error code management.

use std::cell::Cell;

thread_local! {
    static LAST_ERROR: Cell<u32> = const { Cell::new(0) };
}

/// GetLastError — retrieve the calling thread's last-error code.
pub fn GetLastError() -> u32 {
    LAST_ERROR.with(|e| e.get())
}

/// SetLastError — set the calling thread's last-error code.
pub fn SetLastError(error: u32) {
    LAST_ERROR.with(|e| e.set(error));
}

// Common Win32 error codes
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_INVALID_FUNCTION: u32 = 1;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
pub const ERROR_INVALID_DATA: u32 = 13;
pub const ERROR_OUTOFMEMORY: u32 = 14;
pub const ERROR_INVALID_DRIVE: u32 = 15;
pub const ERROR_NO_MORE_FILES: u32 = 18;
pub const ERROR_NOT_READY: u32 = 21;
pub const ERROR_SHARING_VIOLATION: u32 = 32;
pub const ERROR_FILE_EXISTS: u32 = 80;
pub const ERROR_INVALID_PARAMETER: u32 = 87;
pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_ALREADY_EXISTS: u32 = 183;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;
pub const ERROR_IO_PENDING: u32 = 997;

/// Map NTSTATUS to Win32 error code (simplified).
pub fn ntstatus_to_win32(status: i32) -> u32 {
    use winoxide_types::*;
    match status {
        STATUS_SUCCESS => ERROR_SUCCESS,
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_NO_SUCH_FILE => ERROR_FILE_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND => ERROR_PATH_NOT_FOUND,
        STATUS_ACCESS_DENIED => ERROR_ACCESS_DENIED,
        STATUS_INVALID_HANDLE => ERROR_INVALID_HANDLE,
        STATUS_NO_MEMORY => ERROR_NOT_ENOUGH_MEMORY,
        STATUS_INVALID_PARAMETER => ERROR_INVALID_PARAMETER,
        STATUS_SHARING_VIOLATION => ERROR_SHARING_VIOLATION,
        STATUS_OBJECT_NAME_COLLISION => ERROR_ALREADY_EXISTS,
        STATUS_BUFFER_TOO_SMALL => ERROR_INSUFFICIENT_BUFFER,
        STATUS_PENDING => ERROR_IO_PENDING,
        _ => ERROR_INVALID_FUNCTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_error() {
        SetLastError(0);
        assert_eq!(GetLastError(), 0);

        SetLastError(ERROR_FILE_NOT_FOUND);
        assert_eq!(GetLastError(), ERROR_FILE_NOT_FOUND);

        SetLastError(ERROR_SUCCESS);
        assert_eq!(GetLastError(), ERROR_SUCCESS);
    }

    #[test]
    fn test_ntstatus_mapping() {
        assert_eq!(ntstatus_to_win32(winoxide_types::STATUS_SUCCESS), ERROR_SUCCESS);
        assert_eq!(ntstatus_to_win32(winoxide_types::STATUS_ACCESS_DENIED), ERROR_ACCESS_DENIED);
    }
}
