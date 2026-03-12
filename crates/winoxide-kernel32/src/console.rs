//! Win32 Console I/O — WriteConsole, ReadConsole, AllocConsole, etc.

use crate::error::*;

/// Standard handle constants.
pub const STD_INPUT_HANDLE: u32 = 0xFFFFFFF6; // -10
pub const STD_OUTPUT_HANDLE: u32 = 0xFFFFFFF5; // -11
pub const STD_ERROR_HANDLE: u32 = 0xFFFFFFF4; // -12

/// GetStdHandle — Return a handle to standard input/output/error.
pub fn GetStdHandle(std_handle: u32) -> isize {
    match std_handle {
        STD_INPUT_HANDLE => 0,  // stdin fd
        STD_OUTPUT_HANDLE => 1, // stdout fd
        STD_ERROR_HANDLE => 2,  // stderr fd
        _ => {
            SetLastError(ERROR_INVALID_HANDLE);
            -1
        }
    }
}

/// WriteConsoleA — Write a string to the console (ANSI).
pub fn WriteConsoleA(
    handle: isize,
    buffer: &[u8],
    chars_written: &mut u32,
) -> bool {
    let fd = handle as i32;
    let n = unsafe {
        libc::write(fd, buffer.as_ptr() as *const libc::c_void, buffer.len())
    };
    if n < 0 {
        *chars_written = 0;
        false
    } else {
        *chars_written = n as u32;
        true
    }
}

/// OutputDebugStringA — Send a string to the debugger (we print to stderr).
pub fn OutputDebugStringA(message: &str) {
    eprintln!("[OutputDebugString] {}", message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_std_handle() {
        assert_eq!(GetStdHandle(STD_INPUT_HANDLE), 0);
        assert_eq!(GetStdHandle(STD_OUTPUT_HANDLE), 1);
        assert_eq!(GetStdHandle(STD_ERROR_HANDLE), 2);
    }

    #[test]
    fn test_write_console() {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut written = 0u32;
        // Write to stdout (will appear in test output)
        let result = WriteConsoleA(handle, b"", &mut written);
        assert!(result);
    }
}
