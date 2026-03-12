//! Win32 file I/O — CreateFileW, ReadFile, WriteFile, CloseHandle, etc.

use crate::error::*;
use std::ffi::CString;
use std::os::unix::io::RawFd;

/// CreateFile access flags.
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;

/// CreateFile share modes.
pub const FILE_SHARE_READ: u32 = 0x00000001;
pub const FILE_SHARE_WRITE: u32 = 0x00000002;
pub const FILE_SHARE_DELETE: u32 = 0x00000004;

/// CreateFile creation dispositions.
pub const CREATE_NEW: u32 = 1;
pub const CREATE_ALWAYS: u32 = 2;
pub const OPEN_EXISTING: u32 = 3;
pub const OPEN_ALWAYS: u32 = 4;
pub const TRUNCATE_EXISTING: u32 = 5;

/// File attribute flags.
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
pub const FILE_ATTRIBUTE_READONLY: u32 = 0x01;

/// Invalid handle value for Win32.
pub const INVALID_HANDLE_VALUE: isize = -1;

/// Handle type (simplified — wraps a Unix fd).
pub type HANDLE = isize;

/// CreateFileA — Open or create a file (ANSI version).
///
/// Returns a handle on success, or INVALID_HANDLE_VALUE on failure.
pub fn CreateFileA(
    filename: &str,
    desired_access: u32,
    share_mode: u32,
    _security_attributes: usize, // NULL for now
    creation_disposition: u32,
    _flags_and_attributes: u32,
    _template_file: HANDLE,
) -> HANDLE {
    // Translate Win32 path to Unix path
    let unix_path = win32_path_to_unix(filename);

    let c_path = match CString::new(unix_path) {
        Ok(p) => p,
        Err(_) => {
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    };

    // Build open flags
    let mut flags: i32 = 0;

    let read = (desired_access & GENERIC_READ) != 0;
    let write = (desired_access & GENERIC_WRITE) != 0;
    if read && write {
        flags |= libc::O_RDWR;
    } else if write {
        flags |= libc::O_WRONLY;
    } else {
        flags |= libc::O_RDONLY;
    }

    match creation_disposition {
        CREATE_NEW => flags |= libc::O_CREAT | libc::O_EXCL,
        CREATE_ALWAYS => flags |= libc::O_CREAT | libc::O_TRUNC,
        OPEN_EXISTING => {},
        OPEN_ALWAYS => flags |= libc::O_CREAT,
        TRUNCATE_EXISTING => flags |= libc::O_TRUNC,
        _ => {
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_HANDLE_VALUE;
        }
    }

    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o666) };
    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        SetLastError(errno_to_win32(errno));
        return INVALID_HANDLE_VALUE;
    }

    fd as HANDLE
}

/// ReadFile — Read data from a file.
pub fn ReadFile(
    handle: HANDLE,
    buffer: &mut [u8],
    bytes_read: &mut u32,
) -> bool {
    let fd = handle as RawFd;
    let n = unsafe {
        libc::read(fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len())
    };
    if n < 0 {
        let errno = unsafe { *libc::__errno_location() };
        SetLastError(errno_to_win32(errno));
        *bytes_read = 0;
        false
    } else {
        *bytes_read = n as u32;
        SetLastError(ERROR_SUCCESS);
        true
    }
}

/// WriteFile — Write data to a file.
pub fn WriteFile(
    handle: HANDLE,
    buffer: &[u8],
    bytes_written: &mut u32,
) -> bool {
    let fd = handle as RawFd;
    let n = unsafe {
        libc::write(fd, buffer.as_ptr() as *const libc::c_void, buffer.len())
    };
    if n < 0 {
        let errno = unsafe { *libc::__errno_location() };
        SetLastError(errno_to_win32(errno));
        *bytes_written = 0;
        false
    } else {
        *bytes_written = n as u32;
        SetLastError(ERROR_SUCCESS);
        true
    }
}

/// CloseHandle — Close an open handle.
pub fn CloseHandle(handle: HANDLE) -> bool {
    let fd = handle as RawFd;
    let ret = unsafe { libc::close(fd) };
    if ret < 0 {
        SetLastError(ERROR_INVALID_HANDLE);
        false
    } else {
        SetLastError(ERROR_SUCCESS);
        true
    }
}

/// GetFileSize — Get file size.
pub fn GetFileSize(handle: HANDLE) -> Option<u64> {
    let fd = handle as RawFd;
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    let ret = unsafe { libc::fstat(fd, &mut stat) };
    if ret < 0 {
        SetLastError(ERROR_INVALID_HANDLE);
        None
    } else {
        Some(stat.st_size as u64)
    }
}

/// DeleteFileA — Delete a file.
pub fn DeleteFileA(filename: &str) -> bool {
    let unix_path = win32_path_to_unix(filename);
    let c_path = match CString::new(unix_path) {
        Ok(p) => p,
        Err(_) => {
            SetLastError(ERROR_INVALID_PARAMETER);
            return false;
        }
    };
    let ret = unsafe { libc::unlink(c_path.as_ptr()) };
    if ret < 0 {
        let errno = unsafe { *libc::__errno_location() };
        SetLastError(errno_to_win32(errno));
        false
    } else {
        true
    }
}

/// Convert a Win32-style path to Unix path (simplified).
fn win32_path_to_unix(path: &str) -> String {
    let mut p = path.replace('\\', "/");

    // Handle drive letters: C:\path → /mnt/c/path
    if p.len() >= 2 && p.as_bytes().get(1) == Some(&b':') {
        let drive = (p.as_bytes()[0] as char).to_lowercase().next().unwrap();
        p = format!("/mnt/{drive}{}", &p[2..]);
    }

    p
}

/// Map errno to Win32 error code.
fn errno_to_win32(errno: i32) -> u32 {
    match errno {
        libc::ENOENT => ERROR_FILE_NOT_FOUND,
        libc::EACCES | libc::EPERM => ERROR_ACCESS_DENIED,
        libc::EEXIST => ERROR_FILE_EXISTS,
        libc::ENOMEM => ERROR_NOT_ENOUGH_MEMORY,
        libc::EINVAL => ERROR_INVALID_PARAMETER,
        libc::EBUSY => ERROR_SHARING_VIOLATION,
        _ => ERROR_INVALID_FUNCTION,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_win32_path_to_unix() {
        assert_eq!(win32_path_to_unix("C:\\Users\\test"), "/mnt/c/Users/test");
        assert_eq!(win32_path_to_unix("D:\\data\\file.txt"), "/mnt/d/data/file.txt");
        assert_eq!(win32_path_to_unix("/tmp/test"), "/tmp/test");
    }

    #[test]
    fn test_file_roundtrip() {
        let path = "/tmp/winoxide_kernel32_test.tmp";

        // Create and write
        let h = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
        assert_ne!(h, INVALID_HANDLE_VALUE);

        let data = b"Hello from kernel32!";
        let mut written = 0u32;
        assert!(WriteFile(h, data, &mut written));
        assert_eq!(written, data.len() as u32);
        assert!(CloseHandle(h));

        // Open and read
        let h = CreateFileA(path, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        assert_ne!(h, INVALID_HANDLE_VALUE);

        let size = GetFileSize(h).unwrap();
        assert_eq!(size, data.len() as u64);

        let mut buf = [0u8; 64];
        let mut read = 0u32;
        assert!(ReadFile(h, &mut buf, &mut read));
        assert_eq!(read, data.len() as u32);
        assert_eq!(&buf[..read as usize], data);
        assert!(CloseHandle(h));

        // Delete
        assert!(DeleteFileA(path));
    }

    #[test]
    fn test_open_nonexistent() {
        let h = CreateFileA("/tmp/winoxide_nonexistent_xyz.tmp", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        assert_eq!(h, INVALID_HANDLE_VALUE);
        assert_eq!(GetLastError(), ERROR_FILE_NOT_FOUND);
    }
}
