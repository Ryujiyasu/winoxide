//! NT file operations — NtCreateFile, NtReadFile, NtWriteFile, etc.
//!
//! These translate NT file semantics to Linux file operations.
//! The NT path namespace (\??\C:\path) is mapped to Unix paths.

use winoxide_types::*;
use std::os::unix::io::RawFd;
use std::ffi::CString;

/// Convert an NT path to a Unix path.
///
/// NT paths use backslashes and have prefixes like:
/// - `\??\C:\Users\...` → `/home/...` (via drive mapping)
/// - `\Device\UnixDevice\...` → `/...` (direct mapping)
///
/// This is a simplified version; full implementation needs drive letter mapping.
pub fn nt_path_to_unix(nt_path: &[u16]) -> Option<String> {
    let s: String = String::from_utf16_lossy(nt_path);

    // Strip common NT prefixes
    let stripped = s
        .strip_prefix("\\??\\")
        .or_else(|| s.strip_prefix("\\\\?\\"))
        .or_else(|| s.strip_prefix("\\Device\\UnixRoot"))
        .unwrap_or(&s);

    // Handle drive letters: C:\path → /mnt/c/path (or configurable prefix)
    if stripped.len() >= 2 && stripped.as_bytes()[1] == b':' {
        let drive = (stripped.as_bytes()[0] as char).to_lowercase().next()?;
        let rest = &stripped[2..];
        let unix_rest = rest.replace('\\', "/");
        return Some(format!("/mnt/{drive}{unix_rest}"));
    }

    // Direct backslash → forward slash conversion
    Some(stripped.replace('\\', "/"))
}

/// NtCreateFile — Open or create a file.
///
/// This is the core file open/create function in the NT API.
/// It maps to Linux open(2) with appropriate flag translation.
pub fn NtCreateFile(
    file_handle: &mut HANDLE,
    desired_access: ACCESS_MASK,
    object_attributes: &OBJECT_ATTRIBUTES,
    io_status_block: &mut IO_STATUS_BLOCK,
    _allocation_size: Option<&LARGE_INTEGER>,
    _file_attributes: ULONG,
    share_access: ULONG,
    create_disposition: ULONG,
    create_options: ULONG,
) -> NTSTATUS {
    // Get the NT path from object attributes
    let nt_path = unsafe {
        if object_attributes.ObjectName.is_null() {
            io_status_block.Status = STATUS_OBJECT_NAME_INVALID;
            return STATUS_OBJECT_NAME_INVALID;
        }
        let name = &*object_attributes.ObjectName;
        name.as_slice()
    };

    // Convert NT path to Unix path
    let unix_path = match nt_path_to_unix(nt_path) {
        Some(p) => p,
        None => {
            io_status_block.Status = STATUS_OBJECT_PATH_INVALID;
            return STATUS_OBJECT_PATH_INVALID;
        }
    };

    // Translate NT flags to Linux open flags
    let mut flags: i32 = 0;

    // Access mode
    let read = (desired_access & GENERIC_READ) != 0;
    let write = (desired_access & GENERIC_WRITE) != 0;
    if read && write {
        flags |= libc::O_RDWR;
    } else if write {
        flags |= libc::O_WRONLY;
    } else {
        flags |= libc::O_RDONLY;
    }

    // Creation disposition
    match create_disposition {
        FILE_SUPERSEDE | FILE_OVERWRITE_IF => {
            flags |= libc::O_CREAT | libc::O_TRUNC;
        }
        FILE_CREATE => {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
        FILE_OPEN => {
            // No additional flags
        }
        FILE_OPEN_IF => {
            flags |= libc::O_CREAT;
        }
        FILE_OVERWRITE => {
            flags |= libc::O_TRUNC;
        }
        _ => {
            io_status_block.Status = STATUS_INVALID_PARAMETER;
            return STATUS_INVALID_PARAMETER;
        }
    }

    // Directory handling
    if (create_options & FILE_DIRECTORY_FILE) != 0 {
        flags |= libc::O_DIRECTORY;
    }

    if (create_options & FILE_DELETE_ON_CLOSE) != 0 {
        // Will need to track this and unlink on close
    }

    // Open the file
    let c_path = match CString::new(unix_path) {
        Ok(p) => p,
        Err(_) => {
            io_status_block.Status = STATUS_OBJECT_NAME_INVALID;
            return STATUS_OBJECT_NAME_INVALID;
        }
    };

    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o666) };
    if fd < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let status = errno_to_ntstatus(errno);
        io_status_block.Status = status;
        return status;
    }

    // Store the fd as a HANDLE (in real impl, this goes through the server)
    *file_handle = fd as isize as HANDLE;
    io_status_block.Status = STATUS_SUCCESS;
    io_status_block.Information = if (flags & libc::O_CREAT) != 0 { 2 } else { 1 }; // FILE_CREATED or FILE_OPENED

    STATUS_SUCCESS
}

/// NtReadFile — Read data from a file.
pub fn NtReadFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    io_status_block: &mut IO_STATUS_BLOCK,
    buffer: &mut [u8],
    byte_offset: Option<&LARGE_INTEGER>,
) -> NTSTATUS {
    let fd = file_handle as isize as RawFd;

    let bytes_read = if let Some(offset) = byte_offset {
        unsafe {
            libc::pread(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                offset.quad_part as libc::off_t,
            )
        }
    } else {
        unsafe {
            libc::read(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        }
    };

    if bytes_read < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let status = errno_to_ntstatus(errno);
        io_status_block.Status = status;
        return status;
    }

    io_status_block.Status = STATUS_SUCCESS;
    io_status_block.Information = bytes_read as usize;
    STATUS_SUCCESS
}

/// NtWriteFile — Write data to a file.
pub fn NtWriteFile(
    file_handle: HANDLE,
    _event: HANDLE,
    _apc_routine: PVOID,
    _apc_context: PVOID,
    io_status_block: &mut IO_STATUS_BLOCK,
    buffer: &[u8],
    byte_offset: Option<&LARGE_INTEGER>,
) -> NTSTATUS {
    let fd = file_handle as isize as RawFd;

    let bytes_written = if let Some(offset) = byte_offset {
        unsafe {
            libc::pwrite(
                fd,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
                offset.quad_part as libc::off_t,
            )
        }
    } else {
        unsafe {
            libc::write(
                fd,
                buffer.as_ptr() as *const libc::c_void,
                buffer.len(),
            )
        }
    };

    if bytes_written < 0 {
        let errno = unsafe { *libc::__errno_location() };
        let status = errno_to_ntstatus(errno);
        io_status_block.Status = status;
        return status;
    }

    io_status_block.Status = STATUS_SUCCESS;
    io_status_block.Information = bytes_written as usize;
    STATUS_SUCCESS
}

/// NtClose — Close a handle (simplified: closes the fd directly).
pub fn NtClose(handle: HANDLE) -> NTSTATUS {
    let fd = handle as isize as RawFd;
    let ret = unsafe { libc::close(fd) };
    if ret < 0 {
        STATUS_INVALID_HANDLE
    } else {
        STATUS_SUCCESS
    }
}

/// Map Linux errno to NTSTATUS.
fn errno_to_ntstatus(errno: i32) -> NTSTATUS {
    match errno {
        libc::ENOENT => STATUS_OBJECT_NAME_NOT_FOUND,
        libc::EACCES | libc::EPERM => STATUS_ACCESS_DENIED,
        libc::EEXIST => STATUS_OBJECT_NAME_COLLISION,
        libc::ENOMEM => STATUS_NO_MEMORY,
        libc::ENOTDIR => STATUS_NOT_A_DIRECTORY,
        libc::EISDIR => STATUS_FILE_IS_A_DIRECTORY,
        libc::EINVAL => STATUS_INVALID_PARAMETER,
        libc::ENOSPC => STATUS_INSUFFICIENT_RESOURCES,
        libc::ENFILE | libc::EMFILE => STATUS_INSUFFICIENT_RESOURCES,
        libc::EBUSY => STATUS_SHARING_VIOLATION,
        libc::EXDEV => STATUS_NOT_SAME_DEVICE,
        _ => STATUS_UNSUCCESSFUL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nt_path_to_unix() {
        assert_eq!(
            nt_path_to_unix(&encode_utf16("\\??\\C:\\Users\\test")),
            Some("/mnt/c/Users/test".to_string())
        );
        assert_eq!(
            nt_path_to_unix(&encode_utf16("\\Device\\UnixRoot\\tmp\\test")),
            Some("/tmp/test".to_string())
        );
    }

    #[test]
    fn test_file_roundtrip() {
        use std::io::Write;

        // Create a temp file using std
        let dir = std::env::temp_dir();
        let path = dir.join("winoxide_test_roundtrip.tmp");
        std::fs::write(&path, b"hello winoxide").unwrap();
        let path_str = path.to_str().unwrap();

        // Encode as NT path
        let nt_path = format!("\\Device\\UnixRoot{}", path_str);
        let wide: Vec<u16> = nt_path.encode_utf16().collect();
        let mut name = unsafe { UNICODE_STRING::from_slice(&wide) };

        let mut oa = OBJECT_ATTRIBUTES::default();
        oa.ObjectName = &mut name;

        let mut handle = core::ptr::null_mut();
        let mut iosb = IO_STATUS_BLOCK::default();

        // Open
        let status = NtCreateFile(
            &mut handle,
            GENERIC_READ,
            &oa,
            &mut iosb,
            None,
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            0,
        );
        assert_eq!(status, STATUS_SUCCESS);

        // Read
        let mut buf = [0u8; 64];
        let mut iosb2 = IO_STATUS_BLOCK::default();
        let status = NtReadFile(handle, core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(), &mut iosb2, &mut buf, None);
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(&buf[..iosb2.Information], b"hello winoxide");

        // Close
        assert_eq!(NtClose(handle), STATUS_SUCCESS);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    fn encode_utf16(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }
}
