//! Standard I/O — printf, puts, fprintf, fputs, fopen, fclose, etc.
//!
//! These functions provide C-style I/O by wrapping Rust/libc I/O.

use std::ffi::CStr;
use std::os::raw::c_char;

/// puts — write a string + newline to stdout.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn puts(s: *const c_char) -> i32 {
    if s.is_null() {
        return -1;
    }
    let cs = CStr::from_ptr(s);
    match cs.to_str() {
        Ok(string) => {
            println!("{}", string);
            1 // non-negative on success
        }
        Err(_) => -1,
    }
}

/// putchar — write a character to stdout.
pub fn putchar(c: i32) -> i32 {
    let ch = c as u8 as char;
    print!("{}", ch);
    c
}

/// fputs — write a string to a FILE stream (simplified: only supports stdout/stderr).
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn fputs(s: *const c_char, stream: *mut libc::FILE) -> i32 {
    if s.is_null() {
        return -1;
    }
    let ret = libc::fputs(s, stream);
    ret
}

/// fwrite — write data to a FILE stream.
///
/// # Safety
/// `ptr` must be valid for `size * count` bytes.
pub unsafe fn fwrite(
    ptr: *const u8,
    size: usize,
    count: usize,
    stream: *mut libc::FILE,
) -> usize {
    libc::fwrite(ptr as *const libc::c_void, size, count, stream)
}

/// printf — formatted output to stdout (simplified: just outputs the format string).
///
/// Full printf formatting is complex; this is a basic implementation.
///
/// # Safety
/// `format` must be a valid null-terminated C string.
pub unsafe fn printf_simple(format: *const c_char) -> i32 {
    if format.is_null() {
        return -1;
    }
    let cs = CStr::from_ptr(format);
    match cs.to_str() {
        Ok(s) => {
            print!("{}", s);
            s.len() as i32
        }
        Err(_) => -1,
    }
}

/// _write — low-level write to file descriptor (msvcrt internal).
pub fn _write(fd: i32, buffer: *const u8, count: u32) -> i32 {
    let n = unsafe {
        libc::write(fd, buffer as *const libc::c_void, count as usize)
    };
    n as i32
}

/// _read — low-level read from file descriptor.
pub fn _read(fd: i32, buffer: *mut u8, count: u32) -> i32 {
    let n = unsafe {
        libc::read(fd, buffer as *mut libc::c_void, count as usize)
    };
    n as i32
}

/// __acrt_iob_func — return stdin/stdout/stderr FILE pointers.
///
/// # Safety
/// Returns a raw FILE pointer.
pub unsafe fn __acrt_iob_func(index: u32) -> *mut libc::FILE {
    match index {
        0 => libc_stdin(),
        1 => libc_stdout(),
        2 => libc_stderr(),
        _ => std::ptr::null_mut(),
    }
}

unsafe fn libc_stdin() -> *mut libc::FILE {
    libc::fdopen(0, b"r\0".as_ptr() as *const c_char)
}

unsafe fn libc_stdout() -> *mut libc::FILE {
    libc::fdopen(1, b"w\0".as_ptr() as *const c_char)
}

unsafe fn libc_stderr() -> *mut libc::FILE {
    libc::fdopen(2, b"w\0".as_ptr() as *const c_char)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_puts() {
        unsafe {
            let s = b"hello from msvcrt\0";
            let ret = puts(s.as_ptr() as *const c_char);
            assert!(ret >= 0);
        }
    }

    #[test]
    fn test_write_read() {
        // Create a pipe for testing
        let mut fds = [0i32; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };

        let data = b"test";
        let written = _write(fds[1], data.as_ptr(), data.len() as u32);
        assert_eq!(written, 4);

        let mut buf = [0u8; 4];
        let read = _read(fds[0], buf.as_mut_ptr(), 4);
        assert_eq!(read, 4);
        assert_eq!(&buf, b"test");

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
