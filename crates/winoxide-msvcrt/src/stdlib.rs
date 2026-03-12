//! Standard library — malloc, free, calloc, realloc, exit, abort, atoi, etc.

use std::ffi::CStr;
use std::os::raw::c_char;

/// malloc
pub fn malloc(size: usize) -> *mut u8 {
    unsafe { libc::malloc(size) as *mut u8 }
}

/// calloc
pub fn calloc(count: usize, size: usize) -> *mut u8 {
    unsafe { libc::calloc(count, size) as *mut u8 }
}

/// realloc
pub fn realloc(ptr: *mut u8, size: usize) -> *mut u8 {
    unsafe { libc::realloc(ptr as *mut libc::c_void, size) as *mut u8 }
}

/// free
pub fn free(ptr: *mut u8) {
    unsafe { libc::free(ptr as *mut libc::c_void) }
}

/// exit
pub fn exit(status: i32) -> ! {
    unsafe { libc::exit(status) }
}

/// abort
pub fn abort() -> ! {
    unsafe { libc::abort() }
}

/// atoi — convert string to integer.
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn atoi(s: *const c_char) -> i32 {
    if s.is_null() {
        return 0;
    }
    let cs = CStr::from_ptr(s);
    match cs.to_str() {
        Ok(string) => string.trim().parse().unwrap_or(0),
        Err(_) => 0,
    }
}

/// _errno — return pointer to thread-local errno.
pub fn _errno() -> *mut i32 {
    unsafe { libc::__errno_location() }
}

/// getenv
///
/// # Safety
/// `name` must be a valid null-terminated C string.
pub unsafe fn getenv(name: *const c_char) -> *const c_char {
    libc::getenv(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malloc_free() {
        let ptr = malloc(256);
        assert!(!ptr.is_null());
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }
        free(ptr);
    }

    #[test]
    fn test_calloc() {
        let ptr = calloc(10, 4);
        assert!(!ptr.is_null());
        // Should be zeroed
        unsafe {
            for i in 0..40 {
                assert_eq!(*ptr.add(i), 0);
            }
        }
        free(ptr);
    }

    #[test]
    fn test_atoi() {
        unsafe {
            assert_eq!(atoi(b"42\0".as_ptr() as *const c_char), 42);
            assert_eq!(atoi(b"-7\0".as_ptr() as *const c_char), -7);
            assert_eq!(atoi(b"abc\0".as_ptr() as *const c_char), 0);
        }
    }
}
