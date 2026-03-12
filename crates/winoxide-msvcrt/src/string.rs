//! String functions — strlen, strcpy, strcmp, memcpy, memset, etc.
//!
//! These wrap libc implementations directly.

use std::os::raw::c_char;

/// strlen
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn strlen(s: *const c_char) -> usize {
    libc::strlen(s)
}

/// strcpy
///
/// # Safety
/// `dest` must have enough space for the source string.
pub unsafe fn strcpy(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    libc::strcpy(dest, src)
}

/// strncpy
///
/// # Safety
/// `dest` must have at least `n` bytes of space.
pub unsafe fn strncpy(dest: *mut c_char, src: *const c_char, n: usize) -> *mut c_char {
    libc::strncpy(dest, src, n)
}

/// strcmp
///
/// # Safety
/// Both strings must be valid null-terminated C strings.
pub unsafe fn strcmp(s1: *const c_char, s2: *const c_char) -> i32 {
    libc::strcmp(s1, s2)
}

/// strncmp
///
/// # Safety
/// Both pointers must be valid for at least `n` bytes.
pub unsafe fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> i32 {
    libc::strncmp(s1, s2, n)
}

/// _stricmp — case-insensitive string comparison (MSVC extension).
///
/// # Safety
/// Both strings must be valid null-terminated C strings.
pub unsafe fn _stricmp(s1: *const c_char, s2: *const c_char) -> i32 {
    libc::strcasecmp(s1, s2)
}

/// strcat
///
/// # Safety
/// `dest` must have enough space for the concatenation.
pub unsafe fn strcat(dest: *mut c_char, src: *const c_char) -> *mut c_char {
    libc::strcat(dest, src)
}

/// strchr
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn strchr(s: *const c_char, c: i32) -> *const c_char {
    libc::strchr(s, c)
}

/// strrchr
///
/// # Safety
/// `s` must be a valid null-terminated C string.
pub unsafe fn strrchr(s: *const c_char, c: i32) -> *const c_char {
    libc::strrchr(s, c)
}

/// strstr
///
/// # Safety
/// Both strings must be valid null-terminated C strings.
pub unsafe fn strstr(haystack: *const c_char, needle: *const c_char) -> *const c_char {
    libc::strstr(haystack, needle)
}

/// memcpy
///
/// # Safety
/// `dest` and `src` must be valid for `n` bytes and not overlap.
pub unsafe fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    libc::memcpy(dest as *mut libc::c_void, src as *const libc::c_void, n) as *mut u8
}

/// memmove
///
/// # Safety
/// `dest` and `src` must be valid for `n` bytes (may overlap).
pub unsafe fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    libc::memmove(dest as *mut libc::c_void, src as *const libc::c_void, n) as *mut u8
}

/// memset
///
/// # Safety
/// `dest` must be valid for `n` bytes.
pub unsafe fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    libc::memset(dest as *mut libc::c_void, c, n) as *mut u8
}

/// memcmp
///
/// # Safety
/// Both pointers must be valid for `n` bytes.
pub unsafe fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    libc::memcmp(s1 as *const libc::c_void, s2 as *const libc::c_void, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strlen() {
        unsafe {
            assert_eq!(strlen(b"hello\0".as_ptr() as *const c_char), 5);
            assert_eq!(strlen(b"\0".as_ptr() as *const c_char), 0);
        }
    }

    #[test]
    fn test_strcmp() {
        unsafe {
            assert_eq!(strcmp(
                b"abc\0".as_ptr() as *const c_char,
                b"abc\0".as_ptr() as *const c_char,
            ), 0);
            assert!(strcmp(
                b"abc\0".as_ptr() as *const c_char,
                b"abd\0".as_ptr() as *const c_char,
            ) < 0);
        }
    }

    #[test]
    fn test_stricmp() {
        unsafe {
            assert_eq!(_stricmp(
                b"Hello\0".as_ptr() as *const c_char,
                b"hello\0".as_ptr() as *const c_char,
            ), 0);
        }
    }

    #[test]
    fn test_memcpy_memset() {
        let mut buf = [0u8; 8];
        let src = [1u8, 2, 3, 4];
        unsafe {
            memcpy(buf.as_mut_ptr(), src.as_ptr(), 4);
            assert_eq!(&buf[..4], &[1, 2, 3, 4]);

            memset(buf.as_mut_ptr(), 0xFF, 4);
            assert_eq!(&buf[..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        }
    }
}
