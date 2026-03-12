//! Fundamental Windows primitive types.
//!
//! Maps C typedefs from winnt.h / basetsd.h / minwindef.h to Rust types.

use core::ffi::c_void;

// === Integer primitives ===

pub type BYTE = u8;
pub type BOOLEAN = u8;
pub type UCHAR = u8;
pub type CHAR = i8;
pub type CCHAR = i8;

pub type SHORT = i16;
pub type CSHORT = i16;
pub type USHORT = u16;
pub type WORD = u16;
pub type WCHAR = u16;
pub type LANGID = u16;
pub type ATOM = u16;

pub type INT = i32;
pub type UINT = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type DWORD = u32;
pub type HRESULT = i32;
pub type ACCESS_MASK = u32;
pub type LCID = u32;

pub type LONGLONG = i64;
pub type ULONGLONG = u64;
pub type DWORDLONG = u64;

// === Pointer-sized types ===

pub type INT_PTR = isize;
pub type UINT_PTR = usize;
pub type LONG_PTR = isize;
pub type ULONG_PTR = usize;
pub type DWORD_PTR = usize;
pub type SIZE_T = usize;
pub type KAFFINITY = usize;

// === Pointer types ===

pub type PVOID = *mut c_void;
pub type HANDLE = *mut c_void;
pub type PHANDLE = *mut HANDLE;
pub type HMODULE = *mut c_void;

pub type PWSTR = *mut u16;
pub type PCWSTR = *const u16;
pub type PSTR = *mut i8;
pub type PCSTR = *const i8;

// === Special values ===

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
pub const NULL_HANDLE: HANDLE = core::ptr::null_mut();

pub const TRUE: BOOLEAN = 1;
pub const FALSE: BOOLEAN = 0;

// === Compound types ===

/// 64-bit integer union (LARGE_INTEGER).
/// In Windows this is a union of {LowPart, HighPart} and QuadPart.
/// We represent it as i64 and provide accessor methods.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LARGE_INTEGER {
    pub quad_part: i64,
}

impl LARGE_INTEGER {
    pub const fn new(value: i64) -> Self {
        Self { quad_part: value }
    }

    pub const fn low_part(&self) -> u32 {
        self.quad_part as u32
    }

    pub const fn high_part(&self) -> i32 {
        (self.quad_part >> 32) as i32
    }

    pub const fn from_parts(low: u32, high: i32) -> Self {
        Self {
            quad_part: (low as i64) | ((high as i64) << 32),
        }
    }
}

/// Unsigned 64-bit integer union (ULARGE_INTEGER).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ULARGE_INTEGER {
    pub quad_part: u64,
}

impl ULARGE_INTEGER {
    pub const fn new(value: u64) -> Self {
        Self { quad_part: value }
    }

    pub const fn low_part(&self) -> u32 {
        self.quad_part as u32
    }

    pub const fn high_part(&self) -> u32 {
        (self.quad_part >> 32) as u32
    }
}

/// Doubly-linked list entry (LIST_ENTRY).
#[repr(C)]
#[derive(Debug)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

impl Default for LIST_ENTRY {
    fn default() -> Self {
        Self {
            Flink: core::ptr::null_mut(),
            Blink: core::ptr::null_mut(),
        }
    }
}

/// File time (100-nanosecond intervals since 1601-01-01).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FILETIME {
    pub dwLowDateTime: DWORD,
    pub dwHighDateTime: DWORD,
}

impl FILETIME {
    pub const fn as_u64(&self) -> u64 {
        (self.dwLowDateTime as u64) | ((self.dwHighDateTime as u64) << 32)
    }

    pub const fn from_u64(value: u64) -> Self {
        Self {
            dwLowDateTime: value as u32,
            dwHighDateTime: (value >> 32) as u32,
        }
    }
}
