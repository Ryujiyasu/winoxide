//! Core NT kernel type definitions.
//!
//! UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK, CLIENT_ID, etc.

use crate::primitives::*;

/// NT status code (NTSTATUS).
pub type NTSTATUS = i32;

/// Counted Unicode string (UNICODE_STRING).
///
/// `Length` is the byte length of the string (not including terminator).
/// `MaximumLength` is the total buffer capacity in bytes.
/// `Buffer` points to wide characters (UTF-16LE).
#[repr(C)]
#[derive(Debug)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWSTR,
}

impl Default for UNICODE_STRING {
    fn default() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        }
    }
}

impl UNICODE_STRING {
    /// Create from a slice of u16 (does not copy; borrows the slice).
    ///
    /// # Safety
    /// The caller must ensure the slice outlives this UNICODE_STRING.
    pub unsafe fn from_slice(s: &[u16]) -> Self {
        Self {
            Length: (s.len() * 2) as u16,
            MaximumLength: (s.len() * 2) as u16,
            Buffer: s.as_ptr() as *mut u16,
        }
    }

    /// Returns the string as a u16 slice (without null terminator).
    ///
    /// # Safety
    /// The caller must ensure Buffer is valid for Length bytes.
    pub unsafe fn as_slice(&self) -> &[u16] {
        if self.Buffer.is_null() || self.Length == 0 {
            &[]
        } else {
            core::slice::from_raw_parts(self.Buffer, (self.Length / 2) as usize)
        }
    }
}

/// Counted ANSI string (STRING / ANSI_STRING / OEM_STRING).
#[repr(C)]
#[derive(Debug)]
pub struct STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PSTR,
}

impl Default for STRING {
    fn default() -> Self {
        Self {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        }
    }
}

/// Client ID (process + thread identification).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

impl Default for CLIENT_ID {
    fn default() -> Self {
        Self {
            UniqueProcess: core::ptr::null_mut(),
            UniqueThread: core::ptr::null_mut(),
        }
    }
}

// Safety: CLIENT_ID contains raw pointers used as opaque IDs
unsafe impl Send for CLIENT_ID {}
unsafe impl Sync for CLIENT_ID {}

/// I/O status block returned by NT file operations.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IO_STATUS_BLOCK {
    /// NTSTATUS (or pointer in union — we use the status variant).
    pub Status: NTSTATUS,
    /// Number of bytes transferred or other operation-specific information.
    pub Information: ULONG_PTR,
}

impl Default for IO_STATUS_BLOCK {
    fn default() -> Self {
        Self {
            Status: 0,
            Information: 0,
        }
    }
}

/// Object attributes for NtCreate*/NtOpen* calls.
#[repr(C)]
#[derive(Debug)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self {
            Length: core::mem::size_of::<Self>() as u32,
            RootDirectory: core::ptr::null_mut(),
            ObjectName: core::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: core::ptr::null_mut(),
            SecurityQualityOfService: core::ptr::null_mut(),
        }
    }
}

/// Object attribute flags.
pub const OBJ_INHERIT: ULONG = 0x00000002;
pub const OBJ_PERMANENT: ULONG = 0x00000010;
pub const OBJ_EXCLUSIVE: ULONG = 0x00000020;
pub const OBJ_CASE_INSENSITIVE: ULONG = 0x00000040;
pub const OBJ_OPENIF: ULONG = 0x00000080;
pub const OBJ_OPENLINK: ULONG = 0x00000100;
pub const OBJ_KERNEL_HANDLE: ULONG = 0x00000200;

/// NT_TIB — Thread Information Block (at the start of TEB).
#[repr(C)]
#[derive(Debug)]
pub struct NT_TIB {
    pub ExceptionList: PVOID,
    pub StackBase: PVOID,
    pub StackLimit: PVOID,
    pub SubSystemTib: PVOID,
    pub FiberData: PVOID, // union with Version: ULONG
    pub ArbitraryUserPointer: PVOID,
    pub Self_: *mut NT_TIB,
}

impl Default for NT_TIB {
    fn default() -> Self {
        Self {
            ExceptionList: core::ptr::null_mut(),
            StackBase: core::ptr::null_mut(),
            StackLimit: core::ptr::null_mut(),
            SubSystemTib: core::ptr::null_mut(),
            FiberData: core::ptr::null_mut(),
            ArbitraryUserPointer: core::ptr::null_mut(),
            Self_: core::ptr::null_mut(),
        }
    }
}

/// Security descriptor (opaque for now).
#[repr(C)]
#[derive(Debug)]
pub struct SECURITY_DESCRIPTOR {
    pub Revision: BYTE,
    pub Sbz1: BYTE,
    pub Control: USHORT,
    pub Owner: PVOID,
    pub Group: PVOID,
    pub Sacl: PVOID,
    pub Dacl: PVOID,
}

/// Generic access rights.
pub const GENERIC_READ: ACCESS_MASK = 0x80000000;
pub const GENERIC_WRITE: ACCESS_MASK = 0x40000000;
pub const GENERIC_EXECUTE: ACCESS_MASK = 0x20000000;
pub const GENERIC_ALL: ACCESS_MASK = 0x10000000;

pub const DELETE: ACCESS_MASK = 0x00010000;
pub const READ_CONTROL: ACCESS_MASK = 0x00020000;
pub const WRITE_DAC: ACCESS_MASK = 0x00040000;
pub const WRITE_OWNER: ACCESS_MASK = 0x00080000;
pub const SYNCHRONIZE: ACCESS_MASK = 0x00100000;

pub const STANDARD_RIGHTS_REQUIRED: ACCESS_MASK = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
pub const STANDARD_RIGHTS_ALL: ACCESS_MASK = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE;

/// File creation disposition values.
pub const FILE_SUPERSEDE: ULONG = 0x00000000;
pub const FILE_OPEN: ULONG = 0x00000001;
pub const FILE_CREATE: ULONG = 0x00000002;
pub const FILE_OPEN_IF: ULONG = 0x00000003;
pub const FILE_OVERWRITE: ULONG = 0x00000004;
pub const FILE_OVERWRITE_IF: ULONG = 0x00000005;

/// File create options.
pub const FILE_DIRECTORY_FILE: ULONG = 0x00000001;
pub const FILE_WRITE_THROUGH: ULONG = 0x00000002;
pub const FILE_SEQUENTIAL_ONLY: ULONG = 0x00000004;
pub const FILE_NO_INTERMEDIATE_BUFFERING: ULONG = 0x00000008;
pub const FILE_SYNCHRONOUS_IO_ALERT: ULONG = 0x00000010;
pub const FILE_SYNCHRONOUS_IO_NONALERT: ULONG = 0x00000020;
pub const FILE_NON_DIRECTORY_FILE: ULONG = 0x00000040;
pub const FILE_DELETE_ON_CLOSE: ULONG = 0x00001000;
pub const FILE_OPEN_BY_FILE_ID: ULONG = 0x00002000;

/// File share access.
pub const FILE_SHARE_READ: ULONG = 0x00000001;
pub const FILE_SHARE_WRITE: ULONG = 0x00000002;
pub const FILE_SHARE_DELETE: ULONG = 0x00000004;
