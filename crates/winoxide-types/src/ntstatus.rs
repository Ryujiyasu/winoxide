//! NTSTATUS constants from ntstatus.h.

use crate::ntdef::NTSTATUS;

// === Success (0x0000xxxx) ===

pub const STATUS_SUCCESS: NTSTATUS = 0x00000000;
pub const STATUS_WAIT_0: NTSTATUS = 0x00000000;
pub const STATUS_WAIT_1: NTSTATUS = 0x00000001;
pub const STATUS_ABANDONED: NTSTATUS = 0x00000080;
pub const STATUS_USER_APC: NTSTATUS = 0x000000C0;
pub const STATUS_ALREADY_COMPLETE: NTSTATUS = 0x000000FF;
pub const STATUS_KERNEL_APC: NTSTATUS = 0x00000100;
pub const STATUS_ALERTED: NTSTATUS = 0x00000101;
pub const STATUS_TIMEOUT: NTSTATUS = 0x00000102;
pub const STATUS_PENDING: NTSTATUS = 0x00000103;
pub const STATUS_REPARSE: NTSTATUS = 0x00000104;
pub const STATUS_MORE_ENTRIES: NTSTATUS = 0x00000105;
pub const STATUS_SOME_NOT_MAPPED: NTSTATUS = 0x00000107;
pub const STATUS_NOTIFY_ENUM_DIR: NTSTATUS = 0x0000010C;

// === Informational (0x4000xxxx) ===

pub const STATUS_OBJECT_NAME_EXISTS: NTSTATUS = 0x40000000_u32 as i32;
pub const STATUS_THREAD_WAS_SUSPENDED: NTSTATUS = 0x40000001_u32 as i32;
pub const STATUS_IMAGE_NOT_AT_BASE: NTSTATUS = 0x40000003_u32 as i32;

// === Warning (0x8000xxxx) ===

pub const STATUS_GUARD_PAGE_VIOLATION: NTSTATUS = 0x80000001_u32 as i32;
pub const STATUS_DATATYPE_MISALIGNMENT: NTSTATUS = 0x80000002_u32 as i32;
pub const STATUS_BREAKPOINT: NTSTATUS = 0x80000003_u32 as i32;
pub const STATUS_SINGLE_STEP: NTSTATUS = 0x80000004_u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x80000005_u32 as i32;
pub const STATUS_NO_MORE_FILES: NTSTATUS = 0x80000006_u32 as i32;
pub const STATUS_NO_MORE_ENTRIES: NTSTATUS = 0x8000001A_u32 as i32;

// === Error (0xC000xxxx) ===

pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001_u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC0000002_u32 as i32;
pub const STATUS_INVALID_INFO_CLASS: NTSTATUS = 0xC0000003_u32 as i32;
pub const STATUS_INFO_LENGTH_MISMATCH: NTSTATUS = 0xC0000004_u32 as i32;
pub const STATUS_ACCESS_VIOLATION: NTSTATUS = 0xC0000005_u32 as i32;
pub const STATUS_IN_PAGE_ERROR: NTSTATUS = 0xC0000006_u32 as i32;
pub const STATUS_INVALID_HANDLE: NTSTATUS = 0xC0000008_u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000D_u32 as i32;
pub const STATUS_NO_SUCH_FILE: NTSTATUS = 0xC000000F_u32 as i32;
pub const STATUS_NO_MEMORY: NTSTATUS = 0xC0000017_u32 as i32;
pub const STATUS_CONFLICTING_ADDRESSES: NTSTATUS = 0xC0000018_u32 as i32;
pub const STATUS_ILLEGAL_INSTRUCTION: NTSTATUS = 0xC000001D_u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022_u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023_u32 as i32;
pub const STATUS_OBJECT_TYPE_MISMATCH: NTSTATUS = 0xC0000024_u32 as i32;
pub const STATUS_OBJECT_NAME_INVALID: NTSTATUS = 0xC0000033_u32 as i32;
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = 0xC0000034_u32 as i32;
pub const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = 0xC0000035_u32 as i32;
pub const STATUS_OBJECT_PATH_INVALID: NTSTATUS = 0xC0000039_u32 as i32;
pub const STATUS_OBJECT_PATH_NOT_FOUND: NTSTATUS = 0xC000003A_u32 as i32;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: NTSTATUS = 0xC000003B_u32 as i32;
pub const STATUS_SHARING_VIOLATION: NTSTATUS = 0xC0000043_u32 as i32;
pub const STATUS_QUOTA_EXCEEDED: NTSTATUS = 0xC0000044_u32 as i32;
pub const STATUS_SECTION_NOT_IMAGE: NTSTATUS = 0xC0000049_u32 as i32;
pub const STATUS_FILE_LOCK_CONFLICT: NTSTATUS = 0xC0000054_u32 as i32;
pub const STATUS_NOT_SAME_DEVICE: NTSTATUS = 0xC00000D4_u32 as i32;
pub const STATUS_INTEGER_DIVIDE_BY_ZERO: NTSTATUS = 0xC0000094_u32 as i32;
pub const STATUS_INTEGER_OVERFLOW: NTSTATUS = 0xC0000095_u32 as i32;
pub const STATUS_PRIVILEGED_INSTRUCTION: NTSTATUS = 0xC0000096_u32 as i32;
pub const STATUS_FILE_INVALID: NTSTATUS = 0xC0000098_u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000009A_u32 as i32;
pub const STATUS_FILE_IS_A_DIRECTORY: NTSTATUS = 0xC00000BA_u32 as i32;
pub const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC00000BB_u32 as i32;
pub const STATUS_STACK_OVERFLOW: NTSTATUS = 0xC00000FD_u32 as i32;
pub const STATUS_NOT_A_DIRECTORY: NTSTATUS = 0xC0000103_u32 as i32;
pub const STATUS_CANNOT_DELETE: NTSTATUS = 0xC0000121_u32 as i32;
pub const STATUS_FILE_NOT_AVAILABLE: NTSTATUS = 0xC0000467_u32 as i32;

// === Helper functions ===

/// Returns true if the NTSTATUS indicates success (severity 0).
#[inline]
pub const fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

/// Returns true if the NTSTATUS is informational (severity 1).
#[inline]
pub const fn nt_information(status: NTSTATUS) -> bool {
    (status as u32) >> 30 == 1
}

/// Returns true if the NTSTATUS is a warning (severity 2).
#[inline]
pub const fn nt_warning(status: NTSTATUS) -> bool {
    (status as u32) >> 30 == 2
}

/// Returns true if the NTSTATUS is an error (severity 3).
#[inline]
pub const fn nt_error(status: NTSTATUS) -> bool {
    (status as u32) >> 30 == 3
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_classification() {
        assert!(nt_success(STATUS_SUCCESS));
        assert!(nt_success(STATUS_PENDING));
        assert!(!nt_success(STATUS_ACCESS_DENIED));

        assert!(nt_information(STATUS_OBJECT_NAME_EXISTS));
        assert!(nt_warning(STATUS_BUFFER_OVERFLOW));
        assert!(nt_error(STATUS_ACCESS_VIOLATION));
        assert!(nt_error(STATUS_INVALID_HANDLE));
    }

    #[test]
    fn test_status_values() {
        assert_eq!(STATUS_SUCCESS, 0);
        assert_eq!(STATUS_ACCESS_VIOLATION as u32, 0xC0000005);
        assert_eq!(STATUS_INVALID_HANDLE as u32, 0xC0000008);
    }
}
