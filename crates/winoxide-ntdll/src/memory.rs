//! NT virtual memory management — NtAllocateVirtualMemory, NtFreeVirtualMemory, etc.
//!
//! Maps NT virtual memory operations to Linux mmap/munmap/mprotect.

use winoxide_types::*;

/// Memory protection constants.
pub const PAGE_NOACCESS: ULONG = 0x01;
pub const PAGE_READONLY: ULONG = 0x02;
pub const PAGE_READWRITE: ULONG = 0x04;
pub const PAGE_WRITECOPY: ULONG = 0x08;
pub const PAGE_EXECUTE: ULONG = 0x10;
pub const PAGE_EXECUTE_READ: ULONG = 0x20;
pub const PAGE_EXECUTE_READWRITE: ULONG = 0x40;
pub const PAGE_GUARD: ULONG = 0x100;

/// Memory allocation type constants.
pub const MEM_COMMIT: ULONG = 0x00001000;
pub const MEM_RESERVE: ULONG = 0x00002000;
pub const MEM_RELEASE: ULONG = 0x00008000;
pub const MEM_FREE: ULONG = 0x00010000;

/// Convert NT page protection to Linux mmap protection flags.
fn nt_protect_to_unix(protect: ULONG) -> i32 {
    match protect & 0xFF {
        PAGE_NOACCESS => libc::PROT_NONE,
        PAGE_READONLY => libc::PROT_READ,
        PAGE_READWRITE | PAGE_WRITECOPY => libc::PROT_READ | libc::PROT_WRITE,
        PAGE_EXECUTE => libc::PROT_EXEC,
        PAGE_EXECUTE_READ => libc::PROT_READ | libc::PROT_EXEC,
        PAGE_EXECUTE_READWRITE => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

/// NtAllocateVirtualMemory — Allocate or commit virtual memory pages.
pub fn NtAllocateVirtualMemory(
    _process_handle: HANDLE,
    base_address: &mut PVOID,
    _zero_bits: ULONG_PTR,
    region_size: &mut SIZE_T,
    allocation_type: ULONG,
    protect: ULONG,
) -> NTSTATUS {
    let size = *region_size;
    if size == 0 {
        return STATUS_INVALID_PARAMETER;
    }

    // Page-align the size
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let aligned_size = (size + page_size - 1) & !(page_size - 1);

    let prot = nt_protect_to_unix(protect);
    let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    // If a specific address is requested, try to honor it
    let addr = if !(*base_address).is_null() {
        flags |= libc::MAP_FIXED_NOREPLACE;
        *base_address
    } else {
        core::ptr::null_mut()
    };

    let result = unsafe {
        libc::mmap(addr, aligned_size, prot, flags, -1, 0)
    };

    if result == libc::MAP_FAILED {
        let errno = unsafe { *libc::__errno_location() };
        return match errno {
            libc::ENOMEM => STATUS_NO_MEMORY,
            libc::EEXIST => STATUS_CONFLICTING_ADDRESSES,
            _ => STATUS_UNSUCCESSFUL,
        };
    }

    *base_address = result;
    *region_size = aligned_size;
    STATUS_SUCCESS
}

/// NtFreeVirtualMemory — Free or decommit virtual memory pages.
pub fn NtFreeVirtualMemory(
    _process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut SIZE_T,
    free_type: ULONG,
) -> NTSTATUS {
    if (*base_address).is_null() {
        return STATUS_INVALID_PARAMETER;
    }

    if (free_type & MEM_RELEASE) != 0 {
        if *region_size != 0 {
            // MEM_RELEASE requires region_size == 0
            return STATUS_INVALID_PARAMETER;
        }
        // In a real implementation, we'd look up the allocation size
        // For now, this is a simplified version
        return STATUS_NOT_IMPLEMENTED;
    }

    // MEM_DECOMMIT: use madvise to release physical pages
    let ret = unsafe {
        libc::madvise(*base_address, *region_size, libc::MADV_DONTNEED)
    };

    if ret < 0 {
        STATUS_UNSUCCESSFUL
    } else {
        STATUS_SUCCESS
    }
}

/// NtProtectVirtualMemory — Change page protection.
pub fn NtProtectVirtualMemory(
    _process_handle: HANDLE,
    base_address: &mut PVOID,
    region_size: &mut SIZE_T,
    new_protect: ULONG,
    old_protect: &mut ULONG,
) -> NTSTATUS {
    let prot = nt_protect_to_unix(new_protect);

    // TODO: Query old protection properly
    *old_protect = PAGE_READWRITE;

    let ret = unsafe {
        libc::mprotect(*base_address, *region_size, prot)
    };

    if ret < 0 {
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_and_free() {
        let mut addr: PVOID = core::ptr::null_mut();
        let mut size: SIZE_T = 4096;

        let status = NtAllocateVirtualMemory(
            core::ptr::null_mut(),
            &mut addr,
            0,
            &mut size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert!(!addr.is_null());
        assert!(size >= 4096);

        // Write to the allocated memory
        unsafe {
            let ptr = addr as *mut u8;
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        // Clean up
        unsafe { libc::munmap(addr, size) };
    }

    #[test]
    fn test_protect_to_unix() {
        assert_eq!(nt_protect_to_unix(PAGE_NOACCESS), libc::PROT_NONE);
        assert_eq!(nt_protect_to_unix(PAGE_READONLY), libc::PROT_READ);
        assert_eq!(nt_protect_to_unix(PAGE_READWRITE), libc::PROT_READ | libc::PROT_WRITE);
        assert_eq!(nt_protect_to_unix(PAGE_EXECUTE_READ), libc::PROT_READ | libc::PROT_EXEC);
    }
}
