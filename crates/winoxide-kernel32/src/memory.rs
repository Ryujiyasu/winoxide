//! Win32 memory management — VirtualAlloc, VirtualFree, HeapAlloc, etc.

use crate::error::*;

/// Memory allocation types.
pub const MEM_COMMIT: u32 = 0x00001000;
pub const MEM_RESERVE: u32 = 0x00002000;
pub const MEM_RELEASE: u32 = 0x00008000;
pub const MEM_DECOMMIT: u32 = 0x00004000;

/// Page protection.
pub const PAGE_NOACCESS: u32 = 0x01;
pub const PAGE_READONLY: u32 = 0x02;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE: u32 = 0x10;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// VirtualAlloc — Reserve/commit virtual memory pages.
pub fn VirtualAlloc(
    address: *mut u8,
    size: usize,
    allocation_type: u32,
    protect: u32,
) -> *mut u8 {
    let prot = win32_protect_to_unix(protect);
    let mut flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;

    let addr = if !address.is_null() {
        flags |= libc::MAP_FIXED_NOREPLACE;
        address as *mut libc::c_void
    } else {
        std::ptr::null_mut()
    };

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let aligned_size = (size + page_size - 1) & !(page_size - 1);

    let result = unsafe { libc::mmap(addr, aligned_size, prot, flags, -1, 0) };
    if result == libc::MAP_FAILED {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        std::ptr::null_mut()
    } else {
        result as *mut u8
    }
}

/// VirtualFree — Release/decommit virtual memory pages.
pub fn VirtualFree(address: *mut u8, size: usize, free_type: u32) -> bool {
    if address.is_null() {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    if (free_type & MEM_RELEASE) != 0 {
        let ret = unsafe { libc::munmap(address as *mut libc::c_void, size.max(4096)) };
        ret == 0
    } else if (free_type & MEM_DECOMMIT) != 0 {
        let ret = unsafe { libc::madvise(address as *mut libc::c_void, size, libc::MADV_DONTNEED) };
        ret == 0
    } else {
        SetLastError(ERROR_INVALID_PARAMETER);
        false
    }
}

/// GetProcessHeap — return a pseudo-handle for the default heap.
/// (We use libc malloc/free behind the scenes.)
pub fn GetProcessHeap() -> isize {
    1 // pseudo-handle
}

/// HeapAlloc — Allocate memory from a heap.
pub fn HeapAlloc(_heap: isize, flags: u32, size: usize) -> *mut u8 {
    let ptr = unsafe { libc::malloc(size) } as *mut u8;
    if ptr.is_null() {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return std::ptr::null_mut();
    }
    // HEAP_ZERO_MEMORY = 0x08
    if (flags & 0x08) != 0 {
        unsafe { std::ptr::write_bytes(ptr, 0, size) };
    }
    ptr
}

/// HeapFree — Free memory allocated by HeapAlloc.
pub fn HeapFree(_heap: isize, _flags: u32, ptr: *mut u8) -> bool {
    if ptr.is_null() {
        return true;
    }
    unsafe { libc::free(ptr as *mut libc::c_void) };
    true
}

/// HeapReAlloc — Reallocate memory from a heap.
pub fn HeapReAlloc(_heap: isize, flags: u32, ptr: *mut u8, size: usize) -> *mut u8 {
    let new_ptr = unsafe { libc::realloc(ptr as *mut libc::c_void, size) } as *mut u8;
    if new_ptr.is_null() {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    }
    new_ptr
}

fn win32_protect_to_unix(protect: u32) -> i32 {
    match protect {
        PAGE_NOACCESS => libc::PROT_NONE,
        PAGE_READONLY => libc::PROT_READ,
        PAGE_READWRITE => libc::PROT_READ | libc::PROT_WRITE,
        PAGE_EXECUTE => libc::PROT_EXEC,
        PAGE_EXECUTE_READ => libc::PROT_READ | libc::PROT_EXEC,
        PAGE_EXECUTE_READWRITE => libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtual_alloc_free() {
        let ptr = VirtualAlloc(std::ptr::null_mut(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        assert!(!ptr.is_null());

        // Write and read
        unsafe {
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        assert!(VirtualFree(ptr, 4096, MEM_RELEASE));
    }

    #[test]
    fn test_heap_alloc_free() {
        let heap = GetProcessHeap();
        let ptr = HeapAlloc(heap, 0x08, 256); // HEAP_ZERO_MEMORY
        assert!(!ptr.is_null());

        // Should be zeroed
        unsafe {
            assert_eq!(*ptr, 0);
            assert_eq!(*ptr.add(255), 0);
        }

        assert!(HeapFree(heap, 0, ptr));
    }
}
