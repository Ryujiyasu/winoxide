//! Process Environment Block (PEB) definition.

use crate::primitives::*;

/// Process Environment Block.
///
/// This is the per-process data structure accessible via NtCurrentPeb() / TEB.Peb.
/// Fields match the Windows 10+ 64-bit layout.
#[repr(C)]
pub struct PEB {
    pub InheritedAddressSpace: BOOLEAN,
    pub ReadImageFileExecOptions: BOOLEAN,
    pub BeingDebugged: BOOLEAN,
    pub BitField: UCHAR,
    _padding0: [u8; 4], // alignment to 8
    pub Mutant: HANDLE,
    pub ImageBaseAddress: HMODULE,
    pub LdrData: PVOID, // *mut PEB_LDR_DATA
    pub ProcessParameters: PVOID, // *mut RTL_USER_PROCESS_PARAMETERS
    pub SubSystemData: PVOID,
    pub ProcessHeap: HANDLE,
    pub FastPebLock: PVOID, // *mut RTL_CRITICAL_SECTION
    pub AtlThunkSListPtr: PVOID,
    pub IFEOKey: PVOID,
    pub CrossProcessFlags: ULONG,
    _padding1: [u8; 4],
    pub KernelCallbackTable: PVOID,
    pub Reserved: ULONG,
    pub AtlThunkSListPtr32: ULONG,
    pub ApiSetMap: PVOID,
    pub TlsExpansionCounter: ULONG,
    _padding2: [u8; 4],
    pub TlsBitmap: PVOID,
    pub TlsBitmapBits: [ULONG; 2],
    pub ReadOnlySharedMemoryBase: PVOID,
    pub SharedData: PVOID,
    pub ReadOnlyStaticServerData: PVOID,
    pub AnsiCodePageData: PVOID,
    pub OemCodePageData: PVOID,
    pub UnicodeCaseTableData: PVOID,
    pub NumberOfProcessors: ULONG,
    pub NtGlobalFlag: ULONG,
    pub CriticalSectionTimeout: LARGE_INTEGER,
    pub HeapSegmentReserve: SIZE_T,
    pub HeapSegmentCommit: SIZE_T,
    pub HeapDeCommitTotalFreeThreshold: SIZE_T,
    pub HeapDeCommitFreeBlockThreshold: SIZE_T,
    pub NumberOfHeaps: ULONG,
    pub MaximumNumberOfHeaps: ULONG,
    pub ProcessHeaps: PVOID,
    pub GdiSharedHandleTable: PVOID,

    // OS version info
    pub OSMajorVersion: ULONG,
    pub OSMinorVersion: ULONG,
    pub OSBuildNumber: USHORT,
    pub OSCSDVersion: USHORT,
    pub OSPlatformId: ULONG,
    pub ImageSubSystem: ULONG,
    pub ImageSubSystemMajorVersion: ULONG,
    pub ImageSubSystemMinorVersion: ULONG,
    _padding3: [u8; 4],
    pub ActiveProcessAffinityMask: KAFFINITY,

    pub SessionId: ULONG,
}

impl PEB {
    /// Initialize a PEB with default Windows 10 values.
    pub fn new_default() -> Self {
        // Safety: PEB is repr(C) and all-zeros is a valid initial state
        let mut peb: Self = unsafe { core::mem::zeroed() };
        peb.OSMajorVersion = 10;
        peb.OSMinorVersion = 0;
        peb.OSBuildNumber = 19045; // Windows 10 22H2
        peb.OSPlatformId = 2; // VER_PLATFORM_WIN32_NT
        peb.NumberOfProcessors = 1;
        peb
    }
}
