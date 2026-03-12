//! Thread Environment Block (TEB) definition.

use crate::ntdef::*;
use crate::peb::PEB;
use crate::primitives::*;

/// Thread Environment Block (64-bit layout).
///
/// The TEB is the per-thread data structure pointed to by the GS segment register
/// (on x86-64) or the FS segment register (on x86).
#[repr(C)]
pub struct TEB {
    pub Tib: NT_TIB,
    pub EnvironmentPointer: PVOID,
    pub ClientId: CLIENT_ID,
    pub ActiveRpcHandle: PVOID,
    pub ThreadLocalStoragePointer: PVOID,
    pub Peb: *mut PEB,
    pub LastErrorValue: ULONG,
    pub CountOfOwnedCriticalSections: ULONG,
    pub CsrClientThread: PVOID,
    pub Win32ThreadInfo: PVOID,
    pub User32Reserved: [ULONG; 26],
    pub UserReserved: [ULONG; 5],
    _padding0: [u8; 4],
    pub WOW32Reserved: PVOID,
    pub CurrentLocale: ULONG,
    pub FpSoftwareStatusRegister: ULONG,
    pub ReservedForDebuggerInstrumentation: [PVOID; 16],

    // ... many fields omitted for now, filled with padding
    // Full TEB is ~0x1838 bytes on Win64
    _reserved: [u8; 0x1000], // placeholder for remaining fields

    pub TlsSlots: [PVOID; 64],
    pub TlsExpansionSlots: PVOID,
}

impl TEB {
    /// Get the current thread's last Win32 error code.
    pub fn last_error(&self) -> ULONG {
        self.LastErrorValue
    }

    /// Set the current thread's last Win32 error code.
    pub fn set_last_error(&mut self, error: ULONG) {
        self.LastErrorValue = error;
    }
}
