//! NT process/thread management — NtCreateUserProcess, NtTerminateProcess, etc.

use winoxide_types::*;

/// NtTerminateProcess — Terminate a process.
pub fn NtTerminateProcess(handle: HANDLE, exit_status: NTSTATUS) -> NTSTATUS {
    if handle.is_null() {
        // Terminate current process
        unsafe { libc::exit(exit_status) };
    }
    // TODO: Send terminate_process to server
    STATUS_NOT_IMPLEMENTED
}

/// NtTerminateThread — Terminate a thread.
pub fn NtTerminateThread(_handle: HANDLE, _exit_status: NTSTATUS) -> NTSTATUS {
    // TODO: Implement via pthread and server
    STATUS_NOT_IMPLEMENTED
}

/// RtlExitUserProcess — Clean shutdown of the current process.
pub fn RtlExitUserProcess(exit_status: NTSTATUS) -> ! {
    // TODO: Proper cleanup (DLL_PROCESS_DETACH, flush handles, etc.)
    unsafe { libc::exit(exit_status) }
}
