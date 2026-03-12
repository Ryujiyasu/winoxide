//! NT synchronization syscalls — NtCreateEvent, NtWaitForSingleObject, etc.

use winoxide_types::*;

/// NtWaitForSingleObject — Wait for a kernel object to become signaled.
///
/// In the full implementation, this sends a `select` request to the server.
/// For now, this is a stub that returns immediately.
pub fn NtWaitForSingleObject(
    _handle: HANDLE,
    _alertable: BOOLEAN,
    _timeout: Option<&LARGE_INTEGER>,
) -> NTSTATUS {
    // TODO: Implement via server select request
    STATUS_NOT_IMPLEMENTED
}

/// NtWaitForMultipleObjects — Wait for one or all objects to become signaled.
pub fn NtWaitForMultipleObjects(
    _count: ULONG,
    _handles: &[HANDLE],
    _wait_type: u32, // WaitAll = 0, WaitAny = 1
    _alertable: BOOLEAN,
    _timeout: Option<&LARGE_INTEGER>,
) -> NTSTATUS {
    // TODO: Implement via server select request
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateEvent
pub fn NtCreateEvent(
    _event_handle: &mut HANDLE,
    _desired_access: ACCESS_MASK,
    _object_attributes: Option<&OBJECT_ATTRIBUTES>,
    _event_type: u32, // NotificationEvent = 0 (manual), SynchronizationEvent = 1 (auto)
    _initial_state: BOOLEAN,
) -> NTSTATUS {
    // TODO: Implement via server create_event request
    STATUS_NOT_IMPLEMENTED
}

/// NtSetEvent — Set an event to signaled state.
pub fn NtSetEvent(_event_handle: HANDLE, _previous_state: Option<&mut LONG>) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// NtResetEvent — Reset an event to non-signaled state.
pub fn NtResetEvent(_event_handle: HANDLE, _previous_state: Option<&mut LONG>) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateSemaphore
pub fn NtCreateSemaphore(
    _semaphore_handle: &mut HANDLE,
    _desired_access: ACCESS_MASK,
    _object_attributes: Option<&OBJECT_ATTRIBUTES>,
    _initial_count: LONG,
    _maximum_count: LONG,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// NtReleaseSemaphore
pub fn NtReleaseSemaphore(
    _semaphore_handle: HANDLE,
    _release_count: LONG,
    _previous_count: Option<&mut LONG>,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// NtCreateMutant
pub fn NtCreateMutant(
    _mutant_handle: &mut HANDLE,
    _desired_access: ACCESS_MASK,
    _object_attributes: Option<&OBJECT_ATTRIBUTES>,
    _initial_owner: BOOLEAN,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}

/// NtReleaseMutant
pub fn NtReleaseMutant(
    _mutant_handle: HANDLE,
    _previous_count: Option<&mut LONG>,
) -> NTSTATUS {
    STATUS_NOT_IMPLEMENTED
}
