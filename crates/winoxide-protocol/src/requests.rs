//! Server request/reply definitions.
//!
//! Each request corresponds to a kernel operation. The server processes these
//! and returns a reply. Variable-length data (VARARG) is sent/received
//! separately from the fixed-size structs.

use crate::types::*;

/// Request opcodes — each maps to a request/reply struct pair.
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestCode {
    NewProcess = 0,
    GetNewProcessInfo = 1,
    NewThread = 2,
    GetStartupInfo = 3,
    InitProcessDone = 4,
    InitFirstThread = 5,
    InitThread = 6,
    TerminateProcess = 7,
    TerminateThread = 8,
    GetProcessInfo = 9,
    GetProcessDebugInfo = 10,
    GetProcessImageName = 11,
    GetProcessVmCounters = 12,
    SetProcessInfo = 13,
    GetThreadInfo = 14,
    GetThreadTimes = 15,
    SetThreadInfo = 16,
    SuspendThread = 17,
    ResumeThread = 18,
    QueueApc = 19,
    GetApcResult = 20,
    CloseHandle = 21,
    SetHandleInfo = 22,
    DupHandle = 23,
    AllocateReserveObject = 24,
    CompareObjects = 25,
    SetObjectPermanence = 26,
    OpenProcess = 27,
    OpenThread = 28,
    Select = 29,
    CreateEvent = 30,
    EventOp = 31,
    QueryEvent = 32,
    OpenEvent = 33,
    CreateMutex = 34,
    ReleaseMutex = 35,
    OpenMutex = 36,
    QueryMutex = 37,
    CreateSemaphore = 38,
    ReleaseSemaphore = 39,
    OpenSemaphore = 40,
    QuerySemaphore = 41,
    CreateFile = 42,
    OpenFileObject = 43,
    AllocFileHandle = 44,
    GetHandleFd = 45,
    GetHandleUnixName = 46,
    GetFileInfo = 47,
    GetVolumeInfo = 48,
    LockFile = 49,
    UnlockFile = 50,
    // ... more to follow as needed
}

// ============================================================
// Process management
// ============================================================

/// Request: Create a new process.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NewProcessRequest {
    pub token: ObjHandle,
    pub debug: ObjHandle,
    pub parent_process: ObjHandle,
    pub flags: u32,
    pub socket_fd: i32,
    pub access: u32,
    pub machine: u16,
    _pad: u16,
    pub info_size: DataSize,
    pub handles_size: DataSize,
    pub jobs_size: DataSize,
    // VARARG: objattr, handles, jobs, info, env
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NewProcessReply {
    pub info: ObjHandle,
    pub pid: ProcessId,
    pub handle: ObjHandle,
}

/// Request: Get info about a newly created process.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GetNewProcessInfoRequest {
    pub info: ObjHandle,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct GetNewProcessInfoReply {
    pub success: i32,
    pub exit_code: i32,
}

/// Request: Create a new thread.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NewThreadRequest {
    pub process: ObjHandle,
    pub access: u32,
    pub flags: u32,
    pub request_fd: i32,
    // VARARG: objattr
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NewThreadReply {
    pub tid: ThreadId,
    pub handle: ObjHandle,
}

/// Request: Terminate a process.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminateProcessRequest {
    pub handle: ObjHandle,
    pub exit_code: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminateProcessReply {
    pub self_: i32,
}

/// Request: Terminate a thread.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminateThreadRequest {
    pub handle: ObjHandle,
    pub exit_code: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TerminateThreadReply {
    pub self_: i32,
}

// ============================================================
// Handle management
// ============================================================

/// Request: Close a handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CloseHandleRequest {
    pub handle: ObjHandle,
}

/// Request: Duplicate a handle.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DupHandleRequest {
    pub src_process: ObjHandle,
    pub src_handle: ObjHandle,
    pub dst_process: ObjHandle,
    pub access: u32,
    pub attributes: u32,
    pub options: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct DupHandleReply {
    pub handle: ObjHandle,
}

/// Request: Open an existing process by PID.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenProcessRequest {
    pub pid: ProcessId,
    pub access: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenProcessReply {
    pub handle: ObjHandle,
}

/// Request: Open an existing thread by TID.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenThreadRequest {
    pub tid: ThreadId,
    pub access: u32,
    pub attributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenThreadReply {
    pub handle: ObjHandle,
}

// ============================================================
// Synchronization objects
// ============================================================

/// Request: Create an event object.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateEventRequest {
    pub access: u32,
    pub manual_reset: i32,
    pub initial_state: i32,
    // VARARG: objattr
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateEventReply {
    pub handle: ObjHandle,
}

/// Request: Create a mutex.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateMutexRequest {
    pub access: u32,
    pub owned: i32,
    // VARARG: objattr
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateMutexReply {
    pub handle: ObjHandle,
}

/// Request: Release a mutex.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReleaseMutexRequest {
    pub handle: ObjHandle,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReleaseMutexReply {
    pub prev_count: u32,
}

/// Request: Create a semaphore.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateSemaphoreRequest {
    pub access: u32,
    pub initial: i32,
    pub max: i32,
    // VARARG: objattr
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateSemaphoreReply {
    pub handle: ObjHandle,
}

/// Request: Release a semaphore.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReleaseSemaphoreRequest {
    pub handle: ObjHandle,
    pub count: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReleaseSemaphoreReply {
    pub prev_count: u32,
}

// ============================================================
// Wait / Select
// ============================================================

/// Request: Wait on objects (the core synchronization primitive).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SelectRequest {
    pub flags: i32,
    pub cookie: ClientPtr,
    pub timeout: AbsTime,
    pub size: DataSize,
    pub prev_apc: ObjHandle,
    // VARARG: result (apc_result), data (select_op), contexts
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SelectReply {
    pub apc_handle: ObjHandle,
    pub signaled: i32,
    // VARARG: call (apc_call), contexts
}

// ============================================================
// Trait for request dispatch
// ============================================================

/// Trait implemented by all request types.
pub trait ServerRequest: Sized {
    /// The corresponding reply type.
    type Reply: Default;

    /// The request opcode.
    fn code() -> RequestCode;
}

// Implement for core requests
macro_rules! impl_request {
    ($req:ty, $reply:ty, $code:expr) => {
        impl ServerRequest for $req {
            type Reply = $reply;
            fn code() -> RequestCode {
                $code
            }
        }
    };
}

impl_request!(NewProcessRequest, NewProcessReply, RequestCode::NewProcess);
impl_request!(GetNewProcessInfoRequest, GetNewProcessInfoReply, RequestCode::GetNewProcessInfo);
impl_request!(NewThreadRequest, NewThreadReply, RequestCode::NewThread);
impl_request!(TerminateProcessRequest, TerminateProcessReply, RequestCode::TerminateProcess);
impl_request!(TerminateThreadRequest, TerminateThreadReply, RequestCode::TerminateThread);
impl_request!(CloseHandleRequest, (), RequestCode::CloseHandle);
impl_request!(DupHandleRequest, DupHandleReply, RequestCode::DupHandle);
impl_request!(OpenProcessRequest, OpenProcessReply, RequestCode::OpenProcess);
impl_request!(OpenThreadRequest, OpenThreadReply, RequestCode::OpenThread);
impl_request!(CreateEventRequest, CreateEventReply, RequestCode::CreateEvent);
impl_request!(CreateMutexRequest, CreateMutexReply, RequestCode::CreateMutex);
impl_request!(ReleaseMutexRequest, ReleaseMutexReply, RequestCode::ReleaseMutex);
impl_request!(CreateSemaphoreRequest, CreateSemaphoreReply, RequestCode::CreateSemaphore);
impl_request!(ReleaseSemaphoreRequest, ReleaseSemaphoreReply, RequestCode::ReleaseSemaphore);
impl_request!(SelectRequest, SelectReply, RequestCode::Select);
