//! Protocol-level type definitions.
//!
//! These are the wire types used in server communication,
//! distinct from the full NT types (which may be pointer-sized).

/// Object handle (32-bit on the wire, even on 64-bit).
pub type ObjHandle = u32;
/// User handle (for window handles etc.)
pub type UserHandle = u32;
/// Process ID on the wire.
pub type ProcessId = u32;
/// Thread ID on the wire.
pub type ThreadId = u32;
/// Data size for variable-length payloads.
pub type DataSize = u32;
/// Atom value.
pub type AtomT = u32;

/// 64-bit client-side pointer (always u64 on the wire).
pub type ClientPtr = u64;
/// Memory size (always u64 on the wire).
pub type MemSize = u64;
/// File position (always u64 on the wire).
pub type FilePos = u64;
/// Thread/process affinity mask.
pub type AffinityT = u64;
/// Timeout in 100-nanosecond intervals (negative = relative).
pub type Timeout = i64;
/// Absolute time in 100-nanosecond intervals since 1601-01-01.
pub type AbsTime = i64;

/// Null handle constant.
pub const NULL_OBJ_HANDLE: ObjHandle = 0;

/// Request header — sent at the start of every request.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RequestHeader {
    /// Request opcode (from RequestCode enum).
    pub req: i32,
    /// Size of variable request data following the fixed struct.
    pub request_size: DataSize,
    /// Maximum size of variable reply data the client can accept.
    pub reply_size: DataSize,
}

/// Reply header — returned at the start of every reply.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplyHeader {
    /// NTSTATUS error code (0 = success).
    pub error: u32,
    /// Actual size of variable reply data returned.
    pub reply_size: DataSize,
}
