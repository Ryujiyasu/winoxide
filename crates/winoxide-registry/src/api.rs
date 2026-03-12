//! Win32 Registry API — RegOpenKeyEx, RegQueryValueEx, RegSetValueEx, etc.
//!
//! These are the kernelbase-level registry functions that applications call.

use crate::hive::*;
use winoxide_types::*;

/// Predefined registry key handles.
pub const HKEY_CLASSES_ROOT: u32 = 0x80000000;
pub const HKEY_CURRENT_USER: u32 = 0x80000001;
pub const HKEY_LOCAL_MACHINE: u32 = 0x80000002;
pub const HKEY_USERS: u32 = 0x80000003;
pub const HKEY_CURRENT_CONFIG: u32 = 0x80000005;

/// Registry access rights.
pub const KEY_QUERY_VALUE: u32 = 0x0001;
pub const KEY_SET_VALUE: u32 = 0x0002;
pub const KEY_CREATE_SUB_KEY: u32 = 0x0004;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
pub const KEY_READ: u32 = KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | 0x00020000;
pub const KEY_WRITE: u32 = KEY_SET_VALUE | KEY_CREATE_SUB_KEY | 0x00020000;
pub const KEY_ALL_ACCESS: u32 = KEY_READ | KEY_WRITE | 0x000F0000;

/// Win32 error codes used by registry functions.
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_ACCESS_DENIED: u32 = 5;
pub const ERROR_INVALID_HANDLE: u32 = 6;
pub const ERROR_MORE_DATA: u32 = 234;
pub const ERROR_NO_MORE_ITEMS: u32 = 259;

/// Registry disposition (returned by RegCreateKeyEx).
pub const REG_CREATED_NEW_KEY: u32 = 1;
pub const REG_OPENED_EXISTING_KEY: u32 = 2;
