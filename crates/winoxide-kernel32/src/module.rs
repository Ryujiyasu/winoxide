//! Module management — GetModuleHandle, GetProcAddress, etc.

use crate::error::*;
use std::collections::HashMap;
use std::sync::Mutex;

/// Simple module registry (global state).
static MODULE_REGISTRY: Mutex<Option<ModuleMap>> = Mutex::new(None);

type ModuleMap = HashMap<String, ModuleInfo>;

struct ModuleInfo {
    base_address: usize,
    exports: HashMap<String, usize>,
}

/// GetModuleHandleA — Get handle to a loaded module.
/// NULL returns the main executable's handle.
pub fn GetModuleHandleA(module_name: Option<&str>) -> isize {
    match module_name {
        None => {
            // Return pseudo-handle for main exe
            0x00400000 // typical EXE base address
        }
        Some(_name) => {
            // TODO: look up loaded modules
            SetLastError(ERROR_FILE_NOT_FOUND);
            0
        }
    }
}

/// GetModuleFileNameA — Get the path of a loaded module.
pub fn GetModuleFileNameA(
    _module: isize,
    buffer: &mut [u8],
) -> u32 {
    // Return the current executable path
    match std::env::current_exe() {
        Ok(path) => {
            let path_str = path.to_string_lossy();
            let bytes = path_str.as_bytes();
            let copy_len = bytes.len().min(buffer.len().saturating_sub(1));
            buffer[..copy_len].copy_from_slice(&bytes[..copy_len]);
            buffer[copy_len] = 0;
            copy_len as u32
        }
        Err(_) => {
            SetLastError(ERROR_INVALID_FUNCTION);
            0
        }
    }
}

/// GetProcAddress — Get the address of an exported function.
pub fn GetProcAddress(_module: isize, _proc_name: &str) -> usize {
    // TODO: look up PE exports from loaded modules
    SetLastError(ERROR_FILE_NOT_FOUND); // ERROR_PROC_NOT_FOUND
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_module_handle() {
        let h = GetModuleHandleA(None);
        assert_ne!(h, 0);
    }

    #[test]
    fn test_get_module_filename() {
        let mut buf = [0u8; 256];
        let len = GetModuleFileNameA(0, &mut buf);
        assert!(len > 0);
    }
}
