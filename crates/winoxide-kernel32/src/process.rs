//! Win32 process/thread management.

use crate::error::*;

/// GetCurrentProcessId
pub fn GetCurrentProcessId() -> u32 {
    unsafe { libc::getpid() as u32 }
}

/// GetCurrentThreadId
pub fn GetCurrentThreadId() -> u32 {
    unsafe { libc::gettid() as u32 }
}

/// GetCurrentProcess — returns a pseudo-handle.
pub fn GetCurrentProcess() -> isize {
    -1 // Windows convention for current process pseudo-handle
}

/// ExitProcess — terminate the current process.
pub fn ExitProcess(exit_code: u32) -> ! {
    unsafe { libc::exit(exit_code as i32) }
}

/// Sleep — suspend execution for the specified milliseconds.
pub fn Sleep(milliseconds: u32) {
    let ts = libc::timespec {
        tv_sec: (milliseconds / 1000) as i64,
        tv_nsec: ((milliseconds % 1000) as i64) * 1_000_000,
    };
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
}

/// GetTickCount — milliseconds since system start (approximated).
pub fn GetTickCount() -> u32 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ((ts.tv_sec * 1000) + (ts.tv_nsec / 1_000_000)) as u32
}

/// QueryPerformanceCounter
pub fn QueryPerformanceCounter(counter: &mut i64) -> bool {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } == 0 {
        *counter = ts.tv_sec * 1_000_000_000 + ts.tv_nsec;
        true
    } else {
        false
    }
}

/// QueryPerformanceFrequency — returns nanosecond frequency.
pub fn QueryPerformanceFrequency(frequency: &mut i64) -> bool {
    *frequency = 1_000_000_000; // nanoseconds
    true
}

/// GetEnvironmentVariableA
pub fn GetEnvironmentVariableA(name: &str, buffer: &mut [u8]) -> u32 {
    match std::env::var(name) {
        Ok(val) => {
            let bytes = val.as_bytes();
            if bytes.len() + 1 > buffer.len() {
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return (bytes.len() + 1) as u32;
            }
            buffer[..bytes.len()].copy_from_slice(bytes);
            buffer[bytes.len()] = 0;
            bytes.len() as u32
        }
        Err(_) => {
            SetLastError(ERROR_FILE_NOT_FOUND); // ERROR_ENVVAR_NOT_FOUND = same
            0
        }
    }
}

/// SetEnvironmentVariableA
pub fn SetEnvironmentVariableA(name: &str, value: Option<&str>) -> bool {
    match value {
        Some(v) => {
            unsafe { std::env::set_var(name, v) };
            true
        }
        None => {
            unsafe { std::env::remove_var(name) };
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_current_process_id() {
        let pid = GetCurrentProcessId();
        assert!(pid > 0);
    }

    #[test]
    fn test_get_tick_count() {
        let t1 = GetTickCount();
        let t2 = GetTickCount();
        assert!(t2 >= t1);
    }

    #[test]
    fn test_perf_counter() {
        let mut counter = 0i64;
        let mut freq = 0i64;
        assert!(QueryPerformanceCounter(&mut counter));
        assert!(QueryPerformanceFrequency(&mut freq));
        assert!(counter > 0);
        assert_eq!(freq, 1_000_000_000);
    }

    #[test]
    fn test_environment_variable() {
        SetEnvironmentVariableA("WINOXIDE_TEST", Some("hello"));
        let mut buf = [0u8; 64];
        let len = GetEnvironmentVariableA("WINOXIDE_TEST", &mut buf);
        assert_eq!(len, 5);
        assert_eq!(&buf[..5], b"hello");

        SetEnvironmentVariableA("WINOXIDE_TEST", None);
        let len = GetEnvironmentVariableA("WINOXIDE_TEST", &mut buf);
        assert_eq!(len, 0);
    }
}
