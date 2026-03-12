//! API dispatch table — maps Windows DLL exports to Rust implementations.
//!
//! When a PE executable imports `kernel32.dll!CreateFileA`, the execution
//! engine looks up this table and routes the call to our Rust implementation.

use std::collections::HashMap;

/// Represents a resolved API function pointer (as a tagged enum for safety).
#[derive(Debug, Clone)]
pub enum ApiFunction {
    /// Function that takes no args and returns i32.
    Void(fn() -> i32),
    /// Function taking a single usize arg and returning i32.
    OneArg(fn(usize) -> i32),
    /// Stub — recognized but not yet implemented.
    Stub(&'static str),
}

/// Registry of all available Windows API implementations.
#[derive(Debug)]
pub struct ApiTable {
    /// dll_name (lowercase) → (function_name → ApiFunction)
    dlls: HashMap<String, HashMap<String, ApiFunction>>,
    /// Track which APIs were called (for diagnostics).
    call_log: Vec<ApiCall>,
    /// Whether to log calls.
    logging_enabled: bool,
}

/// Record of an API call (for debugging / malware analysis).
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub dll: String,
    pub function: String,
    pub resolved: bool,
}

impl ApiTable {
    /// Create a new API table with all built-in DLL implementations registered.
    pub fn new() -> Self {
        let mut table = Self {
            dlls: HashMap::new(),
            call_log: Vec::new(),
            logging_enabled: false,
        };
        table.register_kernel32();
        table.register_msvcrt();
        table.register_ntdll();
        table
    }

    /// Enable or disable API call logging.
    pub fn set_logging(&mut self, enabled: bool) {
        self.logging_enabled = enabled;
    }

    /// Get the call log (useful for malware analysis).
    pub fn call_log(&self) -> &[ApiCall] {
        &self.call_log
    }

    /// Clear the call log.
    pub fn clear_log(&mut self) {
        self.call_log.clear();
    }

    /// Look up a function by DLL name and function name.
    pub fn resolve(&mut self, dll: &str, function: &str) -> Option<&ApiFunction> {
        let dll_lower = dll.to_ascii_lowercase();
        // Strip .dll extension if present
        let dll_key = dll_lower.strip_suffix(".dll").unwrap_or(&dll_lower);

        let resolved = self.dlls.get(dll_key)
            .and_then(|funcs| funcs.get(function))
            .is_some();

        if self.logging_enabled {
            self.call_log.push(ApiCall {
                dll: dll_key.to_string(),
                function: function.to_string(),
                resolved,
            });
        }

        self.dlls.get(dll_key)
            .and_then(|funcs| funcs.get(function))
    }

    /// Check if a DLL is available (implemented).
    pub fn has_dll(&self, dll: &str) -> bool {
        let dll_lower = dll.to_ascii_lowercase();
        let dll_key = dll_lower.strip_suffix(".dll").unwrap_or(&dll_lower);
        self.dlls.contains_key(dll_key)
    }

    /// List all implemented DLLs.
    pub fn available_dlls(&self) -> Vec<&str> {
        self.dlls.keys().map(|s| s.as_str()).collect()
    }

    /// Count total implemented functions across all DLLs.
    pub fn total_functions(&self) -> usize {
        self.dlls.values().map(|f| f.len()).sum()
    }

    /// List all functions in a DLL.
    pub fn functions_in_dll(&self, dll: &str) -> Vec<&str> {
        let dll_lower = dll.to_ascii_lowercase();
        let dll_key = dll_lower.strip_suffix(".dll").unwrap_or(&dll_lower);
        self.dlls.get(dll_key)
            .map(|funcs| funcs.keys().map(|s| s.as_str()).collect())
            .unwrap_or_default()
    }

    /// Analyze a PE's imports and report coverage.
    pub fn analyze_coverage(&self, imports: &[(String, Vec<String>)]) -> ImportCoverage {
        let mut coverage = ImportCoverage {
            total_dlls: imports.len(),
            total_functions: 0,
            resolved_dlls: 0,
            resolved_functions: 0,
            missing_dlls: Vec::new(),
            missing_functions: Vec::new(),
        };

        for (dll, functions) in imports {
            let dll_lower = dll.to_ascii_lowercase();
            let dll_key = dll_lower.strip_suffix(".dll").unwrap_or(&dll_lower);
            coverage.total_functions += functions.len();

            if self.dlls.contains_key(dll_key) {
                coverage.resolved_dlls += 1;
                let dll_funcs = &self.dlls[dll_key];
                for func in functions {
                    if dll_funcs.contains_key(func.as_str()) {
                        coverage.resolved_functions += 1;
                    } else {
                        coverage.missing_functions.push(format!("{}!{}", dll, func));
                    }
                }
            } else {
                coverage.missing_dlls.push(dll.clone());
                for func in functions {
                    coverage.missing_functions.push(format!("{}!{}", dll, func));
                }
            }
        }

        coverage
    }

    // =========================================================
    // DLL registrations
    // =========================================================

    fn register_dll(&mut self, name: &str, funcs: Vec<(&str, ApiFunction)>) {
        let mut map = HashMap::new();
        for (fname, f) in funcs {
            map.insert(fname.to_string(), f);
        }
        self.dlls.insert(name.to_string(), map);
    }

    fn register_kernel32(&mut self) {
        self.register_dll("kernel32", vec![
            // File I/O
            ("CreateFileA", ApiFunction::Stub("CreateFileA")),
            ("ReadFile", ApiFunction::Stub("ReadFile")),
            ("WriteFile", ApiFunction::Stub("WriteFile")),
            ("CloseHandle", ApiFunction::Stub("CloseHandle")),
            ("GetFileSize", ApiFunction::Stub("GetFileSize")),
            ("DeleteFileA", ApiFunction::Stub("DeleteFileA")),
            ("FindFirstFileA", ApiFunction::Stub("FindFirstFileA")),
            ("FindNextFileA", ApiFunction::Stub("FindNextFileA")),
            ("FindClose", ApiFunction::Stub("FindClose")),
            ("CreateDirectoryA", ApiFunction::Stub("CreateDirectoryA")),
            ("RemoveDirectoryA", ApiFunction::Stub("RemoveDirectoryA")),
            ("GetCurrentDirectoryA", ApiFunction::Stub("GetCurrentDirectoryA")),
            ("SetCurrentDirectoryA", ApiFunction::Stub("SetCurrentDirectoryA")),
            ("GetFullPathNameA", ApiFunction::Stub("GetFullPathNameA")),
            ("GetTempPathA", ApiFunction::Stub("GetTempPathA")),

            // Process / Thread
            ("GetCurrentProcess", ApiFunction::Stub("GetCurrentProcess")),
            ("GetCurrentProcessId", ApiFunction::Stub("GetCurrentProcessId")),
            ("GetCurrentThreadId", ApiFunction::Stub("GetCurrentThreadId")),
            ("CreateProcessA", ApiFunction::Stub("CreateProcessA")),
            ("ExitProcess", ApiFunction::Stub("ExitProcess")),
            ("TerminateProcess", ApiFunction::Stub("TerminateProcess")),
            ("CreateThread", ApiFunction::Stub("CreateThread")),
            ("ExitThread", ApiFunction::Stub("ExitThread")),
            ("Sleep", ApiFunction::Stub("Sleep")),
            ("SleepEx", ApiFunction::Stub("SleepEx")),
            ("GetExitCodeProcess", ApiFunction::Stub("GetExitCodeProcess")),
            ("WaitForSingleObject", ApiFunction::Stub("WaitForSingleObject")),
            ("WaitForMultipleObjects", ApiFunction::Stub("WaitForMultipleObjects")),

            // Memory
            ("VirtualAlloc", ApiFunction::Stub("VirtualAlloc")),
            ("VirtualFree", ApiFunction::Stub("VirtualFree")),
            ("VirtualProtect", ApiFunction::Stub("VirtualProtect")),
            ("HeapAlloc", ApiFunction::Stub("HeapAlloc")),
            ("HeapFree", ApiFunction::Stub("HeapFree")),
            ("HeapReAlloc", ApiFunction::Stub("HeapReAlloc")),
            ("GetProcessHeap", ApiFunction::Stub("GetProcessHeap")),
            ("HeapCreate", ApiFunction::Stub("HeapCreate")),
            ("HeapDestroy", ApiFunction::Stub("HeapDestroy")),
            ("GlobalAlloc", ApiFunction::Stub("GlobalAlloc")),
            ("GlobalFree", ApiFunction::Stub("GlobalFree")),
            ("LocalAlloc", ApiFunction::Stub("LocalAlloc")),
            ("LocalFree", ApiFunction::Stub("LocalFree")),

            // Console
            ("GetStdHandle", ApiFunction::Stub("GetStdHandle")),
            ("WriteConsoleA", ApiFunction::Stub("WriteConsoleA")),
            ("WriteConsoleW", ApiFunction::Stub("WriteConsoleW")),
            ("ReadConsoleA", ApiFunction::Stub("ReadConsoleA")),
            ("ReadConsoleW", ApiFunction::Stub("ReadConsoleW")),
            ("AllocConsole", ApiFunction::Stub("AllocConsole")),
            ("FreeConsole", ApiFunction::Stub("FreeConsole")),
            ("SetConsoleMode", ApiFunction::Stub("SetConsoleMode")),
            ("GetConsoleMode", ApiFunction::Stub("GetConsoleMode")),
            ("SetConsoleTitleA", ApiFunction::Stub("SetConsoleTitleA")),
            ("GetConsoleScreenBufferInfo", ApiFunction::Stub("GetConsoleScreenBufferInfo")),
            ("SetConsoleCursorPosition", ApiFunction::Stub("SetConsoleCursorPosition")),
            ("FillConsoleOutputCharacterA", ApiFunction::Stub("FillConsoleOutputCharacterA")),

            // Module
            ("GetModuleHandleA", ApiFunction::Stub("GetModuleHandleA")),
            ("GetModuleHandleW", ApiFunction::Stub("GetModuleHandleW")),
            ("GetModuleFileNameA", ApiFunction::Stub("GetModuleFileNameA")),
            ("GetModuleFileNameW", ApiFunction::Stub("GetModuleFileNameW")),
            ("GetProcAddress", ApiFunction::Stub("GetProcAddress")),
            ("LoadLibraryA", ApiFunction::Stub("LoadLibraryA")),
            ("LoadLibraryW", ApiFunction::Stub("LoadLibraryW")),
            ("LoadLibraryExA", ApiFunction::Stub("LoadLibraryExA")),
            ("FreeLibrary", ApiFunction::Stub("FreeLibrary")),

            // Error
            ("GetLastError", ApiFunction::Stub("GetLastError")),
            ("SetLastError", ApiFunction::Stub("SetLastError")),

            // Environment / System
            ("GetEnvironmentVariableA", ApiFunction::Stub("GetEnvironmentVariableA")),
            ("SetEnvironmentVariableA", ApiFunction::Stub("SetEnvironmentVariableA")),
            ("GetCommandLineA", ApiFunction::Stub("GetCommandLineA")),
            ("GetCommandLineW", ApiFunction::Stub("GetCommandLineW")),
            ("GetVersionExA", ApiFunction::Stub("GetVersionExA")),
            ("GetSystemInfo", ApiFunction::Stub("GetSystemInfo")),
            ("GetTickCount", ApiFunction::Stub("GetTickCount")),
            ("GetTickCount64", ApiFunction::Stub("GetTickCount64")),
            ("QueryPerformanceCounter", ApiFunction::Stub("QueryPerformanceCounter")),
            ("QueryPerformanceFrequency", ApiFunction::Stub("QueryPerformanceFrequency")),
            ("GetSystemTimeAsFileTime", ApiFunction::Stub("GetSystemTimeAsFileTime")),
            ("GetLocalTime", ApiFunction::Stub("GetLocalTime")),
            ("GetSystemTime", ApiFunction::Stub("GetSystemTime")),

            // String / locale
            ("MultiByteToWideChar", ApiFunction::Stub("MultiByteToWideChar")),
            ("WideCharToMultiByte", ApiFunction::Stub("WideCharToMultiByte")),
            ("GetACP", ApiFunction::Stub("GetACP")),
            ("IsValidCodePage", ApiFunction::Stub("IsValidCodePage")),
            ("GetCPInfo", ApiFunction::Stub("GetCPInfo")),

            // Sync
            ("InitializeCriticalSection", ApiFunction::Stub("InitializeCriticalSection")),
            ("InitializeCriticalSectionAndSpinCount", ApiFunction::Stub("InitializeCriticalSectionAndSpinCount")),
            ("DeleteCriticalSection", ApiFunction::Stub("DeleteCriticalSection")),
            ("EnterCriticalSection", ApiFunction::Stub("EnterCriticalSection")),
            ("LeaveCriticalSection", ApiFunction::Stub("LeaveCriticalSection")),
            ("TryEnterCriticalSection", ApiFunction::Stub("TryEnterCriticalSection")),
            ("CreateEventA", ApiFunction::Stub("CreateEventA")),
            ("SetEvent", ApiFunction::Stub("SetEvent")),
            ("ResetEvent", ApiFunction::Stub("ResetEvent")),
            ("CreateMutexA", ApiFunction::Stub("CreateMutexA")),
            ("ReleaseMutex", ApiFunction::Stub("ReleaseMutex")),

            // TLS
            ("TlsAlloc", ApiFunction::Stub("TlsAlloc")),
            ("TlsFree", ApiFunction::Stub("TlsFree")),
            ("TlsGetValue", ApiFunction::Stub("TlsGetValue")),
            ("TlsSetValue", ApiFunction::Stub("TlsSetValue")),
            ("FlsAlloc", ApiFunction::Stub("FlsAlloc")),
            ("FlsFree", ApiFunction::Stub("FlsFree")),
            ("FlsGetValue", ApiFunction::Stub("FlsGetValue")),
            ("FlsSetValue", ApiFunction::Stub("FlsSetValue")),

            // Misc
            ("OutputDebugStringA", ApiFunction::Stub("OutputDebugStringA")),
            ("IsDebuggerPresent", ApiFunction::Stub("IsDebuggerPresent")),
            ("IsProcessorFeaturePresent", ApiFunction::Stub("IsProcessorFeaturePresent")),
            ("UnhandledExceptionFilter", ApiFunction::Stub("UnhandledExceptionFilter")),
            ("SetUnhandledExceptionFilter", ApiFunction::Stub("SetUnhandledExceptionFilter")),
            ("RtlUnwind", ApiFunction::Stub("RtlUnwind")),
            ("EncodePointer", ApiFunction::Stub("EncodePointer")),
            ("DecodePointer", ApiFunction::Stub("DecodePointer")),

            // Pipe
            ("CreatePipe", ApiFunction::Stub("CreatePipe")),
            ("PeekNamedPipe", ApiFunction::Stub("PeekNamedPipe")),
            ("CreateNamedPipeA", ApiFunction::Stub("CreateNamedPipeA")),
            ("ConnectNamedPipe", ApiFunction::Stub("ConnectNamedPipe")),

            // Locale / DBCS
            ("IsDBCSLeadByteEx", ApiFunction::Stub("IsDBCSLeadByteEx")),
            ("IsDBCSLeadByte", ApiFunction::Stub("IsDBCSLeadByte")),
            ("GetLocaleInfoA", ApiFunction::Stub("GetLocaleInfoA")),
            ("GetLocaleInfoW", ApiFunction::Stub("GetLocaleInfoW")),
            ("GetUserDefaultLCID", ApiFunction::Stub("GetUserDefaultLCID")),
            ("LCMapStringW", ApiFunction::Stub("LCMapStringW")),

            // Virtual memory query
            ("VirtualQuery", ApiFunction::Stub("VirtualQuery")),
            ("VirtualQueryEx", ApiFunction::Stub("VirtualQueryEx")),

            // File mapping
            ("CreateFileMappingA", ApiFunction::Stub("CreateFileMappingA")),
            ("MapViewOfFile", ApiFunction::Stub("MapViewOfFile")),
            ("UnmapViewOfFile", ApiFunction::Stub("UnmapViewOfFile")),

            // Additional process/thread
            ("GetStartupInfoA", ApiFunction::Stub("GetStartupInfoA")),
            ("GetStartupInfoW", ApiFunction::Stub("GetStartupInfoW")),
            ("SetThreadStackGuarantee", ApiFunction::Stub("SetThreadStackGuarantee")),
            ("GetProcessAffinityMask", ApiFunction::Stub("GetProcessAffinityMask")),
        ]);
    }

    fn register_msvcrt(&mut self) {
        self.register_dll("msvcrt", vec![
            // stdio
            ("printf", ApiFunction::Stub("printf")),
            ("fprintf", ApiFunction::Stub("fprintf")),
            ("sprintf", ApiFunction::Stub("sprintf")),
            ("puts", ApiFunction::Stub("puts")),
            ("putchar", ApiFunction::Stub("putchar")),
            ("fputs", ApiFunction::Stub("fputs")),
            ("fwrite", ApiFunction::Stub("fwrite")),
            ("fread", ApiFunction::Stub("fread")),
            ("fopen", ApiFunction::Stub("fopen")),
            ("fclose", ApiFunction::Stub("fclose")),
            ("fgets", ApiFunction::Stub("fgets")),
            ("fflush", ApiFunction::Stub("fflush")),
            ("fseek", ApiFunction::Stub("fseek")),
            ("ftell", ApiFunction::Stub("ftell")),
            ("_write", ApiFunction::Stub("_write")),
            ("_read", ApiFunction::Stub("_read")),
            ("__acrt_iob_func", ApiFunction::Stub("__acrt_iob_func")),
            ("__stdio_common_vfprintf", ApiFunction::Stub("__stdio_common_vfprintf")),

            // stdlib
            ("malloc", ApiFunction::Stub("malloc")),
            ("calloc", ApiFunction::Stub("calloc")),
            ("realloc", ApiFunction::Stub("realloc")),
            ("free", ApiFunction::Stub("free")),
            ("exit", ApiFunction::Stub("exit")),
            ("abort", ApiFunction::Stub("abort")),
            ("atoi", ApiFunction::Stub("atoi")),
            ("atof", ApiFunction::Stub("atof")),
            ("strtol", ApiFunction::Stub("strtol")),
            ("strtod", ApiFunction::Stub("strtod")),
            ("getenv", ApiFunction::Stub("getenv")),
            ("_errno", ApiFunction::Stub("_errno")),
            ("_exit", ApiFunction::Stub("_exit")),
            ("_cexit", ApiFunction::Stub("_cexit")),

            // string
            ("strlen", ApiFunction::Stub("strlen")),
            ("strcpy", ApiFunction::Stub("strcpy")),
            ("strncpy", ApiFunction::Stub("strncpy")),
            ("strcmp", ApiFunction::Stub("strcmp")),
            ("strncmp", ApiFunction::Stub("strncmp")),
            ("_stricmp", ApiFunction::Stub("_stricmp")),
            ("strcat", ApiFunction::Stub("strcat")),
            ("strchr", ApiFunction::Stub("strchr")),
            ("strrchr", ApiFunction::Stub("strrchr")),
            ("strstr", ApiFunction::Stub("strstr")),
            ("memcpy", ApiFunction::Stub("memcpy")),
            ("memmove", ApiFunction::Stub("memmove")),
            ("memset", ApiFunction::Stub("memset")),
            ("memcmp", ApiFunction::Stub("memcmp")),
            ("_strdup", ApiFunction::Stub("_strdup")),
            ("_snprintf", ApiFunction::Stub("_snprintf")),
            ("sscanf", ApiFunction::Stub("sscanf")),
            ("wcslen", ApiFunction::Stub("wcslen")),
            ("wcscpy", ApiFunction::Stub("wcscpy")),
            ("wcscat", ApiFunction::Stub("wcscat")),

            // CRT init
            ("__getmainargs", ApiFunction::Stub("__getmainargs")),
            ("__initenv", ApiFunction::Stub("__initenv")),
            ("__set_app_type", ApiFunction::Stub("__set_app_type")),
            ("__setusermatherr", ApiFunction::Stub("__setusermatherr")),
            ("__p__commode", ApiFunction::Stub("__p__commode")),
            ("__p__fmode", ApiFunction::Stub("__p__fmode")),
            ("__mb_cur_max", ApiFunction::Stub("__mb_cur_max")),
            ("_amsg_exit", ApiFunction::Stub("_amsg_exit")),
            ("_initterm", ApiFunction::Stub("_initterm")),
            ("_initterm_e", ApiFunction::Stub("_initterm_e")),
            ("_configthreadlocale", ApiFunction::Stub("_configthreadlocale")),

            // Exception handling
            ("_except_handler3", ApiFunction::Stub("_except_handler3")),
            ("_except_handler4_common", ApiFunction::Stub("_except_handler4_common")),
            ("_XcptFilter", ApiFunction::Stub("_XcptFilter")),
            ("__C_specific_handler", ApiFunction::Stub("__C_specific_handler")),
            ("_controlfp_s", ApiFunction::Stub("_controlfp_s")),

            // Additional stdio
            ("_iob", ApiFunction::Stub("_iob")),
            ("fopen_s", ApiFunction::Stub("fopen_s")),
            ("fputc", ApiFunction::Stub("fputc")),
            ("vfprintf", ApiFunction::Stub("vfprintf")),
            ("vprintf", ApiFunction::Stub("vprintf")),
            ("vsprintf", ApiFunction::Stub("vsprintf")),
            ("_vsnprintf", ApiFunction::Stub("_vsnprintf")),
            ("vsnprintf", ApiFunction::Stub("vsnprintf")),
            ("perror", ApiFunction::Stub("perror")),

            // Additional stdlib
            ("_onexit", ApiFunction::Stub("_onexit")),
            ("atexit", ApiFunction::Stub("atexit")),
            ("qsort", ApiFunction::Stub("qsort")),
            ("bsearch", ApiFunction::Stub("bsearch")),
            ("abs", ApiFunction::Stub("abs")),
            ("labs", ApiFunction::Stub("labs")),
            ("rand", ApiFunction::Stub("rand")),
            ("srand", ApiFunction::Stub("srand")),
            ("strerror", ApiFunction::Stub("strerror")),

            // Locale
            ("setlocale", ApiFunction::Stub("setlocale")),
            ("localeconv", ApiFunction::Stub("localeconv")),

            // Signal
            ("signal", ApiFunction::Stub("signal")),
            ("raise", ApiFunction::Stub("raise")),

            // File ops
            ("rename", ApiFunction::Stub("rename")),
            ("remove", ApiFunction::Stub("remove")),
            ("tmpnam", ApiFunction::Stub("tmpnam")),
            ("tmpfile", ApiFunction::Stub("tmpfile")),

            // Threading
            ("_lock", ApiFunction::Stub("_lock")),
            ("_unlock", ApiFunction::Stub("_unlock")),
            ("_beginthread", ApiFunction::Stub("_beginthread")),
            ("_beginthreadex", ApiFunction::Stub("_beginthreadex")),
            ("_endthread", ApiFunction::Stub("_endthread")),
            ("_endthreadex", ApiFunction::Stub("_endthreadex")),

            // Math
            ("floor", ApiFunction::Stub("floor")),
            ("ceil", ApiFunction::Stub("ceil")),
            ("pow", ApiFunction::Stub("pow")),
            ("sqrt", ApiFunction::Stub("sqrt")),
            ("sin", ApiFunction::Stub("sin")),
            ("cos", ApiFunction::Stub("cos")),
            ("log", ApiFunction::Stub("log")),
            ("exp", ApiFunction::Stub("exp")),
            ("fabs", ApiFunction::Stub("fabs")),

            // Time
            ("time", ApiFunction::Stub("time")),
            ("clock", ApiFunction::Stub("clock")),
            ("difftime", ApiFunction::Stub("difftime")),
            ("localtime", ApiFunction::Stub("localtime")),
            ("gmtime", ApiFunction::Stub("gmtime")),
            ("strftime", ApiFunction::Stub("strftime")),
            ("mktime", ApiFunction::Stub("mktime")),
        ]);
    }

    fn register_ntdll(&mut self) {
        self.register_dll("ntdll", vec![
            ("RtlInitUnicodeString", ApiFunction::Stub("RtlInitUnicodeString")),
            ("NtCreateFile", ApiFunction::Stub("NtCreateFile")),
            ("NtReadFile", ApiFunction::Stub("NtReadFile")),
            ("NtWriteFile", ApiFunction::Stub("NtWriteFile")),
            ("NtClose", ApiFunction::Stub("NtClose")),
            ("NtAllocateVirtualMemory", ApiFunction::Stub("NtAllocateVirtualMemory")),
            ("NtFreeVirtualMemory", ApiFunction::Stub("NtFreeVirtualMemory")),
            ("NtProtectVirtualMemory", ApiFunction::Stub("NtProtectVirtualMemory")),
            ("NtCreateEvent", ApiFunction::Stub("NtCreateEvent")),
            ("NtWaitForSingleObject", ApiFunction::Stub("NtWaitForSingleObject")),
            ("NtTerminateProcess", ApiFunction::Stub("NtTerminateProcess")),
            ("RtlExitUserProcess", ApiFunction::Stub("RtlExitUserProcess")),
            ("NtQueryInformationProcess", ApiFunction::Stub("NtQueryInformationProcess")),
            ("NtQuerySystemInformation", ApiFunction::Stub("NtQuerySystemInformation")),
            ("RtlGetVersion", ApiFunction::Stub("RtlGetVersion")),
            ("NtQueryVirtualMemory", ApiFunction::Stub("NtQueryVirtualMemory")),
        ]);

        // libssp (GCC stack smashing protector)
        self.register_dll("libssp-0", vec![
            ("__stack_chk_fail", ApiFunction::Stub("__stack_chk_fail")),
            ("__stack_chk_guard", ApiFunction::Stub("__stack_chk_guard")),
        ]);

        // Also register advapi32 (commonly needed)
        self.register_dll("advapi32", vec![
            ("RegOpenKeyExA", ApiFunction::Stub("RegOpenKeyExA")),
            ("RegCloseKey", ApiFunction::Stub("RegCloseKey")),
            ("RegQueryValueExA", ApiFunction::Stub("RegQueryValueExA")),
            ("RegSetValueExA", ApiFunction::Stub("RegSetValueExA")),
            ("RegisterServiceCtrlHandlerA", ApiFunction::Stub("RegisterServiceCtrlHandlerA")),
            ("SetServiceStatus", ApiFunction::Stub("SetServiceStatus")),
            ("StartServiceCtrlDispatcherA", ApiFunction::Stub("StartServiceCtrlDispatcherA")),
        ]);
    }
}

impl Default for ApiTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Import coverage analysis result.
#[derive(Debug)]
pub struct ImportCoverage {
    pub total_dlls: usize,
    pub total_functions: usize,
    pub resolved_dlls: usize,
    pub resolved_functions: usize,
    pub missing_dlls: Vec<String>,
    pub missing_functions: Vec<String>,
}

impl ImportCoverage {
    /// Coverage as a percentage.
    pub fn percentage(&self) -> f64 {
        if self.total_functions == 0 {
            return 100.0;
        }
        (self.resolved_functions as f64 / self.total_functions as f64) * 100.0
    }

    /// Is the executable likely runnable?
    pub fn is_runnable(&self) -> bool {
        self.missing_dlls.is_empty() && self.percentage() >= 80.0
    }
}

impl std::fmt::Display for ImportCoverage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Import Coverage: {:.1}%", self.percentage())?;
        writeln!(f, "  DLLs:      {}/{} resolved", self.resolved_dlls, self.total_dlls)?;
        writeln!(f, "  Functions: {}/{} resolved", self.resolved_functions, self.total_functions)?;
        if !self.missing_dlls.is_empty() {
            writeln!(f, "  Missing DLLs: {}", self.missing_dlls.join(", "))?;
        }
        if !self.missing_functions.is_empty() {
            let show = std::cmp::min(10, self.missing_functions.len());
            for func in &self.missing_functions[..show] {
                writeln!(f, "  Missing: {}", func)?;
            }
            if self.missing_functions.len() > show {
                writeln!(f, "  ... and {} more", self.missing_functions.len() - show)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_table_creation() {
        let table = ApiTable::new();
        assert!(table.has_dll("kernel32"));
        assert!(table.has_dll("kernel32.dll"));
        assert!(table.has_dll("KERNEL32.DLL"));
        assert!(table.has_dll("msvcrt"));
        assert!(table.has_dll("ntdll"));
        assert!(table.has_dll("advapi32"));
        assert!(!table.has_dll("user32"));
        assert!(table.total_functions() > 100);
    }

    #[test]
    fn test_resolve() {
        let mut table = ApiTable::new();
        assert!(table.resolve("kernel32.dll", "CreateFileA").is_some());
        assert!(table.resolve("KERNEL32.DLL", "CreateFileA").is_some());
        assert!(table.resolve("kernel32", "CreateFileA").is_some());
        assert!(table.resolve("kernel32", "NonExistentFunc").is_none());
        assert!(table.resolve("fake.dll", "Whatever").is_none());
    }

    #[test]
    fn test_logging() {
        let mut table = ApiTable::new();
        table.set_logging(true);
        table.resolve("kernel32.dll", "CreateFileA");
        table.resolve("kernel32.dll", "FakeFunction");
        let log = table.call_log();
        assert_eq!(log.len(), 2);
        assert!(log[0].resolved);
        assert!(!log[1].resolved);
    }

    #[test]
    fn test_coverage_analysis() {
        let table = ApiTable::new();
        let imports = vec![
            ("kernel32.dll".to_string(), vec![
                "CreateFileA".to_string(),
                "ReadFile".to_string(),
                "SomeFakeApi".to_string(),
            ]),
            ("msvcrt.dll".to_string(), vec![
                "printf".to_string(),
                "malloc".to_string(),
            ]),
            ("unknown.dll".to_string(), vec![
                "Foo".to_string(),
            ]),
        ];

        let coverage = table.analyze_coverage(&imports);
        assert_eq!(coverage.total_dlls, 3);
        assert_eq!(coverage.total_functions, 6);
        assert_eq!(coverage.resolved_dlls, 2);
        assert_eq!(coverage.resolved_functions, 4); // CreateFileA, ReadFile, printf, malloc
        assert_eq!(coverage.missing_dlls, vec!["unknown.dll"]);
        assert_eq!(coverage.missing_functions.len(), 2); // SomeFakeApi, unknown.dll!Foo
    }
}
