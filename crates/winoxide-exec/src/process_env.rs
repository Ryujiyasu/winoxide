//! Process environment — simulates the Windows process context.
//!
//! Sets up PEB, TEB, environment variables, command line, etc.

use std::collections::HashMap;

/// Simulated Windows process environment.
#[derive(Debug)]
pub struct ProcessEnv {
    /// Process ID.
    pub pid: u32,
    /// Thread ID (main thread).
    pub tid: u32,
    /// Command line arguments.
    pub args: Vec<String>,
    /// Environment variables.
    pub env_vars: HashMap<String, String>,
    /// Module name (exe path).
    pub module_name: String,
    /// Exit code (None = still running).
    pub exit_code: Option<u32>,
    /// Windows version to report.
    pub version: WindowsVersion,
    /// Standard handles.
    pub stdin_handle: u32,
    pub stdout_handle: u32,
    pub stderr_handle: u32,
}

/// Simulated Windows version.
#[derive(Debug, Clone)]
pub struct WindowsVersion {
    pub major: u32,
    pub minor: u32,
    pub build: u32,
    pub service_pack: String,
}

impl WindowsVersion {
    /// Windows 10 (21H2).
    pub fn win10() -> Self {
        Self {
            major: 10,
            minor: 0,
            build: 19044,
            service_pack: String::new(),
        }
    }

    /// Windows 7 SP1 (for compatibility).
    pub fn win7() -> Self {
        Self {
            major: 6,
            minor: 1,
            build: 7601,
            service_pack: "Service Pack 1".to_string(),
        }
    }
}

impl ProcessEnv {
    /// Create a new process environment for running an executable.
    pub fn new(exe_path: &str, args: Vec<String>) -> Self {
        let mut env_vars = HashMap::new();
        // Default environment variables
        env_vars.insert("SystemRoot".to_string(), "C:\\Windows".to_string());
        env_vars.insert("SystemDrive".to_string(), "C:".to_string());
        env_vars.insert("TEMP".to_string(), "C:\\Temp".to_string());
        env_vars.insert("TMP".to_string(), "C:\\Temp".to_string());
        env_vars.insert("PATH".to_string(),
            "C:\\Windows\\System32;C:\\Windows;C:\\Windows\\System32\\Wbem".to_string());
        env_vars.insert("PATHEXT".to_string(),
            ".COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS;.MSC".to_string());
        env_vars.insert("COMSPEC".to_string(), "C:\\Windows\\System32\\cmd.exe".to_string());
        env_vars.insert("USERNAME".to_string(), "User".to_string());
        env_vars.insert("USERPROFILE".to_string(), "C:\\Users\\User".to_string());
        env_vars.insert("HOMEDRIVE".to_string(), "C:".to_string());
        env_vars.insert("HOMEPATH".to_string(), "\\Users\\User".to_string());
        env_vars.insert("APPDATA".to_string(), "C:\\Users\\User\\AppData\\Roaming".to_string());
        env_vars.insert("LOCALAPPDATA".to_string(), "C:\\Users\\User\\AppData\\Local".to_string());
        env_vars.insert("PROGRAMFILES".to_string(), "C:\\Program Files".to_string());
        env_vars.insert("NUMBER_OF_PROCESSORS".to_string(), "4".to_string());
        env_vars.insert("PROCESSOR_ARCHITECTURE".to_string(), "AMD64".to_string());
        env_vars.insert("OS".to_string(), "Windows_NT".to_string());

        Self {
            pid: 1000,
            tid: 1004,
            args,
            env_vars,
            module_name: exe_path.to_string(),
            exit_code: None,
            version: WindowsVersion::win10(),
            stdin_handle: 0xFFFFFFF6,  // STD_INPUT_HANDLE
            stdout_handle: 0xFFFFFFF5, // STD_OUTPUT_HANDLE
            stderr_handle: 0xFFFFFFF4, // STD_ERROR_HANDLE
        }
    }

    /// Get the full command line as a string (like GetCommandLineA).
    pub fn command_line(&self) -> String {
        if self.args.is_empty() {
            return self.module_name.clone();
        }
        let mut parts = vec![self.module_name.clone()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }

    /// Get environment variable (case-insensitive, like Windows).
    pub fn get_env(&self, name: &str) -> Option<&str> {
        let upper = name.to_ascii_uppercase();
        self.env_vars.iter()
            .find(|(k, _)| k.to_ascii_uppercase() == upper)
            .map(|(_, v)| v.as_str())
    }

    /// Set environment variable.
    pub fn set_env(&mut self, name: &str, value: &str) {
        self.env_vars.insert(name.to_string(), value.to_string());
    }

    /// Remove environment variable.
    pub fn remove_env(&mut self, name: &str) {
        let upper = name.to_ascii_uppercase();
        self.env_vars.retain(|k, _| k.to_ascii_uppercase() != upper);
    }

    /// Get the environment block as a Windows-style double-null-terminated string.
    pub fn environment_block(&self) -> Vec<u8> {
        let mut block = Vec::new();
        for (key, value) in &self.env_vars {
            let entry = format!("{}={}\0", key, value);
            block.extend(entry.as_bytes());
        }
        block.push(0); // Double null terminator
        block
    }

    /// Mark process as exited.
    pub fn exit(&mut self, code: u32) {
        self.exit_code = Some(code);
    }

    /// Is the process still running?
    pub fn is_running(&self) -> bool {
        self.exit_code.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_env_creation() {
        let env = ProcessEnv::new("C:\\test.exe", vec!["--flag".to_string()]);
        assert_eq!(env.command_line(), "C:\\test.exe --flag");
        assert_eq!(env.get_env("OS"), Some("Windows_NT"));
        assert_eq!(env.get_env("os"), Some("Windows_NT")); // case-insensitive
        assert!(env.is_running());
    }

    #[test]
    fn test_env_vars() {
        let mut env = ProcessEnv::new("test.exe", vec![]);
        env.set_env("MY_VAR", "hello");
        assert_eq!(env.get_env("MY_VAR"), Some("hello"));

        env.remove_env("MY_VAR");
        assert_eq!(env.get_env("MY_VAR"), None);
    }

    #[test]
    fn test_exit() {
        let mut env = ProcessEnv::new("test.exe", vec![]);
        assert!(env.is_running());
        env.exit(0);
        assert!(!env.is_running());
        assert_eq!(env.exit_code, Some(0));
    }

    #[test]
    fn test_environment_block() {
        let env = ProcessEnv::new("test.exe", vec![]);
        let block = env.environment_block();
        // Should end with double null
        assert_eq!(block[block.len() - 1], 0);
        // Should contain at least one variable
        assert!(block.len() > 10);
    }
}
