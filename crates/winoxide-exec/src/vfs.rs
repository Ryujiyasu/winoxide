//! Virtual File System — sandboxed file I/O for Wasm execution.
//!
//! Instead of accessing the real filesystem, Windows executables interact
//! with this in-memory VFS. This provides:
//! - Complete isolation from the host system
//! - Deterministic behavior across platforms
//! - Full audit trail of file operations

use std::collections::HashMap;

/// Virtual file system.
#[derive(Debug)]
pub struct VirtualFs {
    /// Path → file content.
    files: HashMap<String, VfsFile>,
    /// Current working directory.
    cwd: String,
    /// Access log for security analysis.
    access_log: Vec<FsAccessLog>,
    /// Policy: what paths are accessible.
    policy: FsPolicy,
}

/// A virtual file.
#[derive(Debug, Clone)]
pub struct VfsFile {
    pub content: Vec<u8>,
    pub readonly: bool,
    pub created: bool,
}

/// File access log entry.
#[derive(Debug, Clone)]
pub struct FsAccessLog {
    pub operation: FsOp,
    pub path: String,
    pub allowed: bool,
}

/// File operation types.
#[derive(Debug, Clone, PartialEq)]
pub enum FsOp {
    Open,
    Read,
    Write,
    Delete,
    CreateDir,
    ListDir,
}

/// Filesystem access policy.
#[derive(Debug, Clone)]
pub struct FsPolicy {
    /// Allowed path prefixes for reading.
    pub read_allow: Vec<String>,
    /// Allowed path prefixes for writing.
    pub write_allow: Vec<String>,
    /// Deny all access by default (sandbox mode).
    pub deny_by_default: bool,
}

impl Default for FsPolicy {
    fn default() -> Self {
        Self {
            read_allow: vec![
                "C:\\".to_string(),
            ],
            write_allow: vec![
                "C:\\Users\\".to_string(),
                "C:\\Temp\\".to_string(),
            ],
            deny_by_default: true,
        }
    }
}

/// Handle to an open virtual file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VfsHandle(pub u32);

/// Open file state.
#[derive(Debug)]
struct OpenFile {
    path: String,
    position: usize,
    writable: bool,
}

impl VirtualFs {
    /// Create a new virtual filesystem with default Windows structure.
    pub fn new() -> Self {
        let mut vfs = Self {
            files: HashMap::new(),
            cwd: "C:\\".to_string(),
            access_log: Vec::new(),
            policy: FsPolicy::default(),
        };
        vfs.setup_default_structure();
        vfs
    }

    /// Create a minimal sandbox VFS (no default files).
    pub fn sandbox() -> Self {
        Self {
            files: HashMap::new(),
            cwd: "C:\\".to_string(),
            access_log: Vec::new(),
            policy: FsPolicy {
                read_allow: Vec::new(),
                write_allow: Vec::new(),
                deny_by_default: true,
            },
        }
    }

    /// Set up default Windows directory structure.
    fn setup_default_structure(&mut self) {
        // Windows system directories (empty placeholders)
        let dirs = [
            "C:\\Windows\\",
            "C:\\Windows\\System32\\",
            "C:\\Windows\\SysWOW64\\",
            "C:\\Users\\",
            "C:\\Users\\Default\\",
            "C:\\Program Files\\",
            "C:\\Temp\\",
        ];
        for dir in &dirs {
            self.files.insert(dir.to_string(), VfsFile {
                content: Vec::new(),
                readonly: true,
                created: true,
            });
        }
    }

    /// Get the access log.
    pub fn access_log(&self) -> &[FsAccessLog] {
        &self.access_log
    }

    /// Clear the access log.
    pub fn clear_log(&mut self) {
        self.access_log.clear();
    }

    /// Set the filesystem policy.
    pub fn set_policy(&mut self, policy: FsPolicy) {
        self.policy = policy;
    }

    /// Normalize a Windows path.
    fn normalize_path(&self, path: &str) -> String {
        let mut normalized = path.replace('/', "\\");
        // Handle relative paths
        if !normalized.contains(':') {
            normalized = format!("{}{}", self.cwd, normalized);
        }
        // Uppercase drive letter
        if normalized.len() >= 2 && normalized.as_bytes()[1] == b':' {
            let mut chars: Vec<char> = normalized.chars().collect();
            chars[0] = chars[0].to_ascii_uppercase();
            normalized = chars.into_iter().collect();
        }
        normalized
    }

    /// Check read permission.
    fn check_read(&mut self, path: &str) -> bool {
        if !self.policy.deny_by_default {
            return true;
        }
        let allowed = self.policy.read_allow.iter()
            .any(|prefix| path.to_ascii_uppercase().starts_with(&prefix.to_ascii_uppercase()));
        self.access_log.push(FsAccessLog {
            operation: FsOp::Read,
            path: path.to_string(),
            allowed,
        });
        allowed
    }

    /// Check write permission.
    fn check_write(&mut self, path: &str) -> bool {
        if !self.policy.deny_by_default {
            return true;
        }
        let allowed = self.policy.write_allow.iter()
            .any(|prefix| path.to_ascii_uppercase().starts_with(&prefix.to_ascii_uppercase()));
        self.access_log.push(FsAccessLog {
            operation: FsOp::Write,
            path: path.to_string(),
            allowed,
        });
        allowed
    }

    /// Add a file to the VFS (for pre-populating).
    pub fn add_file(&mut self, path: &str, content: Vec<u8>) {
        let normalized = self.normalize_path(path);
        self.files.insert(normalized, VfsFile {
            content,
            readonly: false,
            created: true,
        });
    }

    /// Read a file.
    pub fn read_file(&mut self, path: &str) -> Result<&[u8], VfsError> {
        let normalized = self.normalize_path(path);
        if !self.check_read(&normalized) {
            return Err(VfsError::AccessDenied(normalized));
        }
        self.files.get(&normalized)
            .map(|f| f.content.as_slice())
            .ok_or(VfsError::FileNotFound(normalized))
    }

    /// Write a file.
    pub fn write_file(&mut self, path: &str, content: Vec<u8>) -> Result<(), VfsError> {
        let normalized = self.normalize_path(path);
        if !self.check_write(&normalized) {
            return Err(VfsError::AccessDenied(normalized));
        }
        if let Some(f) = self.files.get(&normalized) {
            if f.readonly {
                return Err(VfsError::AccessDenied(normalized));
            }
        }
        self.files.insert(normalized, VfsFile {
            content,
            readonly: false,
            created: true,
        });
        Ok(())
    }

    /// Delete a file.
    pub fn delete_file(&mut self, path: &str) -> Result<(), VfsError> {
        let normalized = self.normalize_path(path);
        if !self.check_write(&normalized) {
            return Err(VfsError::AccessDenied(normalized));
        }
        self.access_log.push(FsAccessLog {
            operation: FsOp::Delete,
            path: normalized.clone(),
            allowed: true,
        });
        self.files.remove(&normalized)
            .map(|_| ())
            .ok_or(VfsError::FileNotFound(normalized))
    }

    /// Check if a file exists.
    pub fn file_exists(&self, path: &str) -> bool {
        let normalized = self.normalize_path(path);
        self.files.contains_key(&normalized)
    }

    /// Get current working directory.
    pub fn cwd(&self) -> &str {
        &self.cwd
    }

    /// Set current working directory.
    pub fn set_cwd(&mut self, path: &str) {
        self.cwd = self.normalize_path(path);
        if !self.cwd.ends_with('\\') {
            self.cwd.push('\\');
        }
    }

    /// List files in a directory.
    pub fn list_dir(&self, path: &str) -> Vec<String> {
        let normalized = self.normalize_path(path);
        let prefix = if normalized.ends_with('\\') {
            normalized.clone()
        } else {
            format!("{}\\", normalized)
        };

        self.files.keys()
            .filter(|k| k.starts_with(&prefix) && *k != &prefix)
            .cloned()
            .collect()
    }

    /// Total number of files in the VFS.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }
}

impl Default for VirtualFs {
    fn default() -> Self {
        Self::new()
    }
}

/// VFS error types.
#[derive(Debug)]
pub enum VfsError {
    FileNotFound(String),
    AccessDenied(String),
    AlreadyExists(String),
}

impl std::fmt::Display for VfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FileNotFound(p) => write!(f, "file not found: {}", p),
            Self::AccessDenied(p) => write!(f, "access denied: {}", p),
            Self::AlreadyExists(p) => write!(f, "already exists: {}", p),
        }
    }
}

impl std::error::Error for VfsError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_structure() {
        let vfs = VirtualFs::new();
        assert!(vfs.file_exists("C:\\Windows\\"));
        assert!(vfs.file_exists("C:\\Windows\\System32\\"));
        assert!(vfs.file_exists("C:\\Temp\\"));
    }

    #[test]
    fn test_read_write() {
        let mut vfs = VirtualFs::new();
        vfs.add_file("C:\\Users\\test.txt", b"hello".to_vec());

        let data = vfs.read_file("C:\\Users\\test.txt").unwrap();
        assert_eq!(data, b"hello");

        vfs.write_file("C:\\Users\\output.txt", b"world".to_vec()).unwrap();
        let data = vfs.read_file("C:\\Users\\output.txt").unwrap();
        assert_eq!(data, b"world");
    }

    #[test]
    fn test_sandbox_denies_access() {
        let mut vfs = VirtualFs::sandbox();
        assert!(vfs.read_file("C:\\Windows\\System32\\secret.dll").is_err());
        assert!(vfs.write_file("C:\\hacked.txt", b"pwned".to_vec()).is_err());
    }

    #[test]
    fn test_policy_enforcement() {
        let mut vfs = VirtualFs::new();
        // Can read from C:\ (allowed by default policy)
        vfs.add_file("C:\\test.txt", b"ok".to_vec());
        assert!(vfs.read_file("C:\\test.txt").is_ok());

        // Cannot write to C:\Windows (not in write_allow)
        assert!(vfs.write_file("C:\\Windows\\evil.dll", b"malware".to_vec()).is_err());

        // Can write to C:\\Temp (in write_allow)
        assert!(vfs.write_file("C:\\Temp\\log.txt", b"safe".to_vec()).is_ok());
    }

    #[test]
    fn test_access_log() {
        let mut vfs = VirtualFs::new();
        vfs.add_file("C:\\Users\\data.txt", b"data".to_vec());
        let _ = vfs.read_file("C:\\Users\\data.txt");
        let _ = vfs.write_file("C:\\Windows\\hack.dll", b"nope".to_vec());

        let log = vfs.access_log();
        assert!(log.len() >= 2);
        // First read was allowed, write to Windows was denied
        assert!(log.iter().any(|l| l.allowed && l.operation == FsOp::Read));
        assert!(log.iter().any(|l| !l.allowed && l.operation == FsOp::Write));
    }

    #[test]
    fn test_path_normalization() {
        let mut vfs = VirtualFs::new();
        // Drive letter gets uppercased
        vfs.add_file("c:\\temp\\test.txt", b"data".to_vec());
        assert!(vfs.file_exists("C:\\temp\\test.txt"));
        // Relative paths resolved against cwd
        vfs.set_cwd("C:\\temp");
        vfs.add_file("hello.txt", b"hi".to_vec());
        assert!(vfs.file_exists("C:\\temp\\hello.txt"));
    }
}
