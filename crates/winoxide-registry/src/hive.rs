//! Registry hive — the in-memory tree structure.

use std::collections::BTreeMap;

/// A registry value (stored under a key).
#[derive(Debug, Clone, PartialEq)]
pub enum RegValue {
    /// REG_NONE
    None,
    /// REG_SZ — null-terminated Unicode string
    String(String),
    /// REG_EXPAND_SZ — string with environment variable expansion
    ExpandString(String),
    /// REG_BINARY — arbitrary binary data
    Binary(Vec<u8>),
    /// REG_DWORD — 32-bit integer (little-endian)
    Dword(u32),
    /// REG_QWORD — 64-bit integer (little-endian)
    Qword(u64),
    /// REG_MULTI_SZ — list of strings
    MultiString(Vec<String>),
}

impl RegValue {
    /// Registry type code (REG_* constant).
    pub fn reg_type(&self) -> u32 {
        match self {
            Self::None => REG_NONE,
            Self::String(_) => REG_SZ,
            Self::ExpandString(_) => REG_EXPAND_SZ,
            Self::Binary(_) => REG_BINARY,
            Self::Dword(_) => REG_DWORD,
            Self::Qword(_) => REG_QWORD,
            Self::MultiString(_) => REG_MULTI_SZ,
        }
    }

    /// Serialize to bytes (as Windows would store it).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::None => vec![],
            Self::String(s) | Self::ExpandString(s) => {
                let mut buf: Vec<u8> = s.encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                buf.extend_from_slice(&[0, 0]); // null terminator
                buf
            }
            Self::Binary(b) => b.clone(),
            Self::Dword(v) => v.to_le_bytes().to_vec(),
            Self::Qword(v) => v.to_le_bytes().to_vec(),
            Self::MultiString(strings) => {
                let mut buf = Vec::new();
                for s in strings {
                    buf.extend(s.encode_utf16().flat_map(|c| c.to_le_bytes()));
                    buf.extend_from_slice(&[0, 0]);
                }
                buf.extend_from_slice(&[0, 0]); // double null terminator
                buf
            }
        }
    }
}

// Registry type constants
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_LINK: u32 = 6;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// A registry key node.
#[derive(Debug, Clone)]
pub struct RegKey {
    /// Subkeys (case-insensitive: stored lowercase).
    pub subkeys: BTreeMap<String, RegKey>,
    /// Values (case-insensitive: stored lowercase).
    /// The default value uses empty string as key.
    pub values: BTreeMap<String, RegValue>,
}

impl RegKey {
    pub fn new() -> Self {
        Self {
            subkeys: BTreeMap::new(),
            values: BTreeMap::new(),
        }
    }

    /// Create or open a subkey, returning a mutable reference.
    pub fn create_subkey(&mut self, name: &str) -> &mut RegKey {
        self.subkeys
            .entry(name.to_lowercase())
            .or_insert_with(RegKey::new)
    }

    /// Open an existing subkey.
    pub fn open_subkey(&self, name: &str) -> Option<&RegKey> {
        self.subkeys.get(&name.to_lowercase())
    }

    /// Open an existing subkey mutably.
    pub fn open_subkey_mut(&mut self, name: &str) -> Option<&mut RegKey> {
        self.subkeys.get_mut(&name.to_lowercase())
    }

    /// Delete a subkey (must be empty).
    pub fn delete_subkey(&mut self, name: &str) -> bool {
        let lower = name.to_lowercase();
        if let Some(key) = self.subkeys.get(&lower) {
            if !key.subkeys.is_empty() {
                return false; // Cannot delete non-empty key
            }
        }
        self.subkeys.remove(&lower).is_some()
    }

    /// Set a value.
    pub fn set_value(&mut self, name: &str, value: RegValue) {
        self.values.insert(name.to_lowercase(), value);
    }

    /// Get a value.
    pub fn get_value(&self, name: &str) -> Option<&RegValue> {
        self.values.get(&name.to_lowercase())
    }

    /// Delete a value.
    pub fn delete_value(&mut self, name: &str) -> bool {
        self.values.remove(&name.to_lowercase()).is_some()
    }

    /// Enumerate subkey names.
    pub fn enum_subkeys(&self) -> Vec<&str> {
        self.subkeys.keys().map(|s| s.as_str()).collect()
    }

    /// Enumerate value names.
    pub fn enum_values(&self) -> Vec<(&str, &RegValue)> {
        self.values.iter().map(|(k, v)| (k.as_str(), v)).collect()
    }
}

impl Default for RegKey {
    fn default() -> Self {
        Self::new()
    }
}

/// The complete registry — a set of root hives.
#[derive(Debug)]
pub struct Registry {
    /// HKEY_LOCAL_MACHINE
    pub hklm: RegKey,
    /// HKEY_CURRENT_USER
    pub hkcu: RegKey,
    /// HKEY_CLASSES_ROOT (merged view of HKLM\SOFTWARE\Classes + HKCU\SOFTWARE\Classes)
    pub hkcr: RegKey,
    /// HKEY_USERS
    pub hku: RegKey,
    /// HKEY_CURRENT_CONFIG
    pub hkcc: RegKey,
}

impl Registry {
    pub fn new() -> Self {
        let mut reg = Self {
            hklm: RegKey::new(),
            hkcu: RegKey::new(),
            hkcr: RegKey::new(),
            hku: RegKey::new(),
            hkcc: RegKey::new(),
        };
        reg.init_defaults();
        reg
    }

    /// Initialize with standard Windows registry structure.
    fn init_defaults(&mut self) {
        // HKLM\SOFTWARE
        let sw = self.hklm.create_subkey("software");
        sw.create_subkey("microsoft");
        sw.create_subkey("classes");

        // HKLM\SYSTEM\CurrentControlSet
        let sys = self.hklm.create_subkey("system");
        let ccs = sys.create_subkey("currentcontrolset");
        ccs.create_subkey("control");
        ccs.create_subkey("services");

        // HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion
        let ms = self.hklm.open_subkey_mut("software").unwrap()
            .open_subkey_mut("microsoft").unwrap();
        let wnt = ms.create_subkey("windows nt");
        let cv = wnt.create_subkey("currentversion");
        cv.set_value("productname", RegValue::String("Winoxide".to_string()));
        cv.set_value("currentbuildnumber", RegValue::String("19045".to_string()));
        cv.set_value("currentversion", RegValue::String("6.3".to_string()));

        // HKCU\SOFTWARE
        self.hkcu.create_subkey("software");

        // HKCU\Environment
        self.hkcu.create_subkey("environment");
    }

    /// Navigate to a key by path (e.g., "SOFTWARE\\Microsoft\\Windows NT").
    pub fn open_path<'a>(&'a self, root: &'a RegKey, path: &str) -> Option<&'a RegKey> {
        let mut current = root;
        for component in path.split('\\').filter(|s| !s.is_empty()) {
            current = current.open_subkey(component)?;
        }
        Some(current)
    }

    /// Navigate to a key by path, creating intermediate keys as needed.
    pub fn create_path(&mut self, root: &mut RegKey, path: &str) -> &mut RegKey {
        let mut current = root as *mut RegKey;
        for component in path.split('\\').filter(|s| !s.is_empty()) {
            current = unsafe { &mut *current }.create_subkey(component) as *mut RegKey;
        }
        unsafe { &mut *current }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_basic() {
        let mut reg = Registry::new();

        // Verify default structure
        assert!(reg.hklm.open_subkey("software").is_some());
        assert!(reg.hklm.open_subkey("system").is_some());

        // Read a default value
        let cv = reg.open_path(&reg.hklm, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").unwrap();
        assert_eq!(cv.get_value("productname"), Some(&RegValue::String("Winoxide".to_string())));
    }

    #[test]
    fn test_create_and_read() {
        let mut key = RegKey::new();

        key.set_value("name", RegValue::String("test".to_string()));
        key.set_value("count", RegValue::Dword(42));
        key.set_value("data", RegValue::Binary(vec![1, 2, 3]));

        assert_eq!(key.get_value("name"), Some(&RegValue::String("test".to_string())));
        assert_eq!(key.get_value("count"), Some(&RegValue::Dword(42)));
        assert_eq!(key.get_value("NAME"), Some(&RegValue::String("test".to_string()))); // case insensitive
    }

    #[test]
    fn test_subkeys() {
        let mut key = RegKey::new();

        key.create_subkey("child1");
        key.create_subkey("child2");

        assert_eq!(key.enum_subkeys().len(), 2);
        assert!(key.open_subkey("CHILD1").is_some()); // case insensitive

        // Delete empty subkey
        assert!(key.delete_subkey("child1"));
        assert_eq!(key.enum_subkeys().len(), 1);
    }

    #[test]
    fn test_reg_value_serialization() {
        let val = RegValue::Dword(0x12345678);
        assert_eq!(val.to_bytes(), vec![0x78, 0x56, 0x34, 0x12]);
        assert_eq!(val.reg_type(), REG_DWORD);

        let val = RegValue::String("AB".to_string());
        // UTF-16LE: 'A'=0x41,0x00 'B'=0x42,0x00 null=0x00,0x00
        assert_eq!(val.to_bytes(), vec![0x41, 0x00, 0x42, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_delete_nonempty_subkey_fails() {
        let mut key = RegKey::new();
        let child = key.create_subkey("parent");
        child.create_subkey("child");

        assert!(!key.delete_subkey("parent")); // has children, should fail
    }
}
