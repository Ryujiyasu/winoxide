//! PE image loader — maps a PE file into memory, applies relocations, resolves imports.

use crate::header::*;
use crate::parser::PeFile;
use std::collections::HashMap;

/// A loaded PE module in memory.
pub struct LoadedModule {
    /// The mapped image bytes.
    pub image: Vec<u8>,
    /// Actual base address (for pointer arithmetic in a real implementation,
    /// this would be the mmap'd address; here we use the vec's base).
    pub base_address: u64,
    /// Preferred image base from PE headers.
    pub preferred_base: u64,
    /// Entry point RVA.
    pub entry_point_rva: u32,
    /// Whether this is a DLL.
    pub is_dll: bool,
    /// Module name.
    pub name: String,
    /// Export table: name → RVA.
    pub exports: HashMap<String, u32>,
}

/// Errors during loading.
#[derive(Debug)]
pub enum LoadError {
    ParseError(crate::parser::PeError),
    SectionOutOfBounds,
    ImportNotFound { dll: String, function: String },
    RelocationError(String),
}

impl From<crate::parser::PeError> for LoadError {
    fn from(e: crate::parser::PeError) -> Self {
        LoadError::ParseError(e)
    }
}

/// Map a PE file into a contiguous memory buffer.
///
/// This performs the in-memory loading steps:
/// 1. Allocate SizeOfImage bytes
/// 2. Copy headers
/// 3. Copy sections to their virtual addresses
/// 4. Build export table
pub fn map_pe_image(data: &[u8], name: &str) -> Result<LoadedModule, LoadError> {
    let pe = PeFile::parse(data)?;

    let size_of_image = pe.optional_header.size_of_image() as usize;
    let size_of_headers = pe.optional_header.size_of_headers() as usize;
    let preferred_base = pe.optional_header.image_base();
    let entry_point_rva = pe.optional_header.entry_point();
    let is_dll = pe.is_dll();

    // Allocate the image
    let mut image = vec![0u8; size_of_image];

    // Copy headers
    let header_copy_size = size_of_headers.min(data.len()).min(size_of_image);
    image[..header_copy_size].copy_from_slice(&data[..header_copy_size]);

    // Copy sections
    for section in pe.sections {
        let raw_offset = section.PointerToRawData as usize;
        let raw_size = section.SizeOfRawData as usize;
        let virt_addr = section.VirtualAddress as usize;

        if raw_size == 0 || raw_offset == 0 {
            continue; // BSS or similar
        }

        let src_end = raw_offset.saturating_add(raw_size).min(data.len());
        let dst_end = virt_addr.saturating_add(src_end - raw_offset).min(size_of_image);

        if virt_addr >= size_of_image || raw_offset >= data.len() {
            continue;
        }

        let copy_size = (src_end - raw_offset).min(dst_end - virt_addr);
        image[virt_addr..virt_addr + copy_size]
            .copy_from_slice(&data[raw_offset..raw_offset + copy_size]);
    }

    // Build export table
    let exports = build_export_table(&pe);

    Ok(LoadedModule {
        image,
        base_address: preferred_base, // In real impl, this is the mmap address
        preferred_base,
        entry_point_rva,
        is_dll,
        name: name.to_string(),
        exports,
    })
}

/// Build a name→RVA export lookup table.
fn build_export_table(pe: &PeFile) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for entry in crate::exports::parse_exports(pe) {
        if let Some(name) = entry.name {
            map.insert(name.to_string(), entry.rva);
        }
    }
    map
}

impl LoadedModule {
    /// Look up an export by name, returning its address (base + RVA).
    pub fn get_export_address(&self, name: &str) -> Option<u64> {
        self.exports.get(name).map(|&rva| self.base_address + rva as u64)
    }

    /// Get the entry point address.
    pub fn entry_point_address(&self) -> u64 {
        self.base_address + self.entry_point_rva as u64
    }

    /// Read bytes from the loaded image at an RVA.
    pub fn read_at_rva(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let start = rva as usize;
        let end = start + size;
        if end <= self.image.len() {
            Some(&self.image[start..end])
        } else {
            None
        }
    }

    /// Read a null-terminated string at an RVA.
    pub fn read_string_at_rva(&self, rva: u32) -> Option<&str> {
        let start = rva as usize;
        if start >= self.image.len() {
            return None;
        }
        let remaining = &self.image[start..];
        let len = remaining.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&remaining[..len]).ok()
    }
}

/// Simple module registry for tracking loaded DLLs.
#[derive(Default)]
pub struct ModuleRegistry {
    modules: HashMap<String, LoadedModule>,
}

impl ModuleRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load a PE file and register it.
    pub fn load(&mut self, name: &str, data: &[u8]) -> Result<&LoadedModule, LoadError> {
        let lower_name = name.to_lowercase();
        if self.modules.contains_key(&lower_name) {
            return Ok(&self.modules[&lower_name]);
        }

        let module = map_pe_image(data, name)?;
        self.modules.insert(lower_name.clone(), module);
        Ok(&self.modules[&lower_name])
    }

    /// Look up a loaded module.
    pub fn get(&self, name: &str) -> Option<&LoadedModule> {
        self.modules.get(&name.to_lowercase())
    }

    /// Resolve an import: find the function address in a loaded DLL.
    pub fn resolve_import(&self, dll_name: &str, func_name: &str) -> Option<u64> {
        let module = self.get(dll_name)?;
        module.get_export_address(func_name)
    }

    /// Number of loaded modules.
    pub fn count(&self) -> usize {
        self.modules.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_registry() {
        let mut registry = ModuleRegistry::new();
        assert_eq!(registry.count(), 0);
        assert!(registry.get("kernel32.dll").is_none());
    }
}
