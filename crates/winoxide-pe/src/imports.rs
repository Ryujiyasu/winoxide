//! PE import table parser.
//!
//! Reads the Import Directory and resolves DLL names + imported function names/ordinals.

use crate::header::*;
use crate::parser::PeFile;

/// A parsed import entry (one per imported DLL).
#[derive(Debug)]
pub struct ImportEntry<'a> {
    pub dll_name: &'a str,
    pub functions: Vec<ImportFunction<'a>>,
}

/// A single imported function.
#[derive(Debug)]
pub enum ImportFunction<'a> {
    /// Import by name (with optional hint).
    ByName { hint: u16, name: &'a str },
    /// Import by ordinal number.
    ByOrdinal(u16),
}

/// Parse all imports from a PE file.
pub fn parse_imports<'a>(pe: &PeFile<'a>) -> Vec<ImportEntry<'a>> {
    let mut result = Vec::new();

    let import_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_IMPORT) {
        Some(d) => d,
        None => return result,
    };

    let descriptor_size = std::mem::size_of::<ImageImportDescriptor>();
    let mut offset = 0;

    loop {
        let rva = import_dir.VirtualAddress + offset as u32;
        let desc_data = match pe.rva_to_slice(rva, descriptor_size) {
            Some(d) => d,
            None => break,
        };

        let desc: &ImageImportDescriptor =
            unsafe { &*(desc_data.as_ptr() as *const ImageImportDescriptor) };

        // Terminator: all fields zero
        if desc.Name == 0 && desc.FirstThunk == 0 {
            break;
        }

        let dll_name = pe.read_string_at_rva(desc.Name).unwrap_or("<unknown>");

        // Read the Import Lookup Table (ILT) or fall back to Import Address Table (IAT)
        let thunk_rva = if desc.OriginalFirstThunk != 0 {
            desc.OriginalFirstThunk
        } else {
            desc.FirstThunk
        };

        let functions = if pe.is_64bit() {
            parse_thunks_64(pe, thunk_rva)
        } else {
            parse_thunks_32(pe, thunk_rva)
        };

        result.push(ImportEntry { dll_name, functions });
        offset += descriptor_size;
    }

    result
}

fn parse_thunks_64<'a>(pe: &PeFile<'a>, mut rva: u32) -> Vec<ImportFunction<'a>> {
    let mut funcs = Vec::new();

    loop {
        let data = match pe.rva_to_slice(rva, 8) {
            Some(d) => d,
            None => break,
        };

        let thunk = u64::from_le_bytes(data[..8].try_into().unwrap());
        if thunk == 0 {
            break;
        }

        if (thunk & IMAGE_ORDINAL_FLAG64) != 0 {
            funcs.push(ImportFunction::ByOrdinal((thunk & 0xFFFF) as u16));
        } else {
            let name_rva = thunk as u32;
            // IMAGE_IMPORT_BY_NAME: hint (u16) + name (null-terminated)
            if let Some(hint_data) = pe.rva_to_slice(name_rva, 2) {
                let hint = u16::from_le_bytes([hint_data[0], hint_data[1]]);
                let name = pe.read_string_at_rva(name_rva + 2).unwrap_or("<unknown>");
                funcs.push(ImportFunction::ByName { hint, name });
            }
        }

        rva += 8;
    }

    funcs
}

fn parse_thunks_32<'a>(pe: &PeFile<'a>, mut rva: u32) -> Vec<ImportFunction<'a>> {
    let mut funcs = Vec::new();

    loop {
        let data = match pe.rva_to_slice(rva, 4) {
            Some(d) => d,
            None => break,
        };

        let thunk = u32::from_le_bytes(data[..4].try_into().unwrap());
        if thunk == 0 {
            break;
        }

        if (thunk & IMAGE_ORDINAL_FLAG32) != 0 {
            funcs.push(ImportFunction::ByOrdinal((thunk & 0xFFFF) as u16));
        } else {
            if let Some(hint_data) = pe.rva_to_slice(thunk, 2) {
                let hint = u16::from_le_bytes([hint_data[0], hint_data[1]]);
                let name = pe.read_string_at_rva(thunk + 2).unwrap_or("<unknown>");
                funcs.push(ImportFunction::ByName { hint, name });
            }
        }

        rva += 4;
    }

    funcs
}
