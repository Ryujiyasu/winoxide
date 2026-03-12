//! PE export table parser.

use crate::header::*;
use crate::parser::PeFile;

/// A single exported function.
#[derive(Debug)]
pub struct ExportEntry<'a> {
    pub ordinal: u16,
    pub name: Option<&'a str>,
    pub rva: u32,
}

/// Parse all exports from a PE file.
pub fn parse_exports<'a>(pe: &PeFile<'a>) -> Vec<ExportEntry<'a>> {
    let mut result = Vec::new();

    let export_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT) {
        Some(d) => d,
        None => return result,
    };

    let dir_data = match pe.rva_to_slice(export_dir.VirtualAddress, std::mem::size_of::<ImageExportDirectory>()) {
        Some(d) => d,
        None => return result,
    };

    let dir: &ImageExportDirectory = unsafe { &*(dir_data.as_ptr() as *const ImageExportDirectory) };

    // Read function RVA table
    let func_count = dir.NumberOfFunctions as usize;
    let func_table = match pe.rva_to_slice(dir.AddressOfFunctions, func_count * 4) {
        Some(d) => d,
        None => return result,
    };

    // Read name table and ordinal table
    let name_count = dir.NumberOfNames as usize;
    let name_table = pe.rva_to_slice(dir.AddressOfNames, name_count * 4);
    let ordinal_table = pe.rva_to_slice(dir.AddressOfNameOrdinals, name_count * 2);

    // Build name→ordinal mapping
    let mut ordinal_names: Vec<Option<&str>> = vec![None; func_count];
    if let (Some(names), Some(ordinals)) = (name_table, ordinal_table) {
        for i in 0..name_count {
            let name_rva = u32::from_le_bytes(names[i * 4..i * 4 + 4].try_into().unwrap());
            let ordinal_idx = u16::from_le_bytes(ordinals[i * 2..i * 2 + 2].try_into().unwrap()) as usize;
            if ordinal_idx < func_count {
                ordinal_names[ordinal_idx] = pe.read_string_at_rva(name_rva);
            }
        }
    }

    // Build export entries
    for i in 0..func_count {
        let rva = u32::from_le_bytes(func_table[i * 4..i * 4 + 4].try_into().unwrap());
        if rva == 0 {
            continue; // unused ordinal slot
        }

        result.push(ExportEntry {
            ordinal: (i as u16) + (dir.Base as u16),
            name: ordinal_names[i],
            rva,
        });
    }

    result
}

/// Find an export by name using binary search (matching Wine's behavior).
pub fn find_export_by_name<'a>(pe: &PeFile<'a>, target_name: &str) -> Option<u32> {
    let export_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    let dir_data = pe.rva_to_slice(export_dir.VirtualAddress, std::mem::size_of::<ImageExportDirectory>())?;
    let dir: &ImageExportDirectory = unsafe { &*(dir_data.as_ptr() as *const ImageExportDirectory) };

    let name_count = dir.NumberOfNames as usize;
    let name_table = pe.rva_to_slice(dir.AddressOfNames, name_count * 4)?;
    let ordinal_table = pe.rva_to_slice(dir.AddressOfNameOrdinals, name_count * 2)?;
    let func_table = pe.rva_to_slice(dir.AddressOfFunctions, dir.NumberOfFunctions as usize * 4)?;

    // Binary search on sorted name table
    let mut lo = 0usize;
    let mut hi = name_count;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let name_rva = u32::from_le_bytes(name_table[mid * 4..mid * 4 + 4].try_into().unwrap());
        let name = pe.read_string_at_rva(name_rva)?;

        match name.cmp(target_name) {
            std::cmp::Ordering::Equal => {
                let ordinal_idx = u16::from_le_bytes(
                    ordinal_table[mid * 2..mid * 2 + 2].try_into().unwrap(),
                ) as usize;
                let func_rva = u32::from_le_bytes(
                    func_table[ordinal_idx * 4..ordinal_idx * 4 + 4].try_into().unwrap(),
                );
                return Some(func_rva);
            }
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }

    None
}

/// Find an export by ordinal.
pub fn find_export_by_ordinal<'a>(pe: &PeFile<'a>, ordinal: u16) -> Option<u32> {
    let export_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_EXPORT)?;
    let dir_data = pe.rva_to_slice(export_dir.VirtualAddress, std::mem::size_of::<ImageExportDirectory>())?;
    let dir: &ImageExportDirectory = unsafe { &*(dir_data.as_ptr() as *const ImageExportDirectory) };

    let index = (ordinal as u32).checked_sub(dir.Base)? as usize;
    if index >= dir.NumberOfFunctions as usize {
        return None;
    }

    let func_table = pe.rva_to_slice(dir.AddressOfFunctions, dir.NumberOfFunctions as usize * 4)?;
    let rva = u32::from_le_bytes(func_table[index * 4..index * 4 + 4].try_into().unwrap());
    if rva == 0 { None } else { Some(rva) }
}
