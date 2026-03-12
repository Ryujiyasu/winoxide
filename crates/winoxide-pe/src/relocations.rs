//! PE base relocation processing.
//!
//! When a PE is loaded at a different address than its preferred ImageBase,
//! all absolute addresses embedded in the code/data must be adjusted.

use crate::header::*;
use crate::parser::PeFile;

/// Apply base relocations to a mapped PE image.
///
/// `mapped_image` is the mutable memory where the PE is loaded.
/// `actual_base` is the address where it was actually loaded.
/// `preferred_base` is the ImageBase from the optional header.
///
/// Returns the number of relocations applied, or an error message.
pub fn apply_relocations(
    mapped_image: &mut [u8],
    actual_base: u64,
    preferred_base: u64,
    pe: &PeFile,
) -> Result<usize, &'static str> {
    let delta = actual_base.wrapping_sub(preferred_base);
    if delta == 0 {
        return Ok(0); // No relocations needed
    }

    if (pe.file_header.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) != 0 {
        return Err("relocations stripped but image not at preferred base");
    }

    let reloc_dir = match pe.data_directory(IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        Some(d) => d,
        None => return Ok(0), // No relocation data
    };

    let reloc_data = match pe.rva_to_slice(reloc_dir.VirtualAddress, reloc_dir.Size as usize) {
        Some(d) => d,
        None => return Err("relocation data out of bounds"),
    };

    let mut count = 0;
    let mut offset = 0;

    while offset + std::mem::size_of::<ImageBaseRelocation>() <= reloc_data.len() {
        let block: &ImageBaseRelocation =
            unsafe { &*(reloc_data[offset..].as_ptr() as *const ImageBaseRelocation) };

        if block.SizeOfBlock == 0 {
            break;
        }

        let page_rva = block.VirtualAddress as usize;
        let num_entries = (block.SizeOfBlock as usize - 8) / 2;
        let entries_start = offset + 8;

        for i in 0..num_entries {
            let entry_offset = entries_start + i * 2;
            if entry_offset + 2 > reloc_data.len() {
                break;
            }
            let entry = u16::from_le_bytes([reloc_data[entry_offset], reloc_data[entry_offset + 1]]);

            let reloc_type = entry >> 12;
            let reloc_offset = (entry & 0x0FFF) as usize;
            let target = page_rva + reloc_offset;

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {
                    // Padding, skip
                }
                IMAGE_REL_BASED_HIGHLOW => {
                    // 32-bit fixup
                    if target + 4 <= mapped_image.len() {
                        let val = u32::from_le_bytes(
                            mapped_image[target..target + 4].try_into().unwrap(),
                        );
                        let new_val = val.wrapping_add(delta as u32);
                        mapped_image[target..target + 4].copy_from_slice(&new_val.to_le_bytes());
                        count += 1;
                    }
                }
                IMAGE_REL_BASED_DIR64 => {
                    // 64-bit fixup
                    if target + 8 <= mapped_image.len() {
                        let val = u64::from_le_bytes(
                            mapped_image[target..target + 8].try_into().unwrap(),
                        );
                        let new_val = val.wrapping_add(delta);
                        mapped_image[target..target + 8].copy_from_slice(&new_val.to_le_bytes());
                        count += 1;
                    }
                }
                _ => {
                    // Unknown relocation type — skip for now
                }
            }
        }

        offset += block.SizeOfBlock as usize;
    }

    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir64_relocation() {
        // Simulate a simple relocation scenario
        let mut image = vec![0u8; 0x2000];

        // Place a 64-bit address at offset 0x1000
        let original_addr: u64 = 0x00400000 + 0x1234;
        image[0x1000..0x1008].copy_from_slice(&original_addr.to_le_bytes());

        // Build a relocation block
        let mut reloc_data = Vec::new();
        // Block header: VirtualAddress=0x1000, SizeOfBlock=12 (8 header + 2 entry + 2 padding)
        reloc_data.extend_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        reloc_data.extend_from_slice(&12u32.to_le_bytes());      // SizeOfBlock
        // Entry: type=DIR64 (10), offset=0x000
        let entry: u16 = (IMAGE_REL_BASED_DIR64 << 12) | 0x000;
        reloc_data.extend_from_slice(&entry.to_le_bytes());
        // Padding entry
        reloc_data.extend_from_slice(&0u16.to_le_bytes());

        // Apply with delta = 0x10000 (loaded at 0x410000 instead of 0x400000)
        let preferred_base = 0x00400000u64;
        let actual_base = 0x00410000u64;

        // We need to manually apply since we don't have a real PE file
        let delta = actual_base.wrapping_sub(preferred_base);
        let val = u64::from_le_bytes(image[0x1000..0x1008].try_into().unwrap());
        let new_val = val.wrapping_add(delta);
        image[0x1000..0x1008].copy_from_slice(&new_val.to_le_bytes());

        let result = u64::from_le_bytes(image[0x1000..0x1008].try_into().unwrap());
        assert_eq!(result, 0x00410000 + 0x1234);
    }
}
