//! PE file parser — reads and validates PE headers from raw bytes.

use crate::header::*;
use std::fmt;

/// Parsed PE file (zero-copy — borrows the input data).
#[derive(Debug)]
pub struct PeFile<'a> {
    data: &'a [u8],
    pub dos_header: &'a ImageDosHeader,
    pub file_header: &'a ImageFileHeader,
    pub optional_header: OptionalHeader<'a>,
    pub sections: &'a [ImageSectionHeader],
}

/// Optional header can be 32-bit or 64-bit.
#[derive(Debug, Clone, Copy)]
pub enum OptionalHeader<'a> {
    Pe32(&'a ImageOptionalHeader32),
    Pe64(&'a ImageOptionalHeader64),
}

impl<'a> OptionalHeader<'a> {
    pub fn image_base(&self) -> u64 {
        match self {
            Self::Pe32(h) => h.ImageBase as u64,
            Self::Pe64(h) => h.ImageBase,
        }
    }

    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.SizeOfImage,
            Self::Pe64(h) => h.SizeOfImage,
        }
    }

    pub fn size_of_headers(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.SizeOfHeaders,
            Self::Pe64(h) => h.SizeOfHeaders,
        }
    }

    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.SectionAlignment,
            Self::Pe64(h) => h.SectionAlignment,
        }
    }

    pub fn entry_point(&self) -> u32 {
        match self {
            Self::Pe32(h) => h.AddressOfEntryPoint,
            Self::Pe64(h) => h.AddressOfEntryPoint,
        }
    }

    pub fn data_directory(&self) -> &[ImageDataDirectory] {
        match self {
            Self::Pe32(h) => &h.DataDirectory[..h.NumberOfRvaAndSizes as usize],
            Self::Pe64(h) => &h.DataDirectory[..h.NumberOfRvaAndSizes as usize],
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, Self::Pe64(_))
    }
}

/// PE parsing error.
#[derive(Debug)]
pub enum PeError {
    TooSmall,
    InvalidDosSignature,
    InvalidPeSignature,
    InvalidOptionalHeaderMagic(u16),
    InvalidSectionCount,
    OffsetOutOfBounds,
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall => write!(f, "file too small for PE headers"),
            Self::InvalidDosSignature => write!(f, "invalid DOS signature (expected MZ)"),
            Self::InvalidPeSignature => write!(f, "invalid PE signature (expected PE\\0\\0)"),
            Self::InvalidOptionalHeaderMagic(m) => write!(f, "invalid optional header magic: 0x{m:04x}"),
            Self::InvalidSectionCount => write!(f, "invalid section count"),
            Self::OffsetOutOfBounds => write!(f, "offset out of bounds"),
        }
    }
}

impl std::error::Error for PeError {}

impl<'a> PeFile<'a> {
    /// Parse a PE file from raw bytes.
    pub fn parse(data: &'a [u8]) -> Result<Self, PeError> {
        if data.len() < std::mem::size_of::<ImageDosHeader>() {
            return Err(PeError::TooSmall);
        }

        // DOS header
        let dos_header: &ImageDosHeader = unsafe { &*(data.as_ptr() as *const ImageDosHeader) };
        if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
            return Err(PeError::InvalidDosSignature);
        }

        let pe_offset = dos_header.e_lfanew as usize;
        if pe_offset + 4 > data.len() {
            return Err(PeError::OffsetOutOfBounds);
        }

        // PE signature
        let pe_sig = u32::from_le_bytes([
            data[pe_offset],
            data[pe_offset + 1],
            data[pe_offset + 2],
            data[pe_offset + 3],
        ]);
        if pe_sig != IMAGE_NT_SIGNATURE {
            return Err(PeError::InvalidPeSignature);
        }

        // File header
        let fh_offset = pe_offset + 4;
        if fh_offset + std::mem::size_of::<ImageFileHeader>() > data.len() {
            return Err(PeError::TooSmall);
        }
        let file_header: &ImageFileHeader =
            unsafe { &*(data[fh_offset..].as_ptr() as *const ImageFileHeader) };

        // Optional header
        let oh_offset = fh_offset + std::mem::size_of::<ImageFileHeader>();
        if oh_offset + 2 > data.len() {
            return Err(PeError::TooSmall);
        }
        let magic = u16::from_le_bytes([data[oh_offset], data[oh_offset + 1]]);

        let optional_header = match magic {
            IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                if oh_offset + std::mem::size_of::<ImageOptionalHeader64>() > data.len() {
                    return Err(PeError::TooSmall);
                }
                let oh: &ImageOptionalHeader64 =
                    unsafe { &*(data[oh_offset..].as_ptr() as *const ImageOptionalHeader64) };
                OptionalHeader::Pe64(oh)
            }
            IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                if oh_offset + std::mem::size_of::<ImageOptionalHeader32>() > data.len() {
                    return Err(PeError::TooSmall);
                }
                let oh: &ImageOptionalHeader32 =
                    unsafe { &*(data[oh_offset..].as_ptr() as *const ImageOptionalHeader32) };
                OptionalHeader::Pe32(oh)
            }
            other => return Err(PeError::InvalidOptionalHeaderMagic(other)),
        };

        // Section headers (immediately after optional header)
        let sections_offset = oh_offset + file_header.SizeOfOptionalHeader as usize;
        let num_sections = file_header.NumberOfSections as usize;
        let sections_size = num_sections * std::mem::size_of::<ImageSectionHeader>();

        if sections_offset + sections_size > data.len() {
            return Err(PeError::InvalidSectionCount);
        }

        let sections: &[ImageSectionHeader] = unsafe {
            std::slice::from_raw_parts(
                data[sections_offset..].as_ptr() as *const ImageSectionHeader,
                num_sections,
            )
        };

        Ok(PeFile {
            data,
            dos_header,
            file_header,
            optional_header,
            sections,
        })
    }

    /// Get the raw file data.
    pub fn raw_data(&self) -> &[u8] {
        self.data
    }

    /// Is this a DLL?
    pub fn is_dll(&self) -> bool {
        (self.file_header.Characteristics & IMAGE_FILE_DLL) != 0
    }

    /// Is this a 64-bit PE?
    pub fn is_64bit(&self) -> bool {
        self.optional_header.is_64bit()
    }

    /// Get the machine type.
    pub fn machine(&self) -> u16 {
        self.file_header.Machine
    }

    /// Resolve an RVA to file data.
    pub fn rva_to_slice(&self, rva: u32, size: usize) -> Option<&'a [u8]> {
        // Check if RVA falls within a section
        for section in self.sections {
            let sec_start = section.VirtualAddress;
            let sec_end = sec_start + section.SizeOfRawData;
            if rva >= sec_start && rva < sec_end {
                let file_offset = section.PointerToRawData + (rva - sec_start);
                let start = file_offset as usize;
                let end = start + size;
                if end <= self.data.len() {
                    return Some(&self.data[start..end]);
                }
            }
        }
        None
    }

    /// Read a null-terminated ASCII string at the given RVA.
    pub fn read_string_at_rva(&self, rva: u32) -> Option<&'a str> {
        for section in self.sections {
            let sec_start = section.VirtualAddress;
            let sec_end = sec_start + section.SizeOfRawData;
            if rva >= sec_start && rva < sec_end {
                let file_offset = (section.PointerToRawData + (rva - sec_start)) as usize;
                if file_offset >= self.data.len() {
                    return None;
                }
                let remaining = &self.data[file_offset..];
                let len = remaining.iter().position(|&b| b == 0)?;
                return std::str::from_utf8(&remaining[..len]).ok();
            }
        }
        None
    }

    /// Get a data directory entry.
    pub fn data_directory(&self, index: usize) -> Option<&ImageDataDirectory> {
        let dirs = self.optional_header.data_directory();
        dirs.get(index).filter(|d| d.VirtualAddress != 0 && d.Size != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PE64 file in memory.
    fn build_minimal_pe64() -> Vec<u8> {
        let mut pe = vec![0u8; 512];

        // DOS header
        pe[0] = 0x4D; // 'M'
        pe[1] = 0x5A; // 'Z'
        // e_lfanew at offset 0x3C
        pe[0x3C] = 0x80; // PE headers at offset 0x80

        // PE signature at 0x80
        pe[0x80] = 0x50; // 'P'
        pe[0x81] = 0x45; // 'E'

        // File header at 0x84
        let fh_offset = 0x84;
        pe[fh_offset] = 0x64; pe[fh_offset + 1] = 0x86; // Machine = AMD64
        pe[fh_offset + 2] = 1; // NumberOfSections = 1
        pe[fh_offset + 16] = 0xF0; pe[fh_offset + 17] = 0x00; // SizeOfOptionalHeader = 240
        pe[fh_offset + 18] = 0x02; pe[fh_offset + 19] = 0x20; // Characteristics = EXECUTABLE_IMAGE(0x0002) | DLL(0x2000)

        // Optional header at 0x98
        let oh_offset = 0x98;
        pe[oh_offset] = 0x0b; pe[oh_offset + 1] = 0x02; // Magic = PE32+ (0x20b)

        // AddressOfEntryPoint at oh+16
        pe[oh_offset + 16] = 0x00; pe[oh_offset + 17] = 0x10; // EntryPoint = 0x1000

        // ImageBase at oh+24 (u64)
        pe[oh_offset + 24] = 0x00; pe[oh_offset + 25] = 0x00;
        pe[oh_offset + 26] = 0x40; pe[oh_offset + 27] = 0x00; // ImageBase = 0x00400000

        // SectionAlignment at oh+32
        pe[oh_offset + 32] = 0x00; pe[oh_offset + 33] = 0x10; // SectionAlignment = 0x1000

        // FileAlignment at oh+36
        pe[oh_offset + 36] = 0x00; pe[oh_offset + 37] = 0x02; // FileAlignment = 0x200

        // SizeOfImage at oh+56
        pe[oh_offset + 56] = 0x00; pe[oh_offset + 57] = 0x20; // SizeOfImage = 0x2000

        // SizeOfHeaders at oh+60
        pe[oh_offset + 60] = 0x00; pe[oh_offset + 61] = 0x02; // SizeOfHeaders = 0x200

        // NumberOfRvaAndSizes at oh+108
        pe[oh_offset + 108] = 16; // 16 data directories

        // Section header starts at oh + 240 = 0x98 + 0xF0 = 0x188
        let sh_offset = 0x188;
        pe[sh_offset..sh_offset + 6].copy_from_slice(b".text\0");
        // VirtualSize at +8
        pe[sh_offset + 8] = 0x00; pe[sh_offset + 9] = 0x10; // 0x1000
        // VirtualAddress at +12
        pe[sh_offset + 12] = 0x00; pe[sh_offset + 13] = 0x10; // 0x1000
        // SizeOfRawData at +16
        pe[sh_offset + 16] = 0x00; pe[sh_offset + 17] = 0x02; // 0x200
        // PointerToRawData at +20
        pe[sh_offset + 20] = 0x00; pe[sh_offset + 21] = 0x02; // 0x200
        // Characteristics at +36
        let chars = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE;
        pe[sh_offset + 36..sh_offset + 40].copy_from_slice(&chars.to_le_bytes());

        pe
    }

    #[test]
    fn test_parse_minimal_pe64() {
        let data = build_minimal_pe64();
        let pe = PeFile::parse(&data).unwrap();

        assert!(pe.is_64bit());
        assert!(pe.is_dll());
        assert_eq!(pe.machine(), IMAGE_FILE_MACHINE_AMD64);
        assert_eq!(pe.optional_header.image_base(), 0x00400000);
        assert_eq!(pe.optional_header.entry_point(), 0x1000);
        assert_eq!(pe.optional_header.size_of_image(), 0x2000);
        assert_eq!(pe.sections.len(), 1);
        assert_eq!(pe.sections[0].name(), ".text");
    }

    #[test]
    fn test_invalid_dos_signature() {
        let data = vec![0u8; 256];
        assert!(matches!(PeFile::parse(&data), Err(PeError::InvalidDosSignature)));
    }

    #[test]
    fn test_too_small() {
        let data = vec![0u8; 2];
        assert!(matches!(PeFile::parse(&data), Err(PeError::TooSmall)));
    }
}
