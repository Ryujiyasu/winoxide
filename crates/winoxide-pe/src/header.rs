//! PE header structures — repr(C) for direct memory mapping.

#![allow(non_camel_case_types, non_snake_case)]

/// DOS header magic: "MZ"
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;
/// PE signature: "PE\0\0"
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550;

/// PE32 magic
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10b;
/// PE32+ (64-bit) magic
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;

/// Machine types
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014c;
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;

/// Characteristics
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Data directory indices
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;

/// Section characteristics
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32 = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32 = 0x80000000;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x00000020;
pub const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x00000040;
pub const IMAGE_SCN_CNT_UNINITIALIZED_DATA: u32 = 0x00000080;

/// Relocation types
pub const IMAGE_REL_BASED_ABSOLUTE: u16 = 0;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;

/// Import ordinal flag (64-bit)
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000000000000000;
/// Import ordinal flag (32-bit)
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x80000000;

// ============================================================
// Structures
// ============================================================

/// DOS header (64 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageDosHeader {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: u32, // offset 0x3C: pointer to PE signature
}

/// COFF file header (20 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageFileHeader {
    pub Machine: u16,
    pub NumberOfSections: u16,
    pub TimeDateStamp: u32,
    pub PointerToSymbolTable: u32,
    pub NumberOfSymbols: u32,
    pub SizeOfOptionalHeader: u16,
    pub Characteristics: u16,
}

/// Data directory entry.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageDataDirectory {
    pub VirtualAddress: u32,
    pub Size: u32,
}

/// Optional header (PE32+, 64-bit).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub ImageBase: u64,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u64,
    pub SizeOfStackCommit: u64,
    pub SizeOfHeapReserve: u64,
    pub SizeOfHeapCommit: u64,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; 16],
}

/// Optional header (PE32, 32-bit).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageOptionalHeader32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode: u32,
    pub BaseOfData: u32,
    pub ImageBase: u32,
    pub SectionAlignment: u32,
    pub FileAlignment: u32,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub MajorImageVersion: u16,
    pub MinorImageVersion: u16,
    pub MajorSubsystemVersion: u16,
    pub MinorSubsystemVersion: u16,
    pub Win32VersionValue: u32,
    pub SizeOfImage: u32,
    pub SizeOfHeaders: u32,
    pub CheckSum: u32,
    pub Subsystem: u16,
    pub DllCharacteristics: u16,
    pub SizeOfStackReserve: u32,
    pub SizeOfStackCommit: u32,
    pub SizeOfHeapReserve: u32,
    pub SizeOfHeapCommit: u32,
    pub LoaderFlags: u32,
    pub NumberOfRvaAndSizes: u32,
    pub DataDirectory: [ImageDataDirectory; 16],
}

/// Section header (40 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageSectionHeader {
    pub Name: [u8; 8],
    pub VirtualSize: u32,
    pub VirtualAddress: u32,
    pub SizeOfRawData: u32,
    pub PointerToRawData: u32,
    pub PointerToRelocations: u32,
    pub PointerToLinenumbers: u32,
    pub NumberOfRelocations: u16,
    pub NumberOfLinenumbers: u16,
    pub Characteristics: u32,
}

impl ImageSectionHeader {
    /// Get section name as a string (trimmed of null bytes).
    pub fn name(&self) -> &str {
        let end = self.Name.iter().position(|&b| b == 0).unwrap_or(8);
        std::str::from_utf8(&self.Name[..end]).unwrap_or("<invalid>")
    }
}

/// Import descriptor (20 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageImportDescriptor {
    pub OriginalFirstThunk: u32, // RVA to Import Lookup Table
    pub TimeDateStamp: u32,
    pub ForwarderChain: u32,
    pub Name: u32,           // RVA to DLL name
    pub FirstThunk: u32,     // RVA to Import Address Table
}

/// Export directory.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageExportDirectory {
    pub Characteristics: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub Name: u32,
    pub Base: u32,
    pub NumberOfFunctions: u32,
    pub NumberOfNames: u32,
    pub AddressOfFunctions: u32,
    pub AddressOfNames: u32,
    pub AddressOfNameOrdinals: u32,
}

/// Base relocation block header.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImageBaseRelocation {
    pub VirtualAddress: u32,
    pub SizeOfBlock: u32,
    // Followed by WORD[] entries: (type:4 | offset:12)
}
