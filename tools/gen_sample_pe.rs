#!/usr/bin/env -S cargo +stable -Zscript
//! Generate sample PE executables for testing Winoxide.
//! Run: rustc tools/gen_sample_pe.rs -o /tmp/gen_pe && /tmp/gen_pe

use std::io::Write;

fn main() {
    generate_hello_exe();
    generate_suspicious_exe();
    generate_stealth_exe();
    generate_clean_dll();
    println!("Done! Generated 4 sample PE files in web/samples/");
}

/// Helper to write LE u16
fn w16(buf: &mut Vec<u8>, offset: usize, val: u16) {
    buf[offset..offset+2].copy_from_slice(&val.to_le_bytes());
}

/// Helper to write LE u32
fn w32(buf: &mut Vec<u8>, offset: usize, val: u32) {
    buf[offset..offset+4].copy_from_slice(&val.to_le_bytes());
}

/// Write a string at offset
fn wstr(buf: &mut Vec<u8>, offset: usize, s: &[u8]) {
    buf[offset..offset+s.len()].copy_from_slice(s);
}

/// Build a PE32 (x86) executable with given imports and sections.
fn build_pe32(
    sections: &[SectionDef],
    imports: &[ImportDef],
    entry_rva: u32,
    is_dll: bool,
    subsystem: u16,
) -> Vec<u8> {
    // Layout:
    // 0x000: DOS header (64 bytes) + DOS stub
    // 0x080: PE signature
    // 0x084: File header (20 bytes)
    // 0x098: Optional header PE32 (224 bytes = 28 standard + 68 windows + 128 data dirs)
    // 0x178: Section headers (40 bytes each)
    // 0x200+: Section data (aligned to 0x200)
    // Import data in .idata section

    let pe_offset: usize = 0x80;
    let fh_offset = pe_offset + 4;
    let oh_offset = fh_offset + 20;
    let oh_size: u16 = 224; // PE32 optional header
    let num_sections = sections.len() + if imports.is_empty() { 0 } else { 1 }; // +1 for .idata
    let sh_offset = oh_offset + oh_size as usize;
    let headers_end = sh_offset + num_sections * 40;
    let file_align: u32 = 0x200;
    let section_align: u32 = 0x1000;

    // Calculate aligned headers size
    let headers_size = align_up(headers_end as u32, file_align);

    // Build import data
    let (idata_raw, iat_entries) = if !imports.is_empty() {
        build_import_section(imports, section_align * (sections.len() as u32 + 1))
    } else {
        (vec![], vec![])
    };

    // Calculate total file size
    let mut file_size = headers_size;
    let mut section_vas: Vec<(u32, u32, u32)> = vec![]; // (va, raw_offset, raw_size)

    let mut next_va = section_align; // first section at 0x1000
    for sec in sections {
        let raw_size = align_up(sec.data.len() as u32, file_align);
        let va = next_va;
        let raw_offset = file_size;
        section_vas.push((va, raw_offset, raw_size));
        file_size += raw_size;
        next_va = align_up(va + sec.data.len().max(1) as u32, section_align);
    }

    // .idata section
    let idata_va;
    let idata_raw_offset;
    let idata_raw_size;
    if !imports.is_empty() {
        idata_va = next_va;
        idata_raw_offset = file_size;
        idata_raw_size = align_up(idata_raw.len() as u32, file_align);
        file_size += idata_raw_size;
        next_va = align_up(idata_va + idata_raw.len() as u32, section_align);
    } else {
        idata_va = 0;
        idata_raw_offset = 0;
        idata_raw_size = 0;
    }

    let image_size = align_up(next_va, section_align);
    let mut buf = vec![0u8; file_size as usize];

    // === DOS Header ===
    wstr(&mut buf, 0, b"MZ");
    w32(&mut buf, 0x3C, pe_offset as u32);

    // === PE Signature ===
    wstr(&mut buf, pe_offset, b"PE\0\0");

    // === File Header ===
    w16(&mut buf, fh_offset, 0x014C); // Machine = x86
    w16(&mut buf, fh_offset + 2, num_sections as u16);
    w32(&mut buf, fh_offset + 4, 0x65000000); // TimeDateStamp
    w16(&mut buf, fh_offset + 16, oh_size);
    let mut chars: u16 = 0x0102; // EXECUTABLE_IMAGE | 32BIT_MACHINE
    if is_dll { chars |= 0x2000; }
    w16(&mut buf, fh_offset + 18, chars);

    // === Optional Header (PE32) ===
    w16(&mut buf, oh_offset, 0x10B); // Magic = PE32
    buf[oh_offset + 2] = 14; // MajorLinkerVersion
    w32(&mut buf, oh_offset + 16, entry_rva); // AddressOfEntryPoint
    w32(&mut buf, oh_offset + 28, 0x00400000); // ImageBase
    w32(&mut buf, oh_offset + 32, section_align);
    w32(&mut buf, oh_offset + 36, file_align);
    w16(&mut buf, oh_offset + 40, 6); // MajorOSVersion
    w16(&mut buf, oh_offset + 44, 6); // MajorSubsysVersion
    w32(&mut buf, oh_offset + 56, image_size); // SizeOfImage
    w32(&mut buf, oh_offset + 60, headers_size); // SizeOfHeaders
    w16(&mut buf, oh_offset + 68, subsystem);
    w16(&mut buf, oh_offset + 70, 0x8160); // DllCharacteristics (DYNAMIC_BASE|NX_COMPAT|TERMINAL_SERVER_AWARE)
    w32(&mut buf, oh_offset + 72, 0x100000); // SizeOfStackReserve
    w32(&mut buf, oh_offset + 76, 0x1000); // SizeOfStackCommit
    w32(&mut buf, oh_offset + 80, 0x100000); // SizeOfHeapReserve
    w32(&mut buf, oh_offset + 84, 0x1000); // SizeOfHeapCommit
    w32(&mut buf, oh_offset + 92, 16); // NumberOfRvaAndSizes

    // Data directories (at oh+96)
    let dd_offset = oh_offset + 96;
    if !imports.is_empty() {
        // Import directory (index 1)
        w32(&mut buf, dd_offset + 8, idata_va); // RVA
        w32(&mut buf, dd_offset + 12, idata_raw.len() as u32); // Size
    }

    // === Section Headers ===
    for (i, sec) in sections.iter().enumerate() {
        let sh = sh_offset + i * 40;
        let (va, raw_off, raw_sz) = section_vas[i];
        let name_bytes = sec.name.as_bytes();
        buf[sh..sh + name_bytes.len().min(8)].copy_from_slice(&name_bytes[..name_bytes.len().min(8)]);
        w32(&mut buf, sh + 8, sec.data.len() as u32); // VirtualSize
        w32(&mut buf, sh + 12, va); // VirtualAddress
        w32(&mut buf, sh + 16, raw_sz); // SizeOfRawData
        w32(&mut buf, sh + 20, raw_off); // PointerToRawData
        w32(&mut buf, sh + 36, sec.characteristics);

        // Write section data
        let dst = raw_off as usize;
        buf[dst..dst + sec.data.len()].copy_from_slice(&sec.data);
    }

    // .idata section header
    if !imports.is_empty() {
        let sh = sh_offset + sections.len() * 40;
        wstr(&mut buf, sh, b".idata\0\0");
        w32(&mut buf, sh + 8, idata_raw.len() as u32);
        w32(&mut buf, sh + 12, idata_va);
        w32(&mut buf, sh + 16, idata_raw_size);
        w32(&mut buf, sh + 20, idata_raw_offset);
        w32(&mut buf, sh + 36, 0xC0000040); // READ|WRITE|INITIALIZED_DATA

        // Write .idata
        let dst = idata_raw_offset as usize;
        buf[dst..dst + idata_raw.len()].copy_from_slice(&idata_raw);
    }

    buf
}

struct SectionDef {
    name: String,
    data: Vec<u8>,
    characteristics: u32,
}

struct ImportDef {
    dll: String,
    functions: Vec<String>,
}

/// Build import section data. Returns (raw_data, iat_entries).
fn build_import_section(imports: &[ImportDef], base_va: u32) -> (Vec<u8>, Vec<(u32, String, String)>) {
    // Layout within .idata:
    // [Import descriptors] (20 bytes each + null terminator)
    // [ILT/IAT entries] (4 bytes each per function + null terminator per DLL)
    // [Hint/Name entries] (2-byte hint + null-terminated name)
    // [DLL name strings]

    let num_descs = imports.len();
    let desc_size = (num_descs + 1) * 20; // +1 for null terminator

    let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
    let ilt_size = (total_funcs + imports.len()) * 4; // +1 null term per DLL
    let iat_offset = desc_size + ilt_size;
    let iat_size = ilt_size; // same structure

    let mut hint_names: Vec<(usize, String)> = vec![]; // (offset_in_section, name)
    let mut dll_names: Vec<(usize, String)> = vec![];

    // Calculate hint/name area start
    let hn_start = iat_offset + iat_size;
    let mut hn_cursor = hn_start;

    for imp in imports {
        for func in &imp.functions {
            hint_names.push((hn_cursor, func.clone()));
            hn_cursor += 2 + func.len() + 1; // hint(2) + name + null
            if hn_cursor % 2 != 0 { hn_cursor += 1; } // align to 2
        }
        dll_names.push((hn_cursor, imp.dll.clone()));
        hn_cursor += imp.dll.len() + 1;
    }

    let section_size = hn_cursor;
    let mut data = vec![0u8; section_size];
    let mut iat_entries = vec![];

    // Write import descriptors and ILT/IAT
    let mut ilt_cursor = desc_size;
    let mut iat_cursor = iat_offset;
    let mut hn_idx = 0;

    for (i, imp) in imports.iter().enumerate() {
        let desc = i * 20;
        // OriginalFirstThunk (ILT RVA)
        let ilt_rva = base_va + ilt_cursor as u32;
        data[desc..desc+4].copy_from_slice(&ilt_rva.to_le_bytes());
        // TimeDateStamp = 0
        // ForwarderChain = 0
        // Name RVA
        let (dll_off, _) = dll_names[i];
        let dll_rva = base_va + dll_off as u32;
        data[desc+12..desc+16].copy_from_slice(&dll_rva.to_le_bytes());
        // FirstThunk (IAT RVA)
        let iat_rva = base_va + iat_cursor as u32;
        data[desc+16..desc+20].copy_from_slice(&iat_rva.to_le_bytes());

        for func in &imp.functions {
            let (hn_off, _) = hint_names[hn_idx];
            let hn_rva = base_va + hn_off as u32;

            // ILT entry
            data[ilt_cursor..ilt_cursor+4].copy_from_slice(&hn_rva.to_le_bytes());
            ilt_cursor += 4;

            // IAT entry (same as ILT before binding)
            data[iat_cursor..iat_cursor+4].copy_from_slice(&hn_rva.to_le_bytes());
            iat_entries.push((base_va + iat_cursor as u32, imp.dll.clone(), func.clone()));
            iat_cursor += 4;

            hn_idx += 1;
        }
        // Null terminator for ILT/IAT
        ilt_cursor += 4;
        iat_cursor += 4;
    }

    // Write hint/name entries
    for (off, name) in &hint_names {
        // hint = 0
        data[*off + 2..*off + 2 + name.len()].copy_from_slice(name.as_bytes());
    }

    // Write DLL name strings
    for (off, name) in &dll_names {
        data[*off..*off + name.len()].copy_from_slice(name.as_bytes());
    }

    (data, iat_entries)
}

fn align_up(val: u32, align: u32) -> u32 {
    (val + align - 1) & !(align - 1)
}

// ========== Sample PE generators ==========

/// hello.exe — simple console app that calls GetStdHandle, WriteConsoleA, ExitProcess
fn generate_hello_exe() {
    let msg = b"Hello from Winoxide!\r\n\0";
    let msg_offset = 0x20; // offset within .text for the message

    // x86 machine code for:
    //   push -11                 ; STD_OUTPUT_HANDLE
    //   call [IAT:GetStdHandle]  ; -> EAX = handle
    //   push 0                   ; lpReserved
    //   lea ecx, [written]       ; lpNumberOfCharsWritten
    //   push ecx
    //   push msg_len             ; nNumberOfCharsToWrite
    //   lea ecx, [msg]           ; lpBuffer
    //   push ecx
    //   push eax                 ; hConsole
    //   call [IAT:WriteConsoleA]
    //   push 0                   ; exit code
    //   call [IAT:ExitProcess]

    // We'll simplify: just PUSH args, CALL indirect through IAT, RET
    // IAT will be at .idata section, we reference it from code

    // For simplicity, build code that calls APIs through indirect CALL [mem32]
    // .idata section at VA 0x2000, IAT entries:
    //   0x2000+iat_off: GetStdHandle
    //   0x2000+iat_off+4: WriteConsoleA
    //   0x2000+iat_off+8: ExitProcess

    // Actually, let's build a simpler program:
    // Just push args and call ExitProcess(42)
    let mut code = Vec::new();

    // push 42
    code.push(0x6A); code.push(42);
    // call [0x00402000 + IAT_OFFSET] — we'll patch this
    // For now, use CALL rel32 to a RET (nop program)
    // Better: build actual IAT references

    // Simpler approach: minimal code that the emulator can trace
    code.clear();

    // sub esp, 16 (stack frame)
    code.extend_from_slice(&[0x83, 0xEC, 0x10]);
    // push -11 (STD_OUTPUT_HANDLE = 0xFFFFFFF5)
    code.extend_from_slice(&[0x6A, 0xF5]);
    // call [GetStdHandle IAT] — FF 15 [addr32]
    // IAT for GetStdHandle will be at a known address, filled later
    code.extend_from_slice(&[0xFF, 0x15]);
    let get_std_handle_fixup = code.len();
    code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // push 0 (exit code)
    code.extend_from_slice(&[0x6A, 0x00]);
    // call [ExitProcess IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let exit_process_fixup = code.len();
    code.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder

    // add esp, 16; ret (cleanup)
    code.extend_from_slice(&[0x83, 0xC4, 0x10, 0xC3]);

    // Pad to include message
    while code.len() < msg_offset {
        code.push(0x90); // NOP
    }
    code.extend_from_slice(msg);

    let imports = vec![
        ImportDef {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                "GetStdHandle".into(),
                "WriteConsoleA".into(),
                "ExitProcess".into(),
            ],
        },
    ];

    let pe = build_pe32(
        &[SectionDef {
            name: ".text".into(),
            data: code,
            characteristics: 0x60000020, // CODE|EXECUTE|READ
        }],
        &imports,
        0x1000, // entry at .text start
        false,
        3, // WINDOWS_CUI
    );

    // Fix up IAT addresses in code
    // The .idata section is at VA 0x2000
    // Import descriptor layout: ILT at desc_size, IAT at desc_size + ilt_size
    // For 1 DLL with 3 functions: desc_size = 40, ilt_size = 16, iat_offset = 56
    // IAT entries: GetStdHandle@56, WriteConsoleA@60, ExitProcess@64
    // IAT VA = 0x2000 + 56
    let idata_va = 0x2000u32;
    let desc_size = 40u32; // 2 descriptors (1 + null) * 20
    let ilt_size = 16u32; // 3 entries + null * 4
    let iat_start = idata_va + desc_size + ilt_size;

    let mut pe = pe;
    // Patch GetStdHandle IAT address (ImageBase 0x400000 + iat_start)
    let abs_iat = 0x00400000 + iat_start;
    pe[0x200 + get_std_handle_fixup..0x200 + get_std_handle_fixup + 4]
        .copy_from_slice(&abs_iat.to_le_bytes());
    // Patch ExitProcess IAT address (3rd entry = iat_start + 8)
    let abs_exit = 0x00400000 + iat_start + 8;
    pe[0x200 + exit_process_fixup..0x200 + exit_process_fixup + 4]
        .copy_from_slice(&abs_exit.to_le_bytes());

    std::fs::create_dir_all("web/samples").unwrap();
    let mut f = std::fs::File::create("web/samples/hello.exe").unwrap();
    f.write_all(&pe).unwrap();
    println!("  [+] hello.exe ({} bytes) - Console app: GetStdHandle, WriteConsoleA, ExitProcess", pe.len());
}

/// suspicious.exe — imports process injection + network + anti-debug APIs
fn generate_suspicious_exe() {
    // Minimal code: just call a bunch of suspicious APIs
    let mut code = Vec::new();
    // push ebp; mov ebp, esp
    code.extend_from_slice(&[0x55, 0x89, 0xE5]);
    // sub esp, 32
    code.extend_from_slice(&[0x83, 0xEC, 0x20]);
    // xor eax, eax
    code.extend_from_slice(&[0x31, 0xC0]);
    // Various CALL [IAT] stubs — we won't fix up addresses perfectly
    // but the static analyzer will still see the imports
    // Just make the code do: call IsDebuggerPresent; push 0; call ExitProcess
    // call [IsDebuggerPresent]
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&[0x00, 0x30, 0x40, 0x00]); // placeholder IAT addr
    // push 0
    code.extend_from_slice(&[0x6A, 0x00]);
    // call [ExitProcess]
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&[0x00, 0x30, 0x40, 0x00]); // placeholder
    // leave; ret
    code.extend_from_slice(&[0xC9, 0xC3]);

    let imports = vec![
        ImportDef {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                "VirtualAllocEx".into(),
                "WriteProcessMemory".into(),
                "CreateRemoteThread".into(),
                "OpenProcess".into(),
                "IsDebuggerPresent".into(),
                "GetModuleHandleA".into(),
                "GetProcAddress".into(),
                "LoadLibraryA".into(),
                "VirtualAlloc".into(),
                "VirtualProtect".into(),
                "ExitProcess".into(),
                "Sleep".into(),
                "CreateFileA".into(),
                "WriteFile".into(),
                "CloseHandle".into(),
            ],
        },
        ImportDef {
            dll: "WS2_32.dll".into(),
            functions: vec![
                "WSAStartup".into(),
                "socket".into(),
                "connect".into(),
                "send".into(),
                "recv".into(),
                "closesocket".into(),
            ],
        },
        ImportDef {
            dll: "ADVAPI32.dll".into(),
            functions: vec![
                "RegOpenKeyExA".into(),
                "RegSetValueExA".into(),
                "RegCloseKey".into(),
                "CryptEncrypt".into(),
                "CryptDecrypt".into(),
                "CryptGenKey".into(),
            ],
        },
    ];

    let pe = build_pe32(
        &[SectionDef {
            name: ".text".into(),
            data: code,
            characteristics: 0x60000020,
        },
        SectionDef {
            name: ".wxdata".into(), // suspicious W+X section
            data: vec![0xCC; 256], // INT3 padding
            characteristics: 0xE0000020, // CODE|EXECUTE|READ|WRITE
        }],
        &imports,
        0x1000,
        false,
        3,
    );

    let mut f = std::fs::File::create("web/samples/suspicious.exe").unwrap();
    f.write_all(&pe).unwrap();
    println!("  [+] suspicious.exe ({} bytes) - Process injection + network + crypto + W^X section", pe.len());
}

/// stealth.exe — looks benign statically (MEDIUM ~25) but triggers dynamic behavioral flags (HIGH ~65)
/// Imports are individually innocent but combine to reveal suspicious behavior during emulation.
fn generate_stealth_exe() {
    let mut code = Vec::new();

    // push ebp; mov ebp, esp; sub esp, 64
    code.extend_from_slice(&[0x55, 0x89, 0xE5, 0x83, 0xEC, 0x40]);

    // --- Call OutputDebugStringA (anti-debug pattern) ---
    // lea eax, [ebp-16] ; dummy string pointer
    code.extend_from_slice(&[0x8D, 0x45, 0xF0]);
    // push eax
    code.push(0x50);
    // call [OutputDebugStringA IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_output_debug = code.len();
    code.extend_from_slice(&[0x00; 4]); // placeholder

    // --- Call LoadLibraryA + GetProcAddress (dynamic API resolution) ---
    // push 0 (dummy arg)
    code.extend_from_slice(&[0x6A, 0x00]);
    // call [LoadLibraryA IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_loadlib = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // push eax; push 0
    code.extend_from_slice(&[0x50, 0x6A, 0x00]);
    // call [GetProcAddress IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_getproc = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // --- Call WSAStartup (network activity) ---
    // push 0; push 0x0202 (version 2.2)
    code.extend_from_slice(&[0x6A, 0x00, 0x68, 0x02, 0x02, 0x00, 0x00]);
    // call [WSAStartup IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_wsa = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // --- Call CreateFileA + WriteFile (file operations) ---
    // push multiple args for CreateFileA (7 args)
    for _ in 0..7 { code.extend_from_slice(&[0x6A, 0x00]); }
    // call [CreateFileA IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_createfile = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // push args for WriteFile (5 args)
    for _ in 0..5 { code.extend_from_slice(&[0x6A, 0x00]); }
    // call [WriteFile IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_writefile = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // --- Call RegOpenKeyExA + RegQueryValueExA (registry operations) ---
    // push args for RegOpenKeyExA (5 args)
    for _ in 0..5 { code.extend_from_slice(&[0x6A, 0x00]); }
    // call [RegOpenKeyExA IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_regopen = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // push args for RegQueryValueExA (6 args)
    for _ in 0..6 { code.extend_from_slice(&[0x6A, 0x00]); }
    // call [RegQueryValueExA IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_regquery = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // --- Call ExitProcess(0) ---
    code.extend_from_slice(&[0x6A, 0x00]);
    // call [ExitProcess IAT]
    code.extend_from_slice(&[0xFF, 0x15]);
    let fixup_exit = code.len();
    code.extend_from_slice(&[0x00; 4]);

    // leave; ret
    code.extend_from_slice(&[0xC9, 0xC3]);

    let imports = vec![
        ImportDef {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                "GetStdHandle".into(),
                "WriteConsoleA".into(),
                "ExitProcess".into(),
                "VirtualAlloc".into(),
                "VirtualProtect".into(),
                "GetProcAddress".into(),
                "LoadLibraryA".into(),
                "CreateFileA".into(),
                "WriteFile".into(),
                "CloseHandle".into(),
                "OutputDebugStringA".into(),
                "Sleep".into(),
            ],
        },
        ImportDef {
            dll: "WS2_32.dll".into(),
            functions: vec![
                "WSAStartup".into(),
            ],
        },
        ImportDef {
            dll: "ADVAPI32.dll".into(),
            functions: vec![
                "RegOpenKeyExA".into(),
                "RegQueryValueExA".into(),
                "RegCloseKey".into(),
            ],
        },
    ];

    let pe = build_pe32(
        &[SectionDef {
            name: ".text".into(),
            data: code.clone(),
            characteristics: 0x60000020, // CODE|EXECUTE|READ (normal, no W+X)
        },
        SectionDef {
            name: ".data".into(),
            data: vec![0; 128],
            characteristics: 0xC0000040, // INITIALIZED_DATA|READ|WRITE (normal)
        }],
        &imports,
        0x1000,
        false,
        3, // WINDOWS_CUI
    );

    // Fix up IAT addresses in the code
    // .idata section at VA 0x3000 (after .text@0x1000, .data@0x2000)
    // 4 descriptors (3 DLLs + null) = 80 bytes
    // ILT: 12+1+3+1+3+1 = 21 entries * 4 = 84 bytes (with null terminators: 13+2+4 = 19 terms, but let's calc properly)
    // kernel32: 12 funcs + 1 null = 52 bytes ILT
    // ws2_32: 1 func + 1 null = 8 bytes ILT
    // advapi32: 3 funcs + 1 null = 16 bytes ILT
    // Total ILT: 76 bytes
    // IAT starts at: 80 (descs) + 76 (ILT) = 156
    let idata_va: u32 = 0x3000;
    let desc_size: u32 = 80; // 4 descriptors * 20
    let ilt_size: u32 = 76; // (12+1 + 1+1 + 3+1) * 4
    let iat_start = idata_va + desc_size + ilt_size;
    let image_base: u32 = 0x00400000;

    // IAT layout:
    // kernel32 functions (12): indices 0-11
    //   0: GetStdHandle, 1: WriteConsoleA, 2: ExitProcess, 3: VirtualAlloc,
    //   4: VirtualProtect, 5: GetProcAddress, 6: LoadLibraryA, 7: CreateFileA,
    //   8: WriteFile, 9: CloseHandle, 10: OutputDebugStringA, 11: Sleep
    // [null terminator]
    // ws2_32 functions (1): index 13
    //   13: WSAStartup
    // [null terminator]
    // advapi32 functions (3): indices 15-17
    //   15: RegOpenKeyExA, 16: RegQueryValueExA, 17: RegCloseKey

    let mut pe = pe;
    let code_file_offset = 0x200; // .text raw data starts at file offset 0x200

    let iat_addr = |idx: u32| -> u32 { image_base + iat_start + idx * 4 };

    let fixups: Vec<(usize, u32)> = vec![
        (fixup_output_debug, iat_addr(10)),  // OutputDebugStringA
        (fixup_loadlib, iat_addr(6)),         // LoadLibraryA
        (fixup_getproc, iat_addr(5)),         // GetProcAddress
        (fixup_wsa, iat_addr(13)),            // WSAStartup (after kernel32's 12 + null)
        (fixup_createfile, iat_addr(7)),      // CreateFileA
        (fixup_writefile, iat_addr(8)),       // WriteFile
        (fixup_regopen, iat_addr(15)),        // RegOpenKeyExA (after ws2_32's 1 + null)
        (fixup_regquery, iat_addr(16)),       // RegQueryValueExA
        (fixup_exit, iat_addr(2)),            // ExitProcess
    ];

    for (offset, addr) in fixups {
        pe[code_file_offset + offset..code_file_offset + offset + 4]
            .copy_from_slice(&addr.to_le_bytes());
    }

    std::fs::create_dir_all("web/samples").unwrap();
    let mut f = std::fs::File::create("web/samples/stealth.exe").unwrap();
    f.write_all(&pe).unwrap();
    println!("  [+] stealth.exe ({} bytes) - Looks benign statically, triggers behavioral flags dynamically", pe.len());
}

/// clean.dll — a normal DLL with benign exports
fn generate_clean_dll() {
    // DLL with a few exports and clean imports
    let mut code = Vec::new();
    // DllMain: mov eax, 1; ret 12
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xC2, 0x0C, 0x00]); // ret 12

    // Export: DoSomething at offset 8
    code.extend_from_slice(&[0x31, 0xC0]); // xor eax, eax
    code.extend_from_slice(&[0xC3]); // ret

    // Export: GetVersion at offset 11
    code.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // mov eax, 1
    code.extend_from_slice(&[0xC3]); // ret

    let imports = vec![
        ImportDef {
            dll: "KERNEL32.dll".into(),
            functions: vec![
                "GetModuleHandleA".into(),
                "GetLastError".into(),
                "HeapAlloc".into(),
                "HeapFree".into(),
                "GetProcessHeap".into(),
            ],
        },
        ImportDef {
            dll: "msvcrt.dll".into(),
            functions: vec![
                "malloc".into(),
                "free".into(),
                "memcpy".into(),
                "strlen".into(),
            ],
        },
    ];

    let pe = build_pe32(
        &[SectionDef {
            name: ".text".into(),
            data: code,
            characteristics: 0x60000020,
        },
        SectionDef {
            name: ".data".into(),
            data: vec![0; 64],
            characteristics: 0xC0000040, // INITIALIZED_DATA|READ|WRITE
        }],
        &imports,
        0x1000,
        true, // DLL
        3,
    );

    let mut f = std::fs::File::create("web/samples/clean.dll").unwrap();
    f.write_all(&pe).unwrap();
    println!("  [+] clean.dll ({} bytes) - Benign DLL with memory management imports", pe.len());
}
