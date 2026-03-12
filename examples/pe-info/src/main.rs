//! PE-info: Analyze Windows PE executables.
//!
//! Usage: pe-info <path-to-exe-or-dll>
//!
//! This demonstrates Winoxide's PE parser on real Windows binaries.

use winoxide_pe::parser::{PeFile, OptionalHeader};
use winoxide_pe::imports::{parse_imports, ImportFunction};
use winoxide_pe::exports::parse_exports;
use winoxide_exec::engine::Engine;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: pe-info <path-to-exe-or-dll>");
        std::process::exit(1);
    }

    let path = &args[1];
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading {}: {}", path, e);
            std::process::exit(1);
        }
    };

    let pe = match PeFile::parse(&data) {
        Ok(pe) => pe,
        Err(e) => {
            eprintln!("Error parsing PE: {}", e);
            std::process::exit(1);
        }
    };

    println!("=== PE File: {} ===", path);
    println!();

    // File header info
    let fh = pe.file_header;
    println!("[File Header]");
    println!("  Machine:              {:#06x} ({})", fh.Machine, machine_name(fh.Machine));
    println!("  Number of sections:   {}", fh.NumberOfSections);
    println!("  Timestamp:            {:#010x}", fh.TimeDateStamp);
    println!("  Characteristics:      {:#06x}{}", fh.Characteristics, characteristics_str(fh.Characteristics));
    println!();

    // Optional header
    match pe.optional_header {
        OptionalHeader::Pe32(oh) => {
            println!("[Optional Header — PE32]");
            println!("  Entry point:          {:#010x}", oh.AddressOfEntryPoint);
            println!("  Image base:           {:#010x}", oh.ImageBase);
            println!("  Section alignment:    {:#x}", oh.SectionAlignment);
            println!("  File alignment:       {:#x}", oh.FileAlignment);
            println!("  Image size:           {:#x} ({} KB)", oh.SizeOfImage, oh.SizeOfImage / 1024);
            println!("  Subsystem:            {} ({})", oh.Subsystem, subsystem_name(oh.Subsystem));
            println!("  DLL characteristics:  {:#06x}", oh.DllCharacteristics);
            println!("  Data directories:     {}", oh.NumberOfRvaAndSizes);
        }
        OptionalHeader::Pe64(oh) => {
            println!("[Optional Header — PE64]");
            println!("  Entry point:          {:#010x}", oh.AddressOfEntryPoint);
            println!("  Image base:           {:#018x}", oh.ImageBase);
            println!("  Section alignment:    {:#x}", oh.SectionAlignment);
            println!("  File alignment:       {:#x}", oh.FileAlignment);
            println!("  Image size:           {:#x} ({} KB)", oh.SizeOfImage, oh.SizeOfImage / 1024);
            println!("  Subsystem:            {} ({})", oh.Subsystem, subsystem_name(oh.Subsystem));
            println!("  DLL characteristics:  {:#06x}", oh.DllCharacteristics);
            println!("  Data directories:     {}", oh.NumberOfRvaAndSizes);
        }
    }
    println!();

    // Sections
    let sections = pe.sections;
    println!("[Sections] ({})", sections.len());
    println!("  {:<8} {:>10} {:>10} {:>10} {:>10}  Flags", "Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize");
    for s in sections {
        let name = std::str::from_utf8(&s.Name)
            .unwrap_or("?")
            .trim_end_matches('\0');
        println!(
            "  {:<8} {:#010x} {:#010x} {:#010x} {:#010x}  {}",
            name,
            s.VirtualAddress,
            s.VirtualSize,
            s.PointerToRawData,
            s.SizeOfRawData,
            section_flags_str(s.Characteristics),
        );
    }
    println!();

    // Imports
    let imports = parse_imports(&pe);
    if imports.is_empty() {
        println!("[Imports] None");
    } else {
        let total_funcs: usize = imports.iter().map(|i| i.functions.len()).sum();
        println!("[Imports] {} DLLs, {} functions", imports.len(), total_funcs);
        for imp in &imports {
            println!("  {} ({} functions)", imp.dll_name, imp.functions.len());
            for f in imp.functions.iter().take(8) {
                match f {
                    ImportFunction::ByName { hint, name } => {
                        println!("    - {} (hint: {})", name, hint);
                    }
                    ImportFunction::ByOrdinal(ord) => {
                        println!("    - ordinal #{}", ord);
                    }
                }
            }
            if imp.functions.len() > 8 {
                println!("    ... and {} more", imp.functions.len() - 8);
            }
        }
    }
    println!();

    // Exports
    let exports = parse_exports(&pe);
    if exports.is_empty() {
        println!("[Exports] None");
    } else {
        println!("[Exports] {} functions", exports.len());
        for exp in exports.iter().take(20) {
            if let Some(ref name) = exp.name {
                println!("  #{}: {} -> RVA {:#x}", exp.ordinal, name, exp.rva);
            } else {
                println!("  #{}: (by ordinal) -> RVA {:#x}", exp.ordinal, exp.rva);
            }
        }
        if exports.len() > 20 {
            println!("  ... and {} more", exports.len() - 20);
        }
    }

    // Winoxide execution analysis
    println!();
    let mut engine = Engine::new(path, vec![]);
    let data2 = std::fs::read(path).unwrap();
    match engine.load_pe(data2) {
        Ok(result) => {
            engine.print_diagnostics(&result);
        }
        Err(e) => {
            println!("[Engine] Load error: {}", e);
        }
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x0200 => "IA64",
        0x8664 => "x86-64",
        0xAA64 => "ARM64",
        _ => "Unknown",
    }
}

fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        10 => "EFI Application",
        _ => "Unknown",
    }
}

fn characteristics_str(c: u16) -> String {
    let mut flags = Vec::new();
    if c & 0x0002 != 0 { flags.push("EXECUTABLE"); }
    if c & 0x0020 != 0 { flags.push("LARGE_ADDRESS_AWARE"); }
    if c & 0x2000 != 0 { flags.push("DLL"); }
    if flags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", flags.join(", "))
    }
}

fn section_flags_str(c: u32) -> String {
    let mut flags = Vec::new();
    if c & 0x00000020 != 0 { flags.push("CODE"); }
    if c & 0x00000040 != 0 { flags.push("IDATA"); }
    if c & 0x00000080 != 0 { flags.push("UDATA"); }
    if c & 0x20000000 != 0 { flags.push("X"); }
    if c & 0x40000000 != 0 { flags.push("R"); }
    if c & 0x80000000 != 0 { flags.push("W"); }
    flags.join("|")
}
