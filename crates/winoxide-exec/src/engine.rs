//! Execution engine — ties PE loading, API resolution, and runtime together.

use crate::api_table::{ApiTable, ImportCoverage};
use crate::vfs::VirtualFs;
use crate::process_env::ProcessEnv;
use winoxide_pe::parser::PeFile;
use winoxide_pe::imports::{parse_imports, ImportFunction};

/// The Winoxide execution engine.
#[derive(Debug)]
pub struct Engine {
    /// API dispatch table.
    pub api_table: ApiTable,
    /// Virtual filesystem.
    pub vfs: VirtualFs,
    /// Process environment.
    pub process: ProcessEnv,
    /// Loaded PE data (owned).
    pe_data: Option<Vec<u8>>,
    /// Engine state.
    state: EngineState,
}

/// Engine execution state.
#[derive(Debug, Clone, PartialEq)]
pub enum EngineState {
    /// Not yet loaded.
    Init,
    /// PE loaded and parsed.
    Loaded {
        is_64bit: bool,
        is_dll: bool,
        entry_point: u32,
        num_sections: usize,
    },
    /// Imports resolved, ready to execute.
    Ready,
    /// Currently executing.
    Running,
    /// Execution complete.
    Exited(u32),
    /// Error state.
    Error(String),
}

/// Result of loading a PE file.
#[derive(Debug)]
pub struct LoadResult {
    pub machine: &'static str,
    pub is_dll: bool,
    pub is_64bit: bool,
    pub entry_point: u32,
    pub image_size: u32,
    pub num_sections: usize,
    pub coverage: ImportCoverage,
}

impl Engine {
    /// Create a new execution engine.
    pub fn new(exe_path: &str, args: Vec<String>) -> Self {
        Self {
            api_table: ApiTable::new(),
            vfs: VirtualFs::new(),
            process: ProcessEnv::new(exe_path, args),
            pe_data: None,
            state: EngineState::Init,
        }
    }

    /// Create a sandboxed engine (for Wasm / security analysis).
    pub fn sandboxed(exe_path: &str, args: Vec<String>) -> Self {
        let mut engine = Self {
            api_table: ApiTable::new(),
            vfs: VirtualFs::sandbox(),
            process: ProcessEnv::new(exe_path, args),
            pe_data: None,
            state: EngineState::Init,
        };
        engine.api_table.set_logging(true);
        engine
    }

    /// Get current engine state.
    pub fn state(&self) -> &EngineState {
        &self.state
    }

    /// Load a PE file from bytes.
    pub fn load_pe(&mut self, data: Vec<u8>) -> Result<LoadResult, String> {
        // Parse PE
        let pe = PeFile::parse(&data).map_err(|e| format!("PE parse error: {}", e))?;

        let machine = match pe.file_header.Machine {
            0x014c => "x86",
            0x8664 => "x86-64",
            0xAA64 => "ARM64",
            _ => "unknown",
        };

        let is_64bit = pe.is_64bit();
        let is_dll = pe.is_dll();
        let entry_point = pe.optional_header.entry_point();
        let image_size = pe.optional_header.size_of_image();
        let num_sections = pe.sections.len();

        // Analyze import coverage
        let imports = parse_imports(&pe);
        let import_pairs: Vec<(String, Vec<String>)> = imports.iter().map(|imp| {
            let funcs: Vec<String> = imp.functions.iter().map(|f| {
                match f {
                    ImportFunction::ByName { name, .. } => name.to_string(),
                    ImportFunction::ByOrdinal(ord) => format!("ordinal#{}", ord),
                }
            }).collect();
            (imp.dll_name.to_string(), funcs)
        }).collect();

        let coverage = self.api_table.analyze_coverage(&import_pairs);

        self.state = EngineState::Loaded {
            is_64bit,
            is_dll,
            entry_point,
            num_sections,
        };

        self.pe_data = Some(data);

        Ok(LoadResult {
            machine,
            is_dll,
            is_64bit,
            entry_point,
            image_size,
            num_sections,
            coverage,
        })
    }

    /// Load a PE file from disk.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_file(&mut self, path: &str) -> Result<LoadResult, String> {
        let data = std::fs::read(path).map_err(|e| format!("read error: {}", e))?;
        self.load_pe(data)
    }

    /// Print a diagnostic summary of the loaded PE.
    pub fn print_diagnostics(&self, result: &LoadResult) {
        println!("╔══════════════════════════════════════════╗");
        println!("║       Winoxide Execution Engine          ║");
        println!("╠══════════════════════════════════════════╣");
        println!("║ Module:    {:<29}║", self.process.module_name);
        println!("║ Machine:   {:<29}║", result.machine);
        println!("║ Type:      {:<29}║",
            if result.is_dll { "DLL" } else { "EXE" });
        println!("║ Bitness:   {:<29}║",
            if result.is_64bit { "64-bit" } else { "32-bit" });
        println!("║ Entry:     {:<29}║", format!("{:#010x}", result.entry_point));
        println!("║ Size:      {:<29}║", format!("{} KB", result.image_size / 1024));
        println!("║ Sections:  {:<29}║", result.num_sections);
        println!("╠══════════════════════════════════════════╣");
        println!("║ API Coverage: {:<26.1}%║", result.coverage.percentage());
        println!("║ DLLs:      {}/{} resolved{:>17}║",
            result.coverage.resolved_dlls, result.coverage.total_dlls, "");
        println!("║ Functions: {}/{} resolved{:>16}║",
            result.coverage.resolved_functions, result.coverage.total_functions, "");

        if result.coverage.is_runnable() {
            println!("║ Status:    ✓ LIKELY RUNNABLE             ║");
        } else if result.coverage.percentage() >= 50.0 {
            println!("║ Status:    ~ PARTIAL (may crash)         ║");
        } else {
            println!("║ Status:    ✗ NOT YET SUPPORTED           ║");
        }
        println!("╚══════════════════════════════════════════╝");

        if !result.coverage.missing_dlls.is_empty() {
            println!("\nMissing DLLs:");
            for dll in &result.coverage.missing_dlls {
                println!("  ✗ {}", dll);
            }
        }

        if !result.coverage.missing_functions.is_empty() {
            let show = std::cmp::min(15, result.coverage.missing_functions.len());
            println!("\nMissing functions ({} total):", result.coverage.missing_functions.len());
            for func in &result.coverage.missing_functions[..show] {
                println!("  - {}", func);
            }
            if result.coverage.missing_functions.len() > show {
                println!("  ... and {} more", result.coverage.missing_functions.len() - show);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = Engine::new("test.exe", vec!["--flag".to_string()]);
        assert_eq!(*engine.state(), EngineState::Init);
        assert!(engine.api_table.has_dll("kernel32"));
        assert!(engine.vfs.file_exists("C:\\Windows\\"));
        assert_eq!(engine.process.command_line(), "test.exe --flag");
    }

    #[test]
    fn test_sandboxed_engine() {
        let engine = Engine::sandboxed("suspicious.exe", vec![]);
        assert!(!engine.vfs.file_exists("C:\\Windows\\"));
    }

    #[test]
    fn test_load_invalid_pe() {
        let mut engine = Engine::new("test.exe", vec![]);
        let result = engine.load_pe(vec![0; 64]);
        assert!(result.is_err());
    }

    /// Build a minimal PE64 for testing (same as winoxide-pe test).
    fn build_test_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 512];
        pe[0] = 0x4D; pe[1] = 0x5A;
        pe[0x3C] = 0x80;
        pe[0x80] = 0x50; pe[0x81] = 0x45;
        let fh = 0x84;
        pe[fh] = 0x64; pe[fh + 1] = 0x86; // AMD64
        pe[fh + 2] = 1; // 1 section
        pe[fh + 16] = 0xF0; pe[fh + 17] = 0x00; // SizeOfOptionalHeader
        pe[fh + 18] = 0x02; // EXECUTABLE
        let oh = 0x98;
        pe[oh] = 0x0b; pe[oh + 1] = 0x02; // PE32+
        pe[oh + 16] = 0x00; pe[oh + 17] = 0x10; // EntryPoint = 0x1000
        pe[oh + 24] = 0x00; pe[oh + 25] = 0x00; pe[oh + 26] = 0x40; // ImageBase = 0x400000
        pe[oh + 32] = 0x00; pe[oh + 33] = 0x10; // SectionAlignment
        pe[oh + 36] = 0x00; pe[oh + 37] = 0x02; // FileAlignment
        pe[oh + 56] = 0x00; pe[oh + 57] = 0x20; // SizeOfImage
        pe[oh + 60] = 0x00; pe[oh + 61] = 0x02; // SizeOfHeaders
        pe[oh + 108] = 16; // 16 data dirs
        let sh = 0x188;
        pe[sh..sh + 6].copy_from_slice(b".text\0");
        pe[sh + 8] = 0x00; pe[sh + 9] = 0x10;
        pe[sh + 12] = 0x00; pe[sh + 13] = 0x10;
        pe[sh + 16] = 0x00; pe[sh + 17] = 0x02;
        pe[sh + 20] = 0x00; pe[sh + 21] = 0x02;
        let chars: u32 = 0x60000020;
        pe[sh + 36..sh + 40].copy_from_slice(&chars.to_le_bytes());
        pe
    }

    #[test]
    fn test_load_pe() {
        let mut engine = Engine::new("test.exe", vec![]);
        let pe_data = build_test_pe();
        let result = engine.load_pe(pe_data).unwrap();

        assert_eq!(result.machine, "x86-64");
        assert!(!result.is_dll);
        assert!(result.is_64bit);
        assert_eq!(result.entry_point, 0x1000);
        assert!(matches!(engine.state(), EngineState::Loaded { .. }));
    }
}
