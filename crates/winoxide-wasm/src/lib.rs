//! WebAssembly bindings for Winoxide — PE analysis in the browser.

use wasm_bindgen::prelude::*;
use serde::Serialize;

use winoxide_pe::parser::PeFile;
use winoxide_pe::imports::{parse_imports, ImportFunction};
use winoxide_pe::exports::parse_exports;
use std::collections::HashSet;

/// Analyze a PE file and return JSON results.
#[wasm_bindgen]
pub fn analyze_pe(data: &[u8]) -> String {
    let result = analyze_pe_inner(data);
    serde_json::to_string_pretty(&result).unwrap_or_else(|_| "{}".to_string())
}

fn analyze_pe_inner(data: &[u8]) -> PeAnalysis {
    let pe = match PeFile::parse(data) {
        Ok(pe) => pe,
        Err(e) => {
            return PeAnalysis {
                valid: false,
                error: Some(format!("{}", e)),
                ..Default::default()
            };
        }
    };

    let machine = match pe.file_header.Machine {
        0x014c => "x86",
        0x8664 => "x86-64",
        0xAA64 => "ARM64",
        _ => "unknown",
    };

    let subsystem = match pe.optional_header {
        winoxide_pe::parser::OptionalHeader::Pe32(oh) => oh.Subsystem,
        winoxide_pe::parser::OptionalHeader::Pe64(oh) => oh.Subsystem,
    };

    let subsystem_name = match subsystem {
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI (Console)",
        _ => "Unknown",
    };

    // Parse sections
    let sections: Vec<SectionInfo> = pe.sections.iter().map(|s| {
        let name = std::str::from_utf8(&s.Name)
            .unwrap_or("?")
            .trim_end_matches('\0')
            .to_string();
        let mut flags = Vec::new();
        if s.Characteristics & 0x20000000 != 0 { flags.push("EXECUTE"); }
        if s.Characteristics & 0x40000000 != 0 { flags.push("READ"); }
        if s.Characteristics & 0x80000000 != 0 { flags.push("WRITE"); }
        if s.Characteristics & 0x00000020 != 0 { flags.push("CODE"); }

        let suspicious = is_section_suspicious(&name, s.Characteristics);
        SectionInfo {
            name,
            virtual_size: s.VirtualSize,
            virtual_address: s.VirtualAddress,
            raw_size: s.SizeOfRawData,
            flags: flags.join(", "),
            suspicious,
        }
    }).collect();

    // Parse imports
    let raw_imports = parse_imports(&pe);
    let mut import_list = Vec::new();
    let mut import_pairs = Vec::new();
    let mut suspicious_imports = Vec::new();

    for imp in &raw_imports {
        let funcs: Vec<String> = imp.functions.iter().map(|f| {
            match f {
                ImportFunction::ByName { name, .. } => name.to_string(),
                ImportFunction::ByOrdinal(ord) => format!("ordinal#{}", ord),
            }
        }).collect();

        // Check for suspicious imports
        for func_name in &funcs {
            if let Some(reason) = is_suspicious_api(imp.dll_name, func_name) {
                suspicious_imports.push(SuspiciousApi {
                    dll: imp.dll_name.to_string(),
                    function: func_name.clone(),
                    reason,
                });
            }
        }

        import_list.push(ImportInfo {
            dll: imp.dll_name.to_string(),
            functions: funcs.clone(),
            count: funcs.len(),
        });
        import_pairs.push((imp.dll_name.to_string(), funcs));
    }

    // Parse exports
    let raw_exports = parse_exports(&pe);
    let exports: Vec<ExportInfo> = raw_exports.iter().map(|e| {
        ExportInfo {
            ordinal: e.ordinal,
            name: e.name.map(|s| s.to_string()),
            rva: e.rva,
        }
    }).collect();

    // Coverage analysis (inline known DLLs)
    let known_dlls: HashSet<&str> = [
        "kernel32", "kernelbase", "ntdll", "msvcrt", "ucrtbase",
        "advapi32", "user32", "gdi32", "shell32", "ole32", "oleaut32",
        "ws2_32", "wsock32", "wininet", "winhttp", "crypt32", "bcrypt",
        "libssp-0", "comctl32", "comdlg32", "shlwapi", "version",
        "secur32", "rpcrt4", "psapi", "iphlpapi",
    ].into_iter().collect();

    let total_funcs: usize = import_pairs.iter().map(|(_, f)| f.len()).sum();
    let mut resolved = 0usize;
    let mut missing_dlls = Vec::new();
    for (dll, funcs) in &import_pairs {
        let dll_key = dll.to_ascii_lowercase();
        let dll_key = dll_key.strip_suffix(".dll").unwrap_or(&dll_key);
        if known_dlls.contains(dll_key) {
            resolved += funcs.len();
        } else {
            missing_dlls.push(dll.clone());
        }
    }
    let coverage_pct = if total_funcs == 0 { 100.0 } else { (resolved as f64 / total_funcs as f64) * 100.0 };
    let is_runnable = missing_dlls.is_empty() && coverage_pct >= 80.0;

    // Security assessment
    let risk_score = compute_risk_score(&suspicious_imports, &sections, pe.is_dll());
    let risk_level = match risk_score {
        0..=20 => "LOW",
        21..=50 => "MEDIUM",
        51..=80 => "HIGH",
        _ => "CRITICAL",
    };

    PeAnalysis {
        valid: true,
        error: None,
        file_size: data.len(),
        machine: machine.to_string(),
        is_dll: pe.is_dll(),
        is_64bit: pe.is_64bit(),
        entry_point: pe.optional_header.entry_point(),
        image_size: pe.optional_header.size_of_image(),
        subsystem: subsystem_name.to_string(),
        sections,
        imports: import_list,
        exports,
        total_import_dlls: import_pairs.len(),
        total_import_functions: total_funcs,
        coverage_percent: coverage_pct,
        resolved_functions: resolved,
        is_runnable,
        missing_dlls,
        missing_functions: Vec::new(),
        suspicious_imports,
        risk_score,
        risk_level: risk_level.to_string(),
    }
}

/// Check if a section has suspicious characteristics.
fn is_section_suspicious(name: &str, characteristics: u32) -> bool {
    let is_writable_executable = (characteristics & 0x20000000 != 0) && (characteristics & 0x80000000 != 0);
    let has_unusual_name = !matches!(name, ".text" | ".rdata" | ".data" | ".rsrc" | ".reloc"
        | ".bss" | ".idata" | ".edata" | ".pdata" | ".CRT" | ".tls" | "_RDATA" | ".debug");
    // Writable + executable sections are suspicious (common in packers)
    is_writable_executable || (has_unusual_name && name.starts_with('.'))
}

/// Check if an API call is suspicious from a security perspective.
fn is_suspicious_api(dll: &str, func: &str) -> Option<String> {
    let dll_lower = dll.to_ascii_lowercase();
    match (dll_lower.as_str(), func) {
        // Process injection
        (_, "CreateRemoteThread") => Some("Process injection — creates thread in another process".into()),
        (_, "WriteProcessMemory") => Some("Process injection — writes to another process's memory".into()),
        (_, "VirtualAllocEx") => Some("Process injection — allocates memory in another process".into()),
        (_, "NtMapViewOfSection") => Some("Process injection — maps section into another process".into()),
        (_, "QueueUserAPC") => Some("APC injection — queues code to run in another thread".into()),
        (_, "SetWindowsHookExA") | (_, "SetWindowsHookExW") =>
            Some("Hooking — can intercept keyboard/mouse input".into()),

        // Anti-analysis / evasion
        (_, "IsDebuggerPresent") => Some("Anti-debugging — detects if debugger is attached".into()),
        (_, "CheckRemoteDebuggerPresent") => Some("Anti-debugging — checks for remote debugger".into()),
        (_, "NtQueryInformationProcess") => Some("Anti-debugging — can detect debuggers via ProcessDebugPort".into()),
        (_, "GetTickCount") | (_, "GetTickCount64") => None, // Common, not suspicious alone
        (_, "OutputDebugStringA") => None,

        // Persistence
        (_, "RegSetValueExA") | (_, "RegSetValueExW") =>
            Some("Registry write — potential persistence via Run keys".into()),

        // Network
        ("ws2_32.dll" | "wsock32.dll", _) =>
            Some(format!("Network API — {} (C2 communication possible)", func)),
        ("wininet.dll", _) =>
            Some(format!("HTTP API — {} (data exfiltration possible)", func)),
        ("winhttp.dll", _) =>
            Some(format!("HTTP API — {} (data exfiltration possible)", func)),

        // Crypto (often used by ransomware)
        ("advapi32.dll", "CryptEncrypt") => Some("Encryption — potential ransomware behavior".into()),
        ("advapi32.dll", "CryptDecrypt") => Some("Decryption — potential encrypted payload".into()),
        ("bcrypt.dll", _) => Some(format!("Crypto API — {} (ransomware indicator)", func)),

        // Service manipulation
        (_, "CreateServiceA") | (_, "CreateServiceW") =>
            Some("Service creation — persistence mechanism".into()),
        (_, "StartServiceA") | (_, "StartServiceW") =>
            Some("Service control — privilege escalation possible".into()),

        // Shell execution
        (_, "ShellExecuteA") | (_, "ShellExecuteW") =>
            Some("Shell execution — can launch arbitrary programs".into()),
        (_, "WinExec") => Some("Process execution — launches programs (deprecated API, suspicious)".into()),
        (_, "system") => Some("Shell command execution — runs arbitrary commands".into()),

        _ => None,
    }
}

/// Compute a risk score from 0-100.
fn compute_risk_score(suspicious: &[SuspiciousApi], sections: &[SectionInfo], _is_dll: bool) -> u32 {
    let mut score: u32 = 0;

    // Suspicious API count
    score += (suspicious.len() as u32) * 10;

    // Writable+executable sections (packers/crypters)
    let wx_sections = sections.iter().filter(|s| s.suspicious).count();
    score += (wx_sections as u32) * 15;

    // Network APIs
    let network_apis = suspicious.iter().filter(|s|
        s.reason.contains("Network") || s.reason.contains("HTTP")
    ).count();
    score += (network_apis as u32) * 15;

    // Process injection APIs
    let injection_apis = suspicious.iter().filter(|s|
        s.reason.contains("injection")
    ).count();
    score += (injection_apis as u32) * 20;

    // Crypto APIs (ransomware indicator)
    let crypto_apis = suspicious.iter().filter(|s|
        s.reason.contains("Crypto") || s.reason.contains("ncrypt") || s.reason.contains("ansomware")
    ).count();
    score += (crypto_apis as u32) * 20;

    score.min(100)
}

// ===== Serializable output types =====

#[derive(Debug, Serialize, Default)]
struct PeAnalysis {
    valid: bool,
    error: Option<String>,
    file_size: usize,
    machine: String,
    is_dll: bool,
    is_64bit: bool,
    entry_point: u32,
    image_size: u32,
    subsystem: String,
    sections: Vec<SectionInfo>,
    imports: Vec<ImportInfo>,
    exports: Vec<ExportInfo>,
    total_import_dlls: usize,
    total_import_functions: usize,
    coverage_percent: f64,
    resolved_functions: usize,
    missing_dlls: Vec<String>,
    missing_functions: Vec<String>,
    is_runnable: bool,
    suspicious_imports: Vec<SuspiciousApi>,
    risk_score: u32,
    risk_level: String,
}

#[derive(Debug, Serialize)]
struct SectionInfo {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    flags: String,
    suspicious: bool,
}

#[derive(Debug, Serialize)]
struct ImportInfo {
    dll: String,
    functions: Vec<String>,
    count: usize,
}

#[derive(Debug, Serialize)]
struct ExportInfo {
    ordinal: u16,
    name: Option<String>,
    rva: u32,
}

#[derive(Debug, Serialize)]
struct SuspiciousApi {
    dll: String,
    function: String,
    reason: String,
}
