//! Dynamic analysis — loads a PE into the emulator and runs behavioral analysis.

use crate::emulator::{Emulator, StopReason, ApiCallRecord, BehaviorFlags};
use winoxide_pe::parser::PeFile;
use winoxide_pe::imports::{parse_imports, ImportFunction};
use serde::Serialize;

/// Result of dynamic analysis.
#[derive(Debug, Serialize)]
pub struct DynamicAnalysisResult {
    /// How execution stopped.
    pub stop_reason: String,
    /// Total steps executed.
    pub steps_executed: u64,
    /// API calls observed (ordered by execution).
    pub api_calls: Vec<ApiCallTrace>,
    /// Unique API call summary with counts.
    pub api_summary: Vec<ApiSummaryEntry>,
    /// Behavioral flags.
    pub behavior: BehaviorReport,
    /// Dynamic risk score (0-100).
    pub dynamic_risk_score: u32,
    /// Dynamic risk level.
    pub dynamic_risk_level: String,
    /// Combined verdict.
    pub verdict: String,
    /// Verdict confidence (0-100).
    pub confidence: u32,
}

#[derive(Debug, Serialize)]
pub struct ApiCallTrace {
    pub step: u64,
    pub dll: String,
    pub function: String,
    pub call_site: String,
}

#[derive(Debug, Serialize)]
pub struct ApiSummaryEntry {
    pub api: String,
    pub count: usize,
    pub category: String,
}

#[derive(Debug, Serialize)]
pub struct BehaviorReport {
    pub process_injection: bool,
    pub anti_debug: bool,
    pub file_operations: Vec<String>,
    pub registry_operations: Vec<String>,
    pub network_activity: bool,
    pub crypto_operations: bool,
    pub self_modifying_code: bool,
    pub dynamic_api_resolution: bool,
}

/// Run dynamic analysis on a PE file.
pub fn analyze_dynamic(data: &[u8], max_steps: u64) -> DynamicAnalysisResult {
    let pe = match PeFile::parse(data) {
        Ok(pe) => pe,
        Err(e) => {
            return DynamicAnalysisResult {
                stop_reason: format!("PE parse error: {}", e),
                steps_executed: 0,
                api_calls: vec![],
                api_summary: vec![],
                behavior: BehaviorReport {
                    process_injection: false,
                    anti_debug: false,
                    file_operations: vec![],
                    registry_operations: vec![],
                    network_activity: false,
                    crypto_operations: false,
                    self_modifying_code: false,
                    dynamic_api_resolution: false,
                },
                dynamic_risk_score: 0,
                dynamic_risk_level: "UNKNOWN".into(),
                verdict: "Unable to analyze".into(),
                confidence: 0,
            };
        }
    };

    let image_size = pe.optional_header.size_of_image();
    let entry_rva = pe.optional_header.entry_point();

    // Allocate emulator memory: image + stack + extra
    let mem_size = (image_size + 0x10000).max(2 * 1024 * 1024);
    let mut emu = Emulator::new(mem_size);
    emu.set_max_steps(max_steps);
    emu.set_image_base(0); // We load at VA 0 for simplicity

    // Load sections into virtual memory
    for section in pe.sections {
        let va = section.VirtualAddress;
        let raw_offset = section.PointerToRawData as usize;
        let raw_size = section.SizeOfRawData as usize;

        if raw_offset + raw_size <= data.len() {
            let section_data = &data[raw_offset..raw_offset + raw_size];
            let writable = section.Characteristics & 0x80000000 != 0;
            let executable = section.Characteristics & 0x20000000 != 0;
            emu.load_section(va, section_data, writable, executable);
        }
    }

    // Parse imports and set up IAT
    let imports = parse_imports(&pe);
    let mut iat_addr = image_size; // Place fake IAT after image

    for imp in &imports {
        for func in &imp.functions {
            let func_name = match func {
                ImportFunction::ByName { name, .. } => name.to_string(),
                ImportFunction::ByOrdinal(ord) => format!("ordinal#{}", ord),
            };
            emu.register_iat(iat_addr, imp.dll_name.to_string(), func_name);
            iat_addr += 4;
        }
    }

    // Also register IAT entries at their actual IAT locations in the PE
    // The import directory has the IAT RVAs
    setup_iat_thunks(&pe, data, &mut emu, image_size);

    // Run the emulator from entry point
    let stop = emu.run(entry_rva);

    let stop_reason = match &stop {
        StopReason::StepLimit => "Step limit reached".into(),
        StopReason::ReturnFromMain => "Main function returned".into(),
        StopReason::ExitCalled(code) => format!("ExitProcess({})", code),
        StopReason::UnknownInstruction { offset, bytes } =>
            format!("Unknown instruction at 0x{:x}: {:02x?}", offset, bytes),
        StopReason::AccessViolation { address } =>
            format!("Access violation at 0x{:x}", address),
        StopReason::InfiniteLoop { address } =>
            format!("Infinite loop at 0x{:x}", address),
        StopReason::Breakpoint => "Breakpoint".into(),
    };

    // Build API call trace
    let api_calls: Vec<ApiCallTrace> = emu.api_calls().iter().map(|c| {
        ApiCallTrace {
            step: c.step,
            dll: c.dll.clone(),
            function: c.function.clone(),
            call_site: format!("0x{:08x}", c.call_site),
        }
    }).collect();

    // Build API summary
    let api_summary: Vec<ApiSummaryEntry> = emu.api_call_summary().into_iter().map(|(api, count)| {
        let category = categorize_api(&api);
        ApiSummaryEntry { api, count, category }
    }).collect();

    // Build behavior report
    let behavior = BehaviorReport {
        process_injection: emu.behavior.process_injection,
        anti_debug: emu.behavior.anti_debug,
        file_operations: emu.behavior.file_access.clone(),
        registry_operations: emu.behavior.registry_access.clone(),
        network_activity: emu.behavior.network_activity,
        crypto_operations: emu.behavior.crypto_ops,
        self_modifying_code: emu.behavior.self_modifying,
        dynamic_api_resolution: emu.behavior.dynamic_api_resolution,
    };

    // Calculate dynamic risk score
    let dynamic_risk_score = compute_dynamic_risk(&emu, &api_calls);
    let dynamic_risk_level = match dynamic_risk_score {
        0..=20 => "LOW",
        21..=50 => "MEDIUM",
        51..=80 => "HIGH",
        _ => "CRITICAL",
    };

    // Combined verdict
    let (verdict, confidence) = compute_verdict(&behavior, dynamic_risk_score, &api_calls, &stop);

    DynamicAnalysisResult {
        stop_reason,
        steps_executed: emu.steps(),
        api_calls,
        api_summary,
        behavior,
        dynamic_risk_score,
        dynamic_risk_level: dynamic_risk_level.into(),
        verdict,
        confidence,
    }
}

/// Set up IAT thunks in the emulator so indirect calls to IAT work.
fn setup_iat_thunks(pe: &PeFile, data: &[u8], emu: &mut Emulator, fallback_base: u32) {
    // Data directory index 1 = Import Directory, 12 = IAT
    // We need to find where the IAT entries are in the PE
    if let Some(import_dir) = pe.data_directory(1) {
        let rva = import_dir.VirtualAddress;
        // Walk import descriptors
        let mut desc_rva = rva;
        let mut iat_counter = fallback_base;

        loop {
            // Each descriptor is 20 bytes
            let desc_data = match pe.rva_to_slice(desc_rva, 20) {
                Some(d) => d,
                None => break,
            };

            let original_first_thunk = u32::from_le_bytes([desc_data[0], desc_data[1], desc_data[2], desc_data[3]]);
            let name_rva = u32::from_le_bytes([desc_data[12], desc_data[13], desc_data[14], desc_data[15]]);
            let first_thunk = u32::from_le_bytes([desc_data[16], desc_data[17], desc_data[18], desc_data[19]]);

            // All zeros = end of import descriptors
            if name_rva == 0 {
                break;
            }

            let dll_name = pe.read_string_at_rva(name_rva).unwrap_or("unknown").to_string();

            // Walk the IAT (FirstThunk) and ILT (OriginalFirstThunk)
            let ilt_rva = if original_first_thunk != 0 { original_first_thunk } else { first_thunk };
            let is_64 = pe.is_64bit();
            let entry_size: u32 = if is_64 { 8 } else { 4 };
            let mut idx = 0u32;

            loop {
                let thunk_data = match pe.rva_to_slice(ilt_rva + idx * entry_size, entry_size as usize) {
                    Some(d) => d,
                    None => break,
                };

                let thunk_value = if is_64 {
                    u64::from_le_bytes([
                        thunk_data[0], thunk_data[1], thunk_data[2], thunk_data[3],
                        thunk_data[4], thunk_data[5], thunk_data[6], thunk_data[7],
                    ])
                } else {
                    u32::from_le_bytes([thunk_data[0], thunk_data[1], thunk_data[2], thunk_data[3]]) as u64
                };

                if thunk_value == 0 {
                    break;
                }

                // Determine function name
                let func_name = if is_64 && (thunk_value & 0x8000000000000000) != 0 {
                    format!("ordinal#{}", thunk_value & 0xFFFF)
                } else if !is_64 && (thunk_value & 0x80000000) != 0 {
                    format!("ordinal#{}", thunk_value & 0xFFFF)
                } else {
                    // thunk_value is RVA to IMAGE_IMPORT_BY_NAME (hint + name)
                    let name_rva = thunk_value as u32 + 2; // skip 2-byte hint
                    pe.read_string_at_rva(name_rva).unwrap_or("unknown").to_string()
                };

                // Register IAT: the FirstThunk entry address maps to this function
                let iat_entry_addr = first_thunk + idx * entry_size;
                emu.register_iat(iat_entry_addr, dll_name.clone(), func_name);
                iat_counter += 4;

                idx += 1;
            }

            desc_rva += 20;
        }
    }
}

fn categorize_api(api: &str) -> String {
    let api_lower = api.to_ascii_lowercase();
    if api_lower.contains("file") || api_lower.contains("fopen") || api_lower.contains("fwrite") || api_lower.contains("fread") {
        "File I/O".into()
    } else if api_lower.contains("virtual") || api_lower.contains("heap") || api_lower.contains("alloc") || api_lower.contains("malloc") {
        "Memory".into()
    } else if api_lower.contains("reg") {
        "Registry".into()
    } else if api_lower.contains("socket") || api_lower.contains("connect") || api_lower.contains("send") || api_lower.contains("recv")
        || api_lower.contains("internet") || api_lower.contains("http") {
        "Network".into()
    } else if api_lower.contains("crypt") || api_lower.contains("bcrypt") {
        "Crypto".into()
    } else if api_lower.contains("process") || api_lower.contains("thread") || api_lower.contains("remote") {
        "Process/Thread".into()
    } else if api_lower.contains("debug") || api_lower.contains("query") {
        "Anti-Analysis".into()
    } else if api_lower.contains("console") || api_lower.contains("write") || api_lower.contains("printf") || api_lower.contains("puts") {
        "Output".into()
    } else if api_lower.contains("module") || api_lower.contains("library") || api_lower.contains("procaddress") {
        "Module Loading".into()
    } else {
        "Other".into()
    }
}

fn compute_dynamic_risk(emu: &Emulator, api_calls: &[ApiCallTrace]) -> u32 {
    let mut score: u32 = 0;

    if emu.behavior.process_injection { score += 40; }
    if emu.behavior.anti_debug { score += 15; }
    if emu.behavior.network_activity { score += 25; }
    if emu.behavior.crypto_ops { score += 20; }
    if emu.behavior.self_modifying { score += 30; }
    if emu.behavior.dynamic_api_resolution { score += 10; }
    if !emu.behavior.file_access.is_empty() { score += 5; }
    if !emu.behavior.registry_access.is_empty() { score += 10; }

    // Bonus for suspicious API combinations
    let has_net = emu.behavior.network_activity;
    let has_crypto = emu.behavior.crypto_ops;
    let has_inject = emu.behavior.process_injection;
    if has_net && has_crypto { score += 20; } // Ransomware pattern
    if has_net && has_inject { score += 20; } // RAT pattern
    if has_crypto && !emu.behavior.file_access.is_empty() { score += 15; } // File encryption

    score.min(100)
}

fn compute_verdict(behavior: &BehaviorReport, risk_score: u32, api_calls: &[ApiCallTrace], stop: &StopReason) -> (String, u32) {
    if risk_score >= 80 {
        if behavior.process_injection && behavior.network_activity {
            ("MALICIOUS — Remote Access Trojan (RAT) pattern detected".into(), 90)
        } else if behavior.crypto_operations && !behavior.file_operations.is_empty() {
            ("MALICIOUS — Ransomware pattern detected".into(), 85)
        } else if behavior.process_injection {
            ("LIKELY MALICIOUS — Process injection detected".into(), 80)
        } else {
            ("LIKELY MALICIOUS — Multiple high-risk behaviors detected".into(), 75)
        }
    } else if risk_score >= 50 {
        if behavior.network_activity {
            ("SUSPICIOUS — Network activity with elevated risk indicators".into(), 65)
        } else if behavior.anti_debug {
            ("SUSPICIOUS — Anti-analysis techniques detected".into(), 60)
        } else {
            ("SUSPICIOUS — Elevated risk indicators detected".into(), 55)
        }
    } else if risk_score >= 20 {
        ("LOW RISK — Some notable behaviors but likely benign".into(), 70)
    } else {
        if api_calls.is_empty() {
            ("INCONCLUSIVE — No API calls traced (may need more steps)".into(), 30)
        } else {
            ("CLEAN — No malicious behavior patterns detected".into(), 85)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_categorize_api() {
        assert_eq!(categorize_api("kernel32!CreateFileA"), "File I/O");
        assert_eq!(categorize_api("kernel32!VirtualAlloc"), "Memory");
        assert_eq!(categorize_api("ws2_32!connect"), "Network");
        assert_eq!(categorize_api("bcrypt!BCryptEncrypt"), "Crypto");
    }
}
