# Winoxide

> Rust rewrite of Wine targeting WebAssembly — with a browser-native PE malware analyzer.

**[Live Demo](https://ryujiyasu.github.io/winoxide/)**

![Rust](https://img.shields.io/badge/Rust-000?logo=rust&logoColor=white)
![WebAssembly](https://img.shields.io/badge/WebAssembly-654FF0?logo=webassembly&logoColor=white)
![License](https://img.shields.io/badge/License-MIT%20%2F%20LGPL--2.1-blue)

## Overview

Winoxide is an open-source Windows PE binary analyzer that runs **entirely in the browser** — no server, no upload, no installation. Built from scratch in Rust, compiled to WebAssembly.

### 3-Stage Analysis Pipeline

```
Static Analysis → Safety Check → Dynamic Analysis → Final Verdict
```

1. **Static Analysis** — PE header parsing, section analysis, import/export enumeration, suspicious API detection, risk scoring
2. **Safety Check** — Automated evaluation of whether the binary is safe to emulate
3. **Dynamic Analysis** — x86 CPU emulation with IAT hooking, behavioral analysis, API call tracing
4. **AI Analysis** — Optional Gemini integration for threat intelligence (Google OAuth or API key)

### Multi-language Support

English, 日本語, 中文, 한국어

## Architecture

```
winoxide/
├── crates/
│   ├── winoxide-types/       # Shared types (PE structures, COFF headers)
│   ├── winoxide-pe/          # PE/COFF parser (DOS, NT, sections, imports, exports)
│   ├── winoxide-exec/        # Execution engine
│   │   ├── emulator.rs       # x86 CPU emulator (~40 instructions)
│   │   ├── dynamic_analysis.rs  # Behavioral analysis coordinator
│   │   ├── engine.rs         # PE loader & execution engine
│   │   ├── api_table.rs      # Win32 API implementations
│   │   └── vfs.rs            # Virtual filesystem
│   ├── winoxide-kernel32/    # kernel32.dll implementation
│   ├── winoxide-msvcrt/      # msvcrt.dll implementation
│   ├── winoxide-ntdll/       # ntdll.dll implementation
│   ├── winoxide-registry/    # Windows registry emulation
│   ├── winoxide-protocol/    # IPC protocol
│   ├── winoxide-server/      # Native server (for non-Wasm targets)
│   └── winoxide-wasm/        # WebAssembly bindings (wasm-bindgen)
├── web/                      # Frontend (vanilla HTML/JS + Canvas)
│   ├── index.html            # Analyzer UI
│   ├── pkg/                  # Wasm build output
│   └── samples/              # Test PE files
├── tools/
│   └── gen_sample_pe.rs      # Sample PE generator
└── examples/
    └── pe-info/              # CLI PE info tool
```

## Features

### PE Parser
- DOS Header, NT Headers (PE32/PE32+)
- Section table with suspicious flag detection (W+X, high entropy)
- Import Directory with DLL/function enumeration
- Export Directory
- Risk scoring based on imported APIs and section characteristics

### x86 Emulator
- Full register file (EAX–EDI, ESP, EBP, EIP, EFLAGS)
- ~40 instruction types: MOV, PUSH/POP, CALL, RET, JMP, Jcc, CMP, TEST, LEA, XOR, ADD, SUB, IMUL, REP prefix, and more
- IAT hooking for API call interception
- Infinite loop detection & step limits

### Behavioral Analysis
- Process injection detection (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
- Anti-debug pattern recognition (IsDebuggerPresent, CheckRemoteDebuggerPresent)
- Network activity monitoring (WS2_32, WinHTTP, WinInet)
- Crypto operation tracking (CryptEncrypt, CryptDecrypt)
- File and registry access logging
- Malware pattern matching: RAT, Ransomware, Dropper

## Build

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Lint
cargo clippy

# Build Wasm (for browser)
cd crates/winoxide-wasm && wasm-pack build --target web
```

## Test Samples

The `tools/gen_sample_pe.rs` generates test PE files:

```bash
rustc tools/gen_sample_pe.rs -o /tmp/gen_pe && /tmp/gen_pe
```

| File | Description | Expected Verdict |
|------|-------------|-----------------|
| `hello.exe` | Console app (GetStdHandle, WriteConsoleA) | CLEAN |
| `suspicious.exe` | Injection + network + crypto + W^X section | MALICIOUS |
| `clean.dll` | Benign DLL (HeapAlloc, HeapFree) | CLEAN |

## Deployment

GitHub Pages deployment is automated via `.github/workflows/pages.yml`. Push to `main` to deploy.

## License

MIT OR LGPL-2.1-or-later
