//! x86/x64 CPU emulator for dynamic analysis.
//!
//! This is NOT a full x86 emulator — it's a "smart tracer" that follows
//! control flow to discover which Windows APIs would be called at runtime.
//! It emulates enough instructions to track register/stack state and detect
//! API call sequences.

use serde::Serialize;
use std::collections::HashMap;

/// x86 register set (32-bit mode).
#[derive(Debug, Clone, Default)]
pub struct Registers {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub esp: u32,
    pub ebp: u32,
    pub eip: u32,
    /// Flags: ZF=bit6, SF=bit7, CF=bit0
    pub eflags: u32,
}

/// x64 register set.
#[derive(Debug, Clone, Default)]
pub struct Registers64 {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rip: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub eflags: u64,
}

/// Emulation stop reason.
#[derive(Debug, Clone, Serialize)]
pub enum StopReason {
    /// Hit the step limit.
    StepLimit,
    /// Executed a RET with empty call stack.
    ReturnFromMain,
    /// ExitProcess / exit() was called.
    ExitCalled(u32),
    /// Hit an unimplemented instruction.
    UnknownInstruction { offset: u32, bytes: Vec<u8> },
    /// Access violation.
    AccessViolation { address: u32 },
    /// Infinite loop detected.
    InfiniteLoop { address: u32 },
    /// Breakpoint.
    Breakpoint,
}

/// An API call observed during emulation.
#[derive(Debug, Clone, Serialize)]
pub struct ApiCallRecord {
    /// Instruction address that made the call.
    pub call_site: u32,
    /// Target DLL.
    pub dll: String,
    /// Target function name.
    pub function: String,
    /// Step number (for ordering).
    pub step: u64,
    /// Stack arguments captured (first 4).
    pub args: Vec<u32>,
}

/// Memory operation during emulation.
#[derive(Debug, Clone, Serialize)]
pub struct MemoryOp {
    pub step: u64,
    pub op_type: MemOpType,
    pub address: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Serialize)]
pub enum MemOpType {
    Read,
    Write,
    Alloc,
    Free,
}

/// Behavioral flags detected during emulation.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BehaviorFlags {
    /// Process injection pattern (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
    pub process_injection: bool,
    /// Anti-debugging (IsDebuggerPresent, timing checks)
    pub anti_debug: bool,
    /// File system access
    pub file_access: Vec<String>,
    /// Registry access
    pub registry_access: Vec<String>,
    /// Network activity
    pub network_activity: bool,
    /// Crypto operations
    pub crypto_ops: bool,
    /// Self-modification (write to code section)
    pub self_modifying: bool,
    /// Dynamically resolves APIs (GetProcAddress pattern)
    pub dynamic_api_resolution: bool,
    /// Suspicious string operations (building URLs, paths)
    pub suspicious_strings: Vec<String>,
}

/// IAT (Import Address Table) entry — maps a virtual address to a DLL!Function.
#[derive(Debug, Clone)]
pub struct IatEntry {
    pub dll: String,
    pub function: String,
}

/// The x86 emulator.
pub struct Emulator {
    /// Virtual memory (flat address space).
    memory: Vec<u8>,
    /// Memory size.
    mem_size: u32,
    /// Registers (32-bit mode).
    regs: Registers,
    /// Is 64-bit mode?
    is_64bit: bool,
    /// 64-bit registers (used if is_64bit).
    regs64: Registers64,
    /// Import Address Table mapping: address → (DLL, function).
    iat: HashMap<u32, IatEntry>,
    /// Recorded API calls.
    api_calls: Vec<ApiCallRecord>,
    /// Memory operations.
    mem_ops: Vec<MemoryOp>,
    /// Behavior flags.
    pub behavior: BehaviorFlags,
    /// Step counter.
    steps: u64,
    /// Max steps before stopping.
    max_steps: u64,
    /// Call stack depth tracker.
    call_depth: u32,
    /// Loop detection: address → hit count.
    loop_detector: HashMap<u32, u32>,
    /// Image base.
    image_base: u32,
    /// Writable memory regions (for W^X detection).
    writable_regions: Vec<(u32, u32)>,
    /// Executable memory regions.
    executable_regions: Vec<(u32, u32)>,
}

impl Emulator {
    /// Create a new emulator with the given memory size (default 4MB).
    pub fn new(mem_size: u32) -> Self {
        let mem_size = if mem_size == 0 { 4 * 1024 * 1024 } else { mem_size };
        Self {
            memory: vec![0u8; mem_size as usize],
            mem_size,
            regs: Registers::default(),
            is_64bit: false,
            regs64: Registers64::default(),
            iat: HashMap::new(),
            api_calls: Vec::new(),
            mem_ops: Vec::new(),
            behavior: BehaviorFlags::default(),
            steps: 0,
            max_steps: 50_000,
            call_depth: 0,
            loop_detector: HashMap::new(),
            image_base: 0,
            writable_regions: Vec::new(),
            executable_regions: Vec::new(),
        }
    }

    /// Set maximum execution steps.
    pub fn set_max_steps(&mut self, max: u64) {
        self.max_steps = max;
    }

    /// Load a section into virtual memory.
    pub fn load_section(&mut self, virtual_addr: u32, data: &[u8], writable: bool, executable: bool) {
        let offset = virtual_addr as usize;
        let end = offset + data.len();
        if end <= self.memory.len() {
            self.memory[offset..end].copy_from_slice(data);
        }
        let region = (virtual_addr, virtual_addr + data.len() as u32);
        if writable {
            self.writable_regions.push(region);
        }
        if executable {
            self.executable_regions.push(region);
        }
    }

    /// Register an IAT entry at a virtual address.
    pub fn register_iat(&mut self, address: u32, dll: String, function: String) {
        self.iat.insert(address, IatEntry { dll, function });
    }

    /// Set the image base.
    pub fn set_image_base(&mut self, base: u32) {
        self.image_base = base;
    }

    /// Set up initial state and run from entry point.
    pub fn run(&mut self, entry_point: u32) -> StopReason {
        // Set up stack
        let stack_base = self.mem_size - 0x1000; // Leave 4KB at top
        self.regs.esp = stack_base;
        self.regs.ebp = stack_base;
        self.regs.eip = entry_point;

        // Push a sentinel return address (0xDEADBEEF)
        self.push32(0xDEAD_BEEF);

        self.execute_loop()
    }

    /// Main execution loop.
    fn execute_loop(&mut self) -> StopReason {
        loop {
            if self.steps >= self.max_steps {
                return StopReason::StepLimit;
            }

            let eip = self.regs.eip;

            // Loop detection
            let count = self.loop_detector.entry(eip).or_insert(0);
            *count += 1;
            if *count > 1000 {
                return StopReason::InfiniteLoop { address: eip };
            }

            // Check if we're at the sentinel return address
            if eip == 0xDEAD_BEEF {
                return StopReason::ReturnFromMain;
            }

            // Bounds check
            if eip as usize >= self.memory.len() {
                return StopReason::AccessViolation { address: eip };
            }

            // Check if this is a CALL to an IAT entry (indirect call through IAT)
            // Common patterns: FF 15 [addr] (call [mem32]) or FF 25 [addr] (jmp [mem32])
            let result = self.execute_one();
            self.steps += 1;

            match result {
                Ok(()) => continue,
                Err(reason) => return reason,
            }
        }
    }

    /// Execute one instruction. Returns Err(StopReason) if execution should stop.
    fn execute_one(&mut self) -> Result<(), StopReason> {
        let eip = self.regs.eip;
        let b0 = self.read_u8(eip)?;

        match b0 {
            // NOP
            0x90 => {
                self.regs.eip += 1;
            }

            // INT 3 (breakpoint)
            0xCC => {
                return Err(StopReason::Breakpoint);
            }

            // PUSH r32 (50+r)
            0x50..=0x57 => {
                let val = self.get_reg32(b0 - 0x50);
                self.push32(val);
                self.regs.eip += 1;
            }

            // POP r32 (58+r)
            0x58..=0x5F => {
                let val = self.pop32()?;
                self.set_reg32(b0 - 0x58, val);
                self.regs.eip += 1;
            }

            // PUSH imm32
            0x68 => {
                let imm = self.read_u32(eip + 1)?;
                self.push32(imm);
                self.regs.eip += 5;
            }

            // PUSH imm8
            0x6A => {
                let imm = self.read_u8(eip + 1)? as i8 as i32 as u32;
                self.push32(imm);
                self.regs.eip += 2;
            }

            // MOV r32, imm32 (B8+r)
            0xB8..=0xBF => {
                let reg = b0 - 0xB8;
                let imm = self.read_u32(eip + 1)?;
                self.set_reg32(reg, imm);
                self.regs.eip += 5;
            }

            // MOV r8, imm8 (B0+r)
            0xB0..=0xB7 => {
                // Skip — we don't track 8-bit regs in detail
                self.regs.eip += 2;
            }

            // XOR r32, r/m32 (opcode 0x31 or 0x33)
            0x31 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let result = self.get_reg32(dst) ^ self.get_reg32(src);
                self.set_reg32(dst, result);
                self.update_flags_logic(result);
                self.regs.eip += 2;
            }
            0x33 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let result = self.get_reg32(dst) ^ self.get_reg32(src);
                self.set_reg32(dst, result);
                self.update_flags_logic(result);
                self.regs.eip += 2;
            }

            // SUB r32, r/m32
            0x29 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let a = self.get_reg32(dst);
                let b = self.get_reg32(src);
                let result = a.wrapping_sub(b);
                self.set_reg32(dst, result);
                self.update_flags_sub(a, b, result);
                self.regs.eip += 2;
            }
            0x2B => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let a = self.get_reg32(dst);
                let b = self.get_reg32(src);
                let result = a.wrapping_sub(b);
                self.set_reg32(dst, result);
                self.update_flags_sub(a, b, result);
                self.regs.eip += 2;
            }

            // ADD r32, r/m32
            0x01 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let result = self.get_reg32(dst).wrapping_add(self.get_reg32(src));
                self.set_reg32(dst, result);
                self.update_flags_add(self.get_reg32(dst), self.get_reg32(src), result);
                self.regs.eip += 2;
            }
            0x03 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let result = self.get_reg32(dst).wrapping_add(self.get_reg32(src));
                self.set_reg32(dst, result);
                self.regs.eip += 2;
            }

            // MOV r32, r/m32 (0x89 = mov r/m, r; 0x8B = mov r, r/m)
            0x89 => {
                let modrm = self.read_u8(eip + 1)?;
                let mode = modrm >> 6;
                let src = ((modrm >> 3) & 7) as u8;
                let dst = (modrm & 7) as u8;
                if mode == 3 {
                    // reg-to-reg
                    let val = self.get_reg32(src);
                    self.set_reg32(dst, val);
                    self.regs.eip += 2;
                } else {
                    // mov [mem], reg — skip complex addressing
                    let (_, advance) = self.skip_modrm_mem(mode, dst, eip + 1);
                    self.regs.eip += 1 + advance;
                }
            }
            0x8B => {
                let modrm = self.read_u8(eip + 1)?;
                let mode = modrm >> 6;
                let dst = ((modrm >> 3) & 7) as u8;
                let src = (modrm & 7) as u8;
                if mode == 3 {
                    let val = self.get_reg32(src);
                    self.set_reg32(dst, val);
                    self.regs.eip += 2;
                } else {
                    // mov reg, [mem] — try to read if possible
                    let (addr, advance) = self.decode_modrm_addr(mode, src, eip + 1);
                    if let Some(addr) = addr {
                        if let Ok(val) = self.read_u32(addr) {
                            self.set_reg32(dst, val);
                        }
                    }
                    self.regs.eip += 1 + advance;
                }
            }

            // CMP r32, r/m32 (0x39, 0x3B)
            0x39 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let a = self.get_reg32(dst);
                let b = self.get_reg32(src);
                self.update_flags_sub(a, b, a.wrapping_sub(b));
                self.regs.eip += 2;
            }
            0x3B => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let a = self.get_reg32(dst);
                let b = self.get_reg32(src);
                self.update_flags_sub(a, b, a.wrapping_sub(b));
                self.regs.eip += 2;
            }

            // CMP EAX, imm32
            0x3D => {
                let imm = self.read_u32(eip + 1)?;
                let a = self.regs.eax;
                self.update_flags_sub(a, imm, a.wrapping_sub(imm));
                self.regs.eip += 5;
            }

            // TEST r/m32, r32
            0x85 => {
                let modrm = self.read_u8(eip + 1)?;
                let (src, dst) = self.decode_modrm_regs(modrm);
                let result = self.get_reg32(dst) & self.get_reg32(src);
                self.update_flags_logic(result);
                self.regs.eip += 2;
            }

            // TEST AL, imm8
            0xA8 => {
                let imm = self.read_u8(eip + 1)? as u32;
                let result = (self.regs.eax & 0xFF) & imm;
                self.update_flags_logic(result);
                self.regs.eip += 2;
            }

            // SUB ESP, imm8 pattern (83 EC xx) — common prologue
            // Also handles other 0x83 operations
            0x83 => {
                let modrm = self.read_u8(eip + 1)?;
                let op = (modrm >> 3) & 7;
                let mode = modrm >> 6;
                let rm = modrm & 7;
                let imm = self.read_u8(eip + 2)? as i8 as i32 as u32;
                if mode == 3 {
                    let val = self.get_reg32(rm);
                    let result = match op {
                        0 => val.wrapping_add(imm), // ADD
                        4 => val & imm,              // AND
                        5 => val.wrapping_sub(imm), // SUB
                        7 => {                       // CMP
                            self.update_flags_sub(val, imm, val.wrapping_sub(imm));
                            val // don't modify
                        }
                        _ => val, // other ops: skip
                    };
                    if op != 7 {
                        self.set_reg32(rm, result);
                    }
                }
                self.regs.eip += 3;
            }

            // 0x81: op r/m32, imm32
            0x81 => {
                let modrm = self.read_u8(eip + 1)?;
                let op = (modrm >> 3) & 7;
                let mode = modrm >> 6;
                let rm = modrm & 7;
                let imm = self.read_u32(eip + 2)?;
                if mode == 3 {
                    let val = self.get_reg32(rm);
                    let result = match op {
                        0 => val.wrapping_add(imm),
                        5 => val.wrapping_sub(imm),
                        7 => {
                            self.update_flags_sub(val, imm, val.wrapping_sub(imm));
                            val
                        }
                        _ => val,
                    };
                    if op != 7 {
                        self.set_reg32(rm, result);
                    }
                }
                self.regs.eip += 6;
            }

            // LEA r32, [mem] (8D)
            0x8D => {
                let modrm = self.read_u8(eip + 1)?;
                let mode = modrm >> 6;
                let dst = ((modrm >> 3) & 7) as u8;
                let rm = (modrm & 7) as u8;
                let (addr, advance) = self.decode_modrm_addr(mode, rm, eip + 1);
                if let Some(addr) = addr {
                    self.set_reg32(dst, addr);
                }
                self.regs.eip += 1 + advance;
            }

            // CALL rel32
            0xE8 => {
                let rel = self.read_u32(eip + 1)? as i32;
                let ret_addr = eip + 5;
                let target = (ret_addr as i32 + rel) as u32;
                self.push32(ret_addr);
                self.call_depth += 1;

                // Check if target is in IAT
                if let Some(entry) = self.iat.get(&target).cloned() {
                    self.record_api_call(eip, &entry.dll, &entry.function);
                    // Simulate return from API
                    self.regs.eax = 1; // success return
                    let ret = self.pop32()?;
                    self.regs.eip = ret;
                    self.call_depth = self.call_depth.saturating_sub(1);
                } else {
                    self.regs.eip = target;
                }
            }

            // CALL r/m32 (FF /2) and JMP r/m32 (FF /4)
            0xFF => {
                let modrm = self.read_u8(eip + 1)?;
                let op = (modrm >> 3) & 7;
                let mode = modrm >> 6;
                let rm = (modrm & 7) as u8;

                match op {
                    // CALL r/m32
                    2 => {
                        let (target_addr, advance) = if mode == 3 {
                            (Some(self.get_reg32(rm)), 2u32)
                        } else {
                            let (addr, adv) = self.decode_modrm_addr(mode, rm, eip + 1);
                            // For indirect call [mem], read the target from memory
                            let target = if let Some(a) = addr {
                                self.read_u32(a).ok()
                            } else {
                                None
                            };
                            (target, 1 + adv)
                        };

                        let ret_addr = eip + advance;

                        if let Some(target) = target_addr {
                            // Check if it's an IAT call
                            if let Some(entry) = self.iat.get(&target).cloned() {
                                self.record_api_call(eip, &entry.dll, &entry.function);
                                self.regs.eax = 1;
                                self.regs.eip = ret_addr;
                            } else {
                                // Also check if the memory address itself is an IAT thunk
                                // Pattern: CALL [iat_addr] where iat_addr points to the function
                                let (addr, _) = if mode != 3 {
                                    self.decode_modrm_addr(mode, rm, eip + 1)
                                } else {
                                    (None, 0)
                                };
                                if let Some(iat_addr) = addr {
                                    if let Some(entry) = self.iat.get(&iat_addr).cloned() {
                                        self.record_api_call(eip, &entry.dll, &entry.function);
                                        self.regs.eax = 1;
                                        self.regs.eip = ret_addr;
                                    } else {
                                        self.push32(ret_addr);
                                        self.call_depth += 1;
                                        self.regs.eip = target;
                                    }
                                } else {
                                    self.push32(ret_addr);
                                    self.call_depth += 1;
                                    self.regs.eip = target;
                                }
                            }
                        } else {
                            self.regs.eip += advance;
                        }
                    }
                    // JMP r/m32
                    4 => {
                        let target = if mode == 3 {
                            Some(self.get_reg32(rm))
                        } else {
                            let (addr, _) = self.decode_modrm_addr(mode, rm, eip + 1);
                            addr.and_then(|a| self.read_u32(a).ok())
                        };

                        if let Some(target) = target {
                            // Check IAT
                            if let Some(entry) = self.iat.get(&target).cloned() {
                                self.record_api_call(eip, &entry.dll, &entry.function);
                                self.regs.eax = 1;
                                // For JMP to API, return to caller
                                let ret = self.pop32()?;
                                self.regs.eip = ret;
                            } else {
                                self.regs.eip = target;
                            }
                        } else {
                            // Can't determine target, stop
                            return Err(StopReason::UnknownInstruction {
                                offset: eip,
                                bytes: self.read_bytes(eip, 4),
                            });
                        }
                    }
                    // INC r/m32
                    0 => {
                        if mode == 3 {
                            let val = self.get_reg32(rm).wrapping_add(1);
                            self.set_reg32(rm, val);
                        }
                        self.regs.eip += 2;
                    }
                    // DEC r/m32
                    1 => {
                        if mode == 3 {
                            let val = self.get_reg32(rm).wrapping_sub(1);
                            self.set_reg32(rm, val);
                        }
                        self.regs.eip += 2;
                    }
                    // PUSH r/m32
                    6 => {
                        if mode == 3 {
                            let val = self.get_reg32(rm);
                            self.push32(val);
                        }
                        self.regs.eip += 2;
                    }
                    _ => {
                        return Err(StopReason::UnknownInstruction {
                            offset: eip,
                            bytes: self.read_bytes(eip, 4),
                        });
                    }
                }
            }

            // RET (near)
            0xC3 => {
                let ret_addr = self.pop32()?;
                self.call_depth = self.call_depth.saturating_sub(1);
                if ret_addr == 0xDEAD_BEEF {
                    return Err(StopReason::ReturnFromMain);
                }
                self.regs.eip = ret_addr;
            }

            // RET imm16
            0xC2 => {
                let pop_bytes = self.read_u16(eip + 1)? as u32;
                let ret_addr = self.pop32()?;
                self.regs.esp += pop_bytes;
                self.call_depth = self.call_depth.saturating_sub(1);
                if ret_addr == 0xDEAD_BEEF {
                    return Err(StopReason::ReturnFromMain);
                }
                self.regs.eip = ret_addr;
            }

            // JMP rel32
            0xE9 => {
                let rel = self.read_u32(eip + 1)? as i32;
                self.regs.eip = (eip as i32 + 5 + rel) as u32;
            }

            // JMP rel8
            0xEB => {
                let rel = self.read_u8(eip + 1)? as i8;
                self.regs.eip = (eip as i32 + 2 + rel as i32) as u32;
            }

            // Jcc rel8 (short conditional jumps)
            0x70..=0x7F => {
                let rel = self.read_u8(eip + 1)? as i8;
                let cond = b0 & 0x0F;
                let taken = self.check_condition(cond);
                if taken {
                    self.regs.eip = (eip as i32 + 2 + rel as i32) as u32;
                } else {
                    self.regs.eip += 2;
                }
            }

            // Two-byte opcodes (0x0F prefix)
            0x0F => {
                let b1 = self.read_u8(eip + 1)?;
                match b1 {
                    // Jcc rel32 (near conditional jumps)
                    0x80..=0x8F => {
                        let rel = self.read_u32(eip + 2)? as i32;
                        let cond = b1 & 0x0F;
                        let taken = self.check_condition(cond);
                        if taken {
                            self.regs.eip = (eip as i32 + 6 + rel) as u32;
                        } else {
                            self.regs.eip += 6;
                        }
                    }
                    // SETcc r/m8
                    0x90..=0x9F => {
                        let modrm = self.read_u8(eip + 2)?;
                        let mode = modrm >> 6;
                        let rm = (modrm & 7) as u8;
                        let cond = b1 & 0x0F;
                        let val = if self.check_condition(cond) { 1u32 } else { 0 };
                        if mode == 3 {
                            // Only set low byte, but we approximate
                            let old = self.get_reg32(rm);
                            self.set_reg32(rm, (old & 0xFFFFFF00) | val);
                        }
                        self.regs.eip += 3;
                    }
                    // MOVZX r32, r/m8
                    0xB6 => {
                        let modrm = self.read_u8(eip + 2)?;
                        let mode = modrm >> 6;
                        let dst = ((modrm >> 3) & 7) as u8;
                        let rm = (modrm & 7) as u8;
                        if mode == 3 {
                            let val = self.get_reg32(rm) & 0xFF;
                            self.set_reg32(dst, val);
                        }
                        self.regs.eip += 3;
                    }
                    // MOVZX r32, r/m16
                    0xB7 => {
                        let modrm = self.read_u8(eip + 2)?;
                        let mode = modrm >> 6;
                        let dst = ((modrm >> 3) & 7) as u8;
                        let rm = (modrm & 7) as u8;
                        if mode == 3 {
                            let val = self.get_reg32(rm) & 0xFFFF;
                            self.set_reg32(dst, val);
                        }
                        self.regs.eip += 3;
                    }
                    // IMUL r32, r/m32 (0F AF)
                    0xAF => {
                        let modrm = self.read_u8(eip + 2)?;
                        let (src, dst) = self.decode_modrm_regs(modrm);
                        let result = (self.get_reg32(dst) as i32).wrapping_mul(self.get_reg32(src) as i32);
                        self.set_reg32(dst, result as u32);
                        self.regs.eip += 3;
                    }
                    // NOP (0F 1F ...)
                    0x1F => {
                        // multi-byte NOP — skip based on ModR/M
                        let modrm = self.read_u8(eip + 2)?;
                        let mode = modrm >> 6;
                        let rm = (modrm & 7) as u8;
                        let (_, advance) = self.skip_modrm_mem(mode, rm, eip + 2);
                        self.regs.eip += 2 + advance;
                    }
                    _ => {
                        // Unknown 0F xx — skip 2 bytes
                        self.regs.eip += 2;
                    }
                }
            }

            // LEAVE
            0xC9 => {
                self.regs.esp = self.regs.ebp;
                let val = self.pop32()?;
                self.regs.ebp = val;
                self.regs.eip += 1;
            }

            // INC r32 (40+r) — x86 only, repurposed as REX in x64
            0x40..=0x47 if !self.is_64bit => {
                let reg = b0 - 0x40;
                let val = self.get_reg32(reg).wrapping_add(1);
                self.set_reg32(reg, val);
                self.regs.eip += 1;
            }

            // DEC r32 (48+r)
            0x48..=0x4F if !self.is_64bit => {
                let reg = b0 - 0x48;
                let val = self.get_reg32(reg).wrapping_sub(1);
                self.set_reg32(reg, val);
                self.regs.eip += 1;
            }

            // MOVS / STOS / REP prefix
            0xF2 | 0xF3 => {
                // REP/REPNE prefix — skip the string instruction
                let next = self.read_u8(eip + 1)?;
                match next {
                    0xA4 | 0xA5 | 0xA6 | 0xA7 | 0xAA | 0xAB | 0xAE | 0xAF => {
                        // REP MOVS/CMPS/STOS/SCAS — simulate as NOP (string ops)
                        self.regs.ecx = 0;
                        self.regs.eip += 2;
                    }
                    _ => {
                        self.regs.eip += 1; // just skip the prefix
                    }
                }
            }

            // CDQ (sign-extend EAX into EDX:EAX)
            0x99 => {
                self.regs.edx = if self.regs.eax & 0x80000000 != 0 { 0xFFFFFFFF } else { 0 };
                self.regs.eip += 1;
            }

            // CWDE
            0x98 => {
                self.regs.eax = (self.regs.eax as i16 as i32) as u32;
                self.regs.eip += 1;
            }

            // Catch-all: skip unknown instructions gracefully
            _ => {
                // Try to skip based on common instruction lengths
                // This is a heuristic — real disassembly would be more accurate
                return Err(StopReason::UnknownInstruction {
                    offset: eip,
                    bytes: self.read_bytes(eip, 4),
                });
            }
        }

        Ok(())
    }

    // ===== Helper methods =====

    fn read_u8(&self, addr: u32) -> Result<u8, StopReason> {
        let idx = addr as usize;
        if idx < self.memory.len() {
            Ok(self.memory[idx])
        } else {
            Err(StopReason::AccessViolation { address: addr })
        }
    }

    fn read_u16(&self, addr: u32) -> Result<u16, StopReason> {
        let idx = addr as usize;
        if idx + 1 < self.memory.len() {
            Ok(u16::from_le_bytes([self.memory[idx], self.memory[idx + 1]]))
        } else {
            Err(StopReason::AccessViolation { address: addr })
        }
    }

    fn read_u32(&self, addr: u32) -> Result<u32, StopReason> {
        let idx = addr as usize;
        if idx + 3 < self.memory.len() {
            Ok(u32::from_le_bytes([
                self.memory[idx],
                self.memory[idx + 1],
                self.memory[idx + 2],
                self.memory[idx + 3],
            ]))
        } else {
            Err(StopReason::AccessViolation { address: addr })
        }
    }

    fn read_bytes(&self, addr: u32, count: usize) -> Vec<u8> {
        let start = addr as usize;
        let end = (start + count).min(self.memory.len());
        if start < self.memory.len() {
            self.memory[start..end].to_vec()
        } else {
            vec![]
        }
    }

    fn push32(&mut self, val: u32) {
        self.regs.esp = self.regs.esp.wrapping_sub(4);
        let sp = self.regs.esp as usize;
        if sp + 3 < self.memory.len() {
            self.memory[sp..sp + 4].copy_from_slice(&val.to_le_bytes());
        }
    }

    fn pop32(&mut self) -> Result<u32, StopReason> {
        let val = self.read_u32(self.regs.esp)?;
        self.regs.esp = self.regs.esp.wrapping_add(4);
        Ok(val)
    }

    fn get_reg32(&self, idx: u8) -> u32 {
        match idx & 7 {
            0 => self.regs.eax,
            1 => self.regs.ecx,
            2 => self.regs.edx,
            3 => self.regs.ebx,
            4 => self.regs.esp,
            5 => self.regs.ebp,
            6 => self.regs.esi,
            7 => self.regs.edi,
            _ => unreachable!(),
        }
    }

    fn set_reg32(&mut self, idx: u8, val: u32) {
        match idx & 7 {
            0 => self.regs.eax = val,
            1 => self.regs.ecx = val,
            2 => self.regs.edx = val,
            3 => self.regs.ebx = val,
            4 => self.regs.esp = val,
            5 => self.regs.ebp = val,
            6 => self.regs.esi = val,
            7 => self.regs.edi = val,
            _ => unreachable!(),
        }
    }

    fn decode_modrm_regs(&self, modrm: u8) -> (u8, u8) {
        let reg = (modrm >> 3) & 7;
        let rm = modrm & 7;
        (reg, rm)
    }

    /// Decode ModR/M memory address (simplified — handles common patterns).
    fn decode_modrm_addr(&self, mode: u8, rm: u8, modrm_offset: u32) -> (Option<u32>, u32) {
        match mode {
            0 => {
                if rm == 5 {
                    // [disp32]
                    let disp = self.read_u32(modrm_offset + 1).unwrap_or(0);
                    (Some(disp), 5)
                } else if rm == 4 {
                    // SIB byte
                    (None, 3) // skip SIB + possible displacement
                } else {
                    let base = self.get_reg32(rm);
                    (Some(base), 1)
                }
            }
            1 => {
                // [reg + disp8]
                if rm == 4 {
                    (None, 3)
                } else {
                    let base = self.get_reg32(rm);
                    let disp = self.read_u8(modrm_offset + 1).unwrap_or(0) as i8 as i32;
                    (Some((base as i32 + disp) as u32), 2)
                }
            }
            2 => {
                // [reg + disp32]
                if rm == 4 {
                    (None, 6)
                } else {
                    let base = self.get_reg32(rm);
                    let disp = self.read_u32(modrm_offset + 1).unwrap_or(0) as i32;
                    (Some((base as i32 + disp) as u32), 5)
                }
            }
            3 => {
                // register direct — not a memory address
                (Some(self.get_reg32(rm)), 1)
            }
            _ => (None, 1),
        }
    }

    /// Skip a ModR/M memory operand without decoding (returns byte count consumed).
    fn skip_modrm_mem(&self, mode: u8, rm: u8, _modrm_offset: u32) -> ((), u32) {
        let advance = match mode {
            0 => {
                if rm == 5 { 5 } // [disp32]
                else if rm == 4 { 2 } // SIB (approximate)
                else { 1 }
            }
            1 => if rm == 4 { 3 } else { 2 },
            2 => if rm == 4 { 6 } else { 5 },
            3 => 1,
            _ => 1,
        };
        ((), advance)
    }

    fn check_condition(&self, cond: u8) -> bool {
        let zf = (self.regs.eflags >> 6) & 1 != 0;
        let sf = (self.regs.eflags >> 7) & 1 != 0;
        let cf = self.regs.eflags & 1 != 0;
        let of = (self.regs.eflags >> 11) & 1 != 0;

        match cond {
            0x0 => of,           // JO
            0x1 => !of,          // JNO
            0x2 => cf,           // JB/JNAE
            0x3 => !cf,          // JAE/JNB
            0x4 => zf,           // JE/JZ
            0x5 => !zf,          // JNE/JNZ
            0x6 => cf || zf,     // JBE/JNA
            0x7 => !cf && !zf,   // JA/JNBE
            0x8 => sf,           // JS
            0x9 => !sf,          // JNS
            0xA => false,        // JP (parity — approx)
            0xB => true,         // JNP
            0xC => sf != of,     // JL/JNGE
            0xD => sf == of,     // JGE/JNL
            0xE => zf || (sf != of), // JLE/JNG
            0xF => !zf && (sf == of), // JG/JNLE
            _ => false,
        }
    }

    fn update_flags_logic(&mut self, result: u32) {
        self.regs.eflags &= !(1 | (1 << 6) | (1 << 7) | (1 << 11));
        if result == 0 { self.regs.eflags |= 1 << 6; } // ZF
        if result & 0x80000000 != 0 { self.regs.eflags |= 1 << 7; } // SF
    }

    fn update_flags_sub(&mut self, a: u32, b: u32, result: u32) {
        self.regs.eflags &= !(1 | (1 << 6) | (1 << 7) | (1 << 11));
        if result == 0 { self.regs.eflags |= 1 << 6; }
        if result & 0x80000000 != 0 { self.regs.eflags |= 1 << 7; }
        if a < b { self.regs.eflags |= 1; } // CF
        let sa = (a >> 31) & 1;
        let sb = (b >> 31) & 1;
        let sr = (result >> 31) & 1;
        if (sa != sb) && (sa != sr) { self.regs.eflags |= 1 << 11; } // OF
    }

    fn update_flags_add(&mut self, a: u32, b: u32, result: u32) {
        self.regs.eflags &= !(1 | (1 << 6) | (1 << 7) | (1 << 11));
        if result == 0 { self.regs.eflags |= 1 << 6; }
        if result & 0x80000000 != 0 { self.regs.eflags |= 1 << 7; }
        if result < a { self.regs.eflags |= 1; }
        let sa = (a >> 31) & 1;
        let sb = (b >> 31) & 1;
        let sr = (result >> 31) & 1;
        if (sa == sb) && (sa != sr) { self.regs.eflags |= 1 << 11; }
    }

    /// Record an API call and analyze behavior.
    fn record_api_call(&mut self, call_site: u32, dll: &str, function: &str) {
        // Capture stack arguments (first 4)
        let args = (0..4).filter_map(|i| {
            self.read_u32(self.regs.esp + 4 + i * 4).ok()
        }).collect::<Vec<_>>();

        self.api_calls.push(ApiCallRecord {
            call_site,
            dll: dll.to_string(),
            function: function.to_string(),
            step: self.steps,
            args,
        });

        // Behavioral analysis
        self.analyze_behavior(dll, function);

        // Handle special APIs
        match function {
            "ExitProcess" | "exit" | "_exit" | "NtTerminateProcess" | "RtlExitUserProcess" => {
                // Don't actually stop — just note it
            }
            "IsDebuggerPresent" => {
                // Return 0 (no debugger)
                self.regs.eax = 0;
            }
            "GetModuleHandleA" | "GetModuleHandleW" => {
                self.regs.eax = self.image_base;
            }
            "GetCurrentProcess" => {
                self.regs.eax = 0xFFFFFFFF; // pseudo-handle
            }
            "GetCurrentProcessId" => {
                self.regs.eax = 1234;
            }
            "GetCurrentThreadId" => {
                self.regs.eax = 5678;
            }
            "GetLastError" => {
                self.regs.eax = 0; // ERROR_SUCCESS
            }
            "VirtualAlloc" | "HeapAlloc" | "malloc" | "calloc" => {
                // Return a fake allocation
                self.regs.eax = 0x00100000;
            }
            "GetProcAddress" => {
                self.behavior.dynamic_api_resolution = true;
                self.regs.eax = 0; // NULL — can't resolve dynamically
            }
            "LoadLibraryA" | "LoadLibraryW" => {
                self.behavior.dynamic_api_resolution = true;
                self.regs.eax = 0x10000000; // fake module handle
            }
            _ => {}
        }
    }

    /// Analyze API call patterns for behavioral flags.
    fn analyze_behavior(&mut self, dll: &str, function: &str) {
        let dll_lower = dll.to_ascii_lowercase();

        // Process injection detection
        if matches!(function,
            "VirtualAllocEx" | "WriteProcessMemory" | "CreateRemoteThread" |
            "NtMapViewOfSection" | "QueueUserAPC"
        ) {
            self.behavior.process_injection = true;
        }

        // Anti-debugging
        if matches!(function,
            "IsDebuggerPresent" | "CheckRemoteDebuggerPresent" |
            "NtQueryInformationProcess" | "OutputDebugStringA"
        ) {
            self.behavior.anti_debug = true;
        }

        // File access
        if matches!(function,
            "CreateFileA" | "CreateFileW" | "DeleteFileA" | "DeleteFileW" |
            "fopen" | "fopen_s" | "rename" | "remove"
        ) {
            self.behavior.file_access.push(function.to_string());
        }

        // Registry access
        if function.starts_with("Reg") {
            self.behavior.registry_access.push(function.to_string());
        }

        // Network activity
        if matches!(dll_lower.as_str(), "ws2_32" | "wsock32" | "wininet" | "winhttp") {
            self.behavior.network_activity = true;
        }

        // Crypto operations
        if matches!(dll_lower.as_str(), "bcrypt" | "ncrypt") ||
           matches!(function, "CryptEncrypt" | "CryptDecrypt" | "CryptGenKey" | "CryptDeriveKey") {
            self.behavior.crypto_ops = true;
        }
    }

    // ===== Public query methods =====

    /// Get all recorded API calls.
    pub fn api_calls(&self) -> &[ApiCallRecord] {
        &self.api_calls
    }

    /// Get the number of executed steps.
    pub fn steps(&self) -> u64 {
        self.steps
    }

    /// Get unique API call summary (DLL!Function → count).
    pub fn api_call_summary(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for call in &self.api_calls {
            let key = format!("{}!{}", call.dll, call.function);
            *counts.entry(key).or_default() += 1;
        }
        let mut result: Vec<_> = counts.into_iter().collect();
        result.sort_by(|a, b| b.1.cmp(&a.1));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_execution() {
        let mut emu = Emulator::new(1024 * 1024);
        // Simple program: XOR EAX, EAX; RET
        let code_base = 0x1000u32;
        let code = [0x31, 0xC0, 0xC3]; // xor eax, eax; ret
        emu.load_section(code_base, &code, false, true);
        let reason = emu.run(code_base);
        assert!(matches!(reason, StopReason::ReturnFromMain));
        assert_eq!(emu.regs.eax, 0);
    }

    #[test]
    fn test_push_pop() {
        let mut emu = Emulator::new(1024 * 1024);
        let code_base = 0x1000u32;
        // PUSH 42; POP EAX; RET
        let code = [0x6A, 0x2A, 0x58, 0xC3];
        emu.load_section(code_base, &code, false, true);
        let reason = emu.run(code_base);
        assert!(matches!(reason, StopReason::ReturnFromMain));
        assert_eq!(emu.regs.eax, 42);
    }

    #[test]
    fn test_api_call_detection() {
        let mut emu = Emulator::new(1024 * 1024);
        let code_base = 0x1000u32;
        let iat_addr = 0x2000u32;

        // Register IAT entry
        emu.register_iat(iat_addr, "kernel32".into(), "ExitProcess".into());

        // Write IAT pointer into memory
        let iat_slot = 0x3000u32;
        let addr_bytes = iat_addr.to_le_bytes();
        emu.load_section(iat_slot, &addr_bytes, false, false);

        // CALL [0x3000]; RET
        // FF 15 = CALL [disp32]
        let mut code = vec![0xFF, 0x15];
        code.extend_from_slice(&iat_slot.to_le_bytes());
        code.push(0xC3); // ret
        emu.load_section(code_base, &code, false, true);

        let reason = emu.run(code_base);
        assert!(matches!(reason, StopReason::ReturnFromMain));
        assert_eq!(emu.api_calls().len(), 1);
        assert_eq!(emu.api_calls()[0].function, "ExitProcess");
    }

    #[test]
    fn test_infinite_loop_detection() {
        let mut emu = Emulator::new(1024 * 1024);
        emu.set_max_steps(5000);
        let code_base = 0x1000u32;
        // JMP -2 (infinite loop)
        let code = [0xEB, 0xFE];
        emu.load_section(code_base, &code, false, true);
        let reason = emu.run(code_base);
        assert!(matches!(reason, StopReason::InfiniteLoop { .. }));
    }

    #[test]
    fn test_conditional_jump() {
        let mut emu = Emulator::new(1024 * 1024);
        let code_base = 0x1000u32;
        // XOR EAX, EAX; TEST EAX, EAX; JNZ +2; MOV EAX, 1; RET
        let code = [
            0x31, 0xC0, // xor eax, eax
            0x85, 0xC0, // test eax, eax
            0x75, 0x05, // jnz +5 (skip mov)
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0xC3,       // ret
        ];
        emu.load_section(code_base, &code, false, true);
        let reason = emu.run(code_base);
        assert!(matches!(reason, StopReason::ReturnFromMain));
        assert_eq!(emu.regs.eax, 1); // Should NOT have jumped (ZF=1 after xor)
    }
}
