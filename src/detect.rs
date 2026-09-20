// Badang — Hook Detection Module
// Analyzes which APIs are hooked in a target process
// For authorized security research only.

use std::fmt;

/// Hook status for an API
#[derive(Debug, Clone)]
pub struct HookStatus {
    pub api_name: String,
    pub address: usize,
    pub is_hooked: bool,
    pub hook_type: Option<HookType>,
    pub original_bytes: Option<Vec<u8>>,
    pub hooked_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum HookType {
    JMP,
    PUSH_POP,
    INT3,
    Unknown,
}

impl fmt::Display for HookStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}",
            self.api_name,
            if self.is_hooked { "HOOKED" } else { "clean" }
        )
    }
}

/// Known clean prologue patterns for common NT APIs (x64)
/// Native NT API functions typically start with:
///   4C 8B D1          mov r10, rcx
///   B8 xx xx xx xx    mov eax, syscall_number
///   0F 05             syscall
pub const CLEAN_NT_PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];

/// Known clean epilogue patterns
pub const CLEAN_NT_EPILOGUE: [u8; 4] = [0x48, 0x83, 0xE4, 0xF0]; // rsp alignment + ret

/// Check if an API is hooked by comparing bytes at its address
/// This is a simplified check — production would parse the PE properly
pub fn check_api(api_name: &str, address: usize, _num_bytes: usize) -> HookStatus {
    // In production, this would:
    // 1. Read memory at `address` for `num_bytes`
    // 2. Read clean ntdll.dll from disk
    // 3. Find the same function in the clean DLL
    // 4. Compare bytes

    // For now, this is a simulation stub
    let is_hooked = false; // Placeholder — would be determined by actual comparison

    HookStatus {
        api_name: api_name.to_string(),
        address,
        is_hooked,
        hook_type: None,
        original_bytes: None,
        hooked_bytes: None,
    }
}

/// Analyze hooked APIs in a target process
pub fn analyze(pid: u32) {
    dry_run(pid);
}
pub fn dry_run(pid: u32) {
    eprintln!("  Target PID: {}", pid);
    eprintln!("  Technique: Hook Detection Analysis");
    eprintln!();
    eprintln!("  What it does:");
    eprintln!("    1. Get the address of target APIs via GetProcAddress");
    eprintln!("    2. Read the first N bytes of each function");
    eprintln!("    3. Compare with known clean prologue patterns");
    eprintln!("    4. Report which APIs are hooked and how");
    eprintln!();
    eprintln!("  APIs to check (commonly hooked by EDRs):");
    eprintln!("    - NtCreateFile");
    eprintln!("    - NtOpenFile");
    eprintln!("    - NtAllocateVirtualMemory");
    eprintln!("    - NtWriteVirtualMemory");
    eprintln!("    - NtCreateThreadEx");
    eprintln!("    - NtProtectVirtualMemory");
    eprintln!("    - NtMapViewOfSection");
    eprintln!("    - NtQueueApcThread");
    eprintln!("    - NtReadVirtualMemory");
    eprintln!("    - NtDeviceIoControlFile");
    eprintln!();
    eprintln!("  Detection:");
    eprintln!("    - Clean NT API prologue: mov r10, rcx; mov eax, syscall; syscall");
    eprintln!("    - Hooked functions may have: JMP, PUSH/POP, INT 3");
    eprintln!("    - Some EDRs use more sophisticated hooks (multiple jumps)");
    eprintln!();
}

/// Print technique information
pub fn print_info() {
    eprintln!();
    eprintln!("=== Hook Detection Analysis ===");
    eprintln!();
    eprintln!("What it does:");
    eprintln!("  Analyzes a target process to determine which Windows APIs");
    eprintln!("  have been hooked by security software (EDR, AV, etc.).");
    eprintln!();
    eprintln!("How it works:");
    eprintln!("  1. For each target API, get its address in the process");
    eprintln!("  2. Read the first several bytes of the function");
    eprintln!("  3. Compare against known clean/hook patterns:");
    eprintln!("     - Clean NT API: starts with mov r10, rcx; mov eax, ...; syscall");
    eprintln!("     - Hooked via JMP: starts with JMP to EDR code");
    eprintln!("     - Hooked via push/pop: modifies stack to redirect");
    eprintln!("     - Hooked via INT 3: breakpoint instruction for debugger");
    eprintln!("  4. Report findings: which APIs are hooked, hook type, address");
    eprintln!();
    eprintln!("  This is a diagnostic tool — it tells you what the EDR has done,");
    eprintln!("  which is the first step in understanding how to bypass it.");
    eprintln!();
    eprintln!("Detection considerations:");
    eprintln!("  - The act of reading another process's memory can be flagged");
    eprintln!("  - GetProcAddress itself may be hooked");
    eprintln!("  - Some EDRs detect when their hooks are being enumerated");
    eprintln!("  - This technique is used by BOTH attackers and defenders");
    eprintln!();
    eprintln!("Ethical note:");
    eprintln!("  Hook detection is a legitimate security research technique.");
    eprintln!("  EDR developers use it to verify their hooks work correctly.");
    eprintln!("  Red teams use it to understand what they're up against.");
    eprintln!();
}
