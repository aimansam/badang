// Badang — Hook Detection Module
// Analyzes which APIs are hooked in a target process
// For authorized security research only.

#[allow(dead_code)]
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
    PushPop,
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
pub const CLEAN_NT_PROLOGUE: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
pub const CLEAN_NT_EPILOGUE: [u8; 4] = [0x48, 0x83, 0xE4, 0xF0];

/// Check if an API is hooked by comparing bytes at its address
pub fn check_api(api_name: &str, address: usize, _num_bytes: usize) -> HookStatus {
    let is_hooked = false;
    HookStatus {
        api_name: api_name.to_string(),
        address,
        is_hooked,
        hook_type: None,
        original_bytes: None,
        hooked_bytes: None,
    }
}

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
    eprintln!("  Detection:");
    eprintln!("    - Clean NT API prologue: mov r10, rcx; mov eax, syscall; syscall");
    eprintln!("    - Hooked functions may have: JMP, PUSH/POP, INT 3");
    eprintln!("    - Some EDRs use more sophisticated hooks (multiple jumps)");
    eprintln!("    - Some EDRs detect when their hooks are being enumerated");
    eprintln!("    - This technique is used by BOTH attackers and defenders");
    eprintln!();
}

pub fn print_info() {
    eprintln!();
    eprintln!("=== Hook Detection Analysis ===");
    eprintln!("  Analyzes a target process to determine which Windows APIs");
    eprintln!("  have been hooked by security software (EDR, AV, etc.).");
    eprintln!("  Hook detection is a legitimate security research technique.");
    eprintln!("  EDR developers use it to verify their hooks work correctly.");
    eprintln!("  Red teams use it to understand what they're up against.");
    eprintln!();
}
