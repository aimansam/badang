// Badang — API Unhooking Module
// Demonstrates API unhooking techniques for EDR evasion research
// For authorized security research only.

/// Unhooking method types
#[derive(Debug, Clone, PartialEq)]
pub enum UnhookMethod {
    DirectByte,
    Trampoline,
    InlineHook,
}

impl UnhookMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "direct" | "directbyte" | "direct_bytes" => Some(Self::DirectByte),
            "trampoline" => Some(Self::Trampoline),
            "inline" | "inlinehook" => Some(Self::InlineHook),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::DirectByte => "Direct Byte Restoration",
            Self::Trampoline => "Trampoline",
            Self::InlineHook => "Inline Hook",
        }
    }
}

/// Analyze API unhooking for a target function
pub fn analyze(func_name: &str) {
    dry_run(func_name);
}

/// Dry-run: print unhooking information
pub fn dry_run(func_name: &str) {
    eprintln!("  Target API: {}", func_name);
    eprintln!("  Technique: API Unhooking (restore original function bytes)");
    eprintln!();
    eprintln!("  What it does:");
    eprintln!("    1. Read the clean ntdll.dll from disk");
    eprintln!("    2. Parse PE to find the target function in the clean DLL");
    eprintln!("    3. Read the original function bytes from the clean DLL");
    eprintln!("    4. Compare with the in-memory version in the current process");
    eprintln!("    5. If hooked (bytes differ), restore the original bytes");
    eprintln!("    6. Use VirtualProtect to make memory writable, then write");
    eprintln!();
    eprintln!("  Commonly hooked APIs:");
    eprintln!("    - NtCreateFile, NtOpenFile");
    eprintln!("    - NtAllocateVirtualMemory");
    eprintln!("    - NtWriteVirtualMemory");
    eprintln!("    - NtCreateThreadEx");
    eprintln!("    - NtProtectVirtualMemory");
    eprintln!("    - NtMapViewOfSection");
    eprintln!("    - NtQueueApcThread");
    eprintln!("    - NtReadVirtualMemory");
    eprintln!("    - NtDeviceIoControlFile");
    eprintln!();
    eprintln!("  Detection considerations:");
    eprintln!("    - Unhooking itself is a known technique — EDRs detect it");
    eprintln!("    - Writing to ntdll.dll memory is heavily monitored");
    eprintln!("    - Some EDRs continuously re-hook functions");
    eprintln!("    - This is an arms race, not a permanent bypass");
    eprintln!("    - The mere act of reading ntdll.dll from disk can be flagged");
    eprintln!();
}

/// Print technique information
pub fn print_info() {
    eprintln!();
    eprintln!("=== API Unhooking ===");
    eprintln!();
    eprintln!("What it does:");
    eprintln!("  Restores the original (unhooked) version of an API function");
    eprintln!("  that has been modified by an EDR to insert detection hooks.");
    eprintln!();
    eprintln!("How it works:");
    eprintln!("  1. EDRs hook APIs by modifying the first N bytes of ntdll.dll");
    eprintln!("     functions in memory to jump to their callback code.");
    eprintln!("  2. The original bytes are stored elsewhere by the EDR.");
    eprintln!("  3. Badang reads the clean ntdll.dll from disk (not the in-memory one).");
    eprintln!("  4. It parses the PE to find the target function in the clean DLL.");
    eprintln!("  5. It reads the original function bytes.");
    eprintln!("  6. It compares with the in-memory version.");
    eprintln!("  7. If hooked, it overwrites the in-memory version with clean bytes.");
    eprintln!("  8. It uses VirtualProtect to make the memory writable first.");
    eprintln!();
    eprintln!("Detection considerations:");
    eprintln!("  - Unhooking is a KNOWN technique — EDRs have detection for it");
    eprintln!("  - The act of modifying ntdll.dll memory is itself a red flag");
    eprintln!("  - Many EDRs continuously monitor and re-hook ntdll.dll");
    eprintln!("  - Reading ntdll.dll from disk can be flagged as suspicious");
    eprintln!("  - This technique may work briefly but EDRs will re-hook");
    eprintln!("  - It's an arms race, not a reliable long-term bypass");
    eprintln!();
    eprintln!("Ethical note:");
    eprintln!("  API unhooking is used by malware to disable EDR detection.");
    eprintln!("  Understanding it is essential for EDR developers and defenders.");
    eprintln!();
}
