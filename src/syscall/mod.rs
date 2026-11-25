// Badang — Syscall Module

pub mod indirect;

use crate::log::LogSink;

#[allow(dead_code)]
pub const SYS_NT_CREATE_THREAD_EX: u32 = 0x5A;
pub const SYS_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x4B;
pub const SYS_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x3A;
pub const SYS_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x4D;
pub const SYS_NT_MAP_VIEW_OF_SECTION: u32 = 0x5B;
pub const SYS_NT_QUEUE_APC_THREAD: u32 = 0x2B;
pub const SYS_NT_CREATE_FILE: u32 = 0x55;
pub const SYS_NT_OPEN_FILE: u32 = 0x53;
pub const SYS_NT_READ_FILE: u32 = 0x3F;
pub const SYS_NT_WRITE_FILE: u32 = 0x50;
pub const SYS_NT_DEVICE_IO_CONTROL_FILE: u32 = 0x52;
pub const SYS_NT_CLOSE: u32 = 0x0C;
pub const SYS_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x66;

pub struct SyscallTable {
    pub func_name: String,
    pub win7_sp1: u32,
    pub win10_1809: u32,
    pub win10_22h2: u32,
    pub win11_22h2: u32,
}

impl SyscallTable {
    pub fn new(func_name: &str, win7: u32, win10_1809: u32, win10_22h2: u32, win11: u32) -> Self {
        SyscallTable {
            func_name: func_name.to_string(),
            win7_sp1: win7,
            win10_1809,
            win10_22h2,
            win11_22h2: win11,
        }
    }

    pub fn describe(&self, log: &LogSink) {
        log.info(format!("  Function: {}", self.func_name));
        log.detail(format!("    Windows 7 SP1:      syscall {}", self.win7_sp1));
        log.detail(format!(
            "    Windows 10 1809:   syscall {}",
            self.win10_1809
        ));
        log.detail(format!(
            "    Windows 10 22H2:   syscall {}",
            self.win10_22h2
        ));
        log.detail(format!(
            "    Windows 11 22H2:   syscall {}",
            self.win11_22h2
        ));
        log.warning("    Note: syscall numbers change between versions — never hardcode");
    }
}

pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    use crate::obf;
    let table: &[(&[u8], u32)] = &[
        (obf::NT_CREATE_THREAD, 0x5A),
        (obf::NT_ALLOC_VM, 0x4B),
        (obf::NT_WRITE_VM, 0x3A),
        (obf::NT_PROTECT_VM, 0x4D),
        (obf::NT_MAP_VIEW, 0x5B),
        (obf::NT_QUEUE_APC, 0x2B),
        (obf::NT_CREATE_FILE, 0x55),
        (obf::NT_OPEN_FILE, 0x53),
        (obf::NT_READ_FILE, 0x3F),
        (obf::NT_WRITE_FILE, 0x50),
        (obf::NT_DEVICE_IO, 0x52),
        (obf::NT_CLOSE, 0x0C),
        (obf::NT_WAIT, 0x66),
    ];
    table.iter()
        .find(|(enc, _)| obf::s(enc) == func_name)
        .map(|(_, ssn)| *ssn)
}

pub fn invoke_syscall(func_name: &str, args: Vec<u64>, log: &LogSink) -> std::io::Result<u64> {
    let syscall_num = get_syscall_number(func_name)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Unknown syscall"))?;

    log.step("[DRY RUN] Direct Syscall Invocation");
    log.info(format!("  Function: {}", func_name));
    log.info(format!("  Syscall number: 0x{:X}", syscall_num));
    log.info(format!(
        "  Arguments: {} (would pass via rcx, rdx, r8, r9, stack)",
        args.len()
    ));
    log.info("  Technique: Direct syscall invocation");
    log.detail("  Note: kernel callbacks may still observe");
    log.info("");

    Ok(0)
}

pub fn dry_run(func_name: &str, log: &LogSink) {
    if let Some(num) = get_syscall_number(func_name) {
        log.info(format!("  Function: {}", func_name));
        log.info(format!("  Syscall number: 0x{:X}", num));
    } else {
        log.info(format!(
            "  Function: {} (unknown — would need dynamic resolution)",
            func_name
        ));
    }
    log.info("  Technique: Direct syscall invocation");
    log.detail("  Steps: resolve SSN → set registers → execute syscall instruction");
    log.info("");
}

// ----- Windows live analysis -----
#[cfg(windows)]
pub fn analyze(func_name: &str, log: &LogSink) {
    use std::ffi::CString;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(
            module: *mut std::ffi::c_void,
            name: *const u8,
        ) -> *mut std::ffi::c_void;
    }

    log.step(format!("[SYSCALL] Analyzing {} for direct invocation", func_name));
    log.info("");

    let ssn = match get_syscall_number(func_name) {
        Some(n) => n,
        None => {
            log.error(format!("  Unknown function: {} — not in SSN table", func_name));
            return;
        }
    };

    log.info(format!("  SSN (from table): 0x{:X} ({})", ssn, ssn));

    // Resolve the actual function address from ntdll to read its bytes
    let ntdll_name = CString::new(crate::obf::s(crate::obf::NTDLL)).unwrap();
    let ntdll = unsafe { GetModuleHandleA(ntdll_name.as_ptr() as *const u8) };
    if ntdll.is_null() {
        log.error("  Failed to get module handle");
        return;
    }

    let c_name = match CString::new(func_name) {
        Ok(n) => n,
        Err(_) => {
            log.error("  Invalid function name");
            return;
        }
    };
    let func_addr = unsafe { GetProcAddress(ntdll, c_name.as_ptr() as *const u8) };
    if func_addr.is_null() {
        log.error(format!("  {} not found in ntdll.dll", func_name));
        return;
    }

    log.info(format!("  Address: {:p}", func_addr));

    // Read the function bytes directly (our own process, no ReadProcessMemory needed)
    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(func_addr as *const u8, 32) };

    let hex_str: String = bytes.iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    log.info(format!("  Bytes: {}", hex_str));

    // Extract the SSN from the actual bytes (at offset 4, after mov r10,rcx; mov eax,)
    if bytes.len() >= 8 && bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8 {
        let live_ssn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        log.info(format!("  SSN (from memory): 0x{:X} ({})", live_ssn, live_ssn));

        if live_ssn == ssn {
            log.info("  Status: SSN matches table — table is correct for this OS version");
        } else {
            log.warning(format!(
                "  Status: SSN MISMATCH — table says 0x{:X}, memory says 0x{:X}",
                ssn, live_ssn
            ));
            log.warning("  The live SSN from memory is the correct one for this OS version");
        }

        log.info("");
        log.info("  Direct syscall stub (ready to use):");
        log.detail(format!("    mov r10, rcx          ; 4C 8B D1"));
        log.detail(format!("    mov eax, 0x{:X}        ; B8 {:02X} {:02X} {:02X} {:02X}",
            live_ssn, bytes[4], bytes[5], bytes[6], bytes[7]));
        log.detail(format!("    syscall               ; 0F 05"));
        log.detail(format!("    ret                   ; C3"));
    } else {
        let hook = crate::analysis::detect::classify_hook(bytes);
        match hook {
            Some(hook_type) => {
                log.warning(format!("  MODIFIED — {} detected at function entry", hook_type));
                log.warning("  Cannot extract SSN from modified bytes");
                log.info("  Options:");
                log.detail("    1. Restore the function first, then read the SSN");
                log.detail("    2. Use the SSN from the table (may not match this OS version)");
                log.detail("    3. Read SSN from ntdll.dll on disk (always clean)");
            }
            None => {
                log.info("  Function prologue doesn't match expected pattern");
            }
        }
    }

    log.info("");
}

// ----- Non-Windows stub -----
#[cfg(not(windows))]
pub fn analyze(func_name: &str, log: &LogSink) {
    log.step(format!("[SYSCALL] {}", func_name));
    log.error("  Live syscall analysis requires Windows.");
    log.info("  This binary was not compiled on Windows — only dry-run mode is available.");
    log.info("");
}

pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== Direct Syscall Invocation ===");
    log.info("");
    log.detail("  Invokes kernel functions directly via the syscall instruction.");
    log.info("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_table() {
        assert!(get_syscall_number("NtCreateThreadEx").is_some());
        assert!(get_syscall_number("NtAllocateVirtualMemory").is_some());
        assert!(get_syscall_number("UnknownFunction").is_none());
    }

    #[test]
    fn test_syscall_numbers() {
        assert_eq!(get_syscall_number("NtCreateThreadEx"), Some(0x5A));
        assert_eq!(get_syscall_number("NtAllocateVirtualMemory"), Some(0x4B));
        assert_eq!(get_syscall_number("NtWriteVirtualMemory"), Some(0x3A));
        assert_eq!(get_syscall_number("NtProtectVirtualMemory"), Some(0x4D));
        assert_eq!(get_syscall_number("NtMapViewOfSection"), Some(0x5B));
        assert_eq!(get_syscall_number("NtQueueApcThread"), Some(0x2B));
    }
}
