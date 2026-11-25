// Badang — API restoration module

use crate::log::LogSink;

#[derive(Debug, Clone, PartialEq)]
pub enum UnhookMethod {
    DirectByte,
    Trampoline,
    InlineHook,
}

impl UnhookMethod {
    #[allow(clippy::should_implement_trait)]
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

    log.step(format!("[RESTORE] Analyzing {} for modifications", func_name));
    log.info("");

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

    let bytes: &[u8] = unsafe { std::slice::from_raw_parts(func_addr as *const u8, 32) };

    let hex_str: String = bytes.iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    log.info(format!("  Current bytes: {}", hex_str));

    let hook = crate::analysis::detect::classify_hook(bytes);

    match hook {
        Some(hook_type) => {
            log.warning(format!("  Status: MODIFIED — {}", hook_type));
            log.info("");
            log.info("  To restore, Badang would:");
            log.detail("    1. Read clean ntdll.dll from C:\\Windows\\System32\\ntdll.dll");
            log.detail("    2. Parse PE headers to find this function's offset");
            log.detail("    3. Read the original clean bytes from disk");
            log.detail(format!("    4. Make memory writable at {:p}", func_addr));
            log.detail("    5. Overwrite modified bytes with clean bytes");
            log.detail("    6. Restore memory protection (RX)");
            log.info("");

            // Show what clean bytes should look like
            if let Some(ssn) = crate::syscall::get_syscall_number(func_name) {
                log.info("  Expected clean bytes:");
                log.detail(format!("    4c 8b d1 b8 {:02x} {:02x} {:02x} {:02x}",
                    ssn as u8, (ssn >> 8) as u8, (ssn >> 16) as u8, (ssn >> 24) as u8));
                log.detail(format!("    (mov r10, rcx; mov eax, 0x{:X})", ssn));
            }
        }
        None => {
            log.info("  Status: CLEAN — no modifications detected");
            log.info("  This function's prologue matches the expected clean pattern.");
            log.info("  No restoration needed.");

            if bytes.len() >= 8 && bytes[3] == 0xB8 {
                let ssn = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
                log.detail(format!("  SSN: 0x{:X} ({})", ssn, ssn));
            }
        }
    }

    log.info("");
}

// ----- Non-Windows stub -----
#[cfg(not(windows))]
pub fn analyze(func_name: &str, log: &LogSink) {
    log.step(format!("[RESTORE] {}", func_name));
    log.error("  Live analysis requires Windows.");
    log.info("  This binary was not compiled on Windows — only dry-run mode is available.");
    log.info("");
}

pub fn dry_run(func_name: &str, log: &LogSink) {
    log.info(format!("  Target API: {}", func_name));
    log.info("  Technique: API Restoration (restore original function bytes)");
    log.info("");
    log.detail("  What it does:");
    log.detail("    1. Read the clean ntdll.dll from disk");
    log.detail("    2. Parse PE to find the target function in the clean DLL");
    log.detail("    3. Read the original function bytes from the clean DLL");
    log.detail("    4. Compare with the in-memory version in the current process");
    log.detail("    5. If modified (bytes differ), restore the original bytes");
    log.detail("    6. Make memory writable, then write clean bytes");
    log.info("");
    log.detail("  Restores original bytes from clean copy on disk.");
    log.info("");
}

pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== API Restoration ===");
    log.info("");
    log.detail("  Restores original function bytes from clean copy.");
    log.info("");
}
