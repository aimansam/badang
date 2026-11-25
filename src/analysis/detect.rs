// Badang — Hook Detection Module
// Analyzes which APIs are hooked in a target process
// For authorized security research only.

#[allow(dead_code)]
use std::fmt;

use crate::log::LogSink;

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
    #[allow(clippy::upper_case_acronyms)]
    JMP,
    PushPop,
    INT3,
    Unknown,
}

impl fmt::Display for HookType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HookType::JMP => write!(f, "JMP hook (0xE9/0xFF)"),
            HookType::PushPop => write!(f, "PUSH/RET detour"),
            HookType::INT3 => write!(f, "INT3 breakpoint (0xCC)"),
            HookType::Unknown => write!(f, "Unknown modification"),
        }
    }
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

// Clean NT API prologue: mov r10, rcx; mov eax, <ssn>
pub fn clean_nt_prologue() -> [u8; 4] {
    crate::obf::ba(&crate::obf::SYSCALL_PROLOGUE)
}
pub const CLEAN_NT_EPILOGUE: [u8; 4] = [0x48, 0x83, 0xE4, 0xF0];

const NUM_BYTES_TO_READ: usize = 32;

fn target_apis() -> Vec<String> {
    crate::obf::API_LIST.iter().map(|enc| crate::obf::s(enc)).collect()
}

pub fn classify_hook(bytes: &[u8]) -> Option<HookType> {
    if bytes.is_empty() {
        return None;
    }
    // JMP rel32
    if bytes[0] == 0xE9 {
        return Some(HookType::JMP);
    }
    // JMP [rip+disp32] (FF 25) or JMP reg (FF Ex)
    if bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] == 0x25 || (bytes[1] & 0xF0) == 0xE0) {
        return Some(HookType::JMP);
    }
    // INT3 breakpoint
    if bytes[0] == 0xCC {
        return Some(HookType::INT3);
    }
    // PUSH addr + RET detour (0x68 ... C3) or MOV [rsp], addr + RET
    if bytes.len() >= 6 && bytes[0] == 0x68 {
        if bytes[5] == 0xC3 {
            return Some(HookType::PushPop);
        }
    }
    if bytes.len() >= 4 && bytes[..4] != clean_nt_prologue() {
        return Some(HookType::Unknown);
    }
    None
}

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

// ----- Windows live analysis -----
#[cfg(windows)]
pub fn analyze(pid: u32, log: &LogSink) {
    use std::ffi::CString;

    #[link(name = "kernel32")]
    extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut std::ffi::c_void;
        fn CloseHandle(h: *mut std::ffi::c_void) -> i32;
        fn ReadProcessMemory(
            process: *mut std::ffi::c_void,
            base: *const std::ffi::c_void,
            buffer: *mut u8,
            size: usize,
            read: *mut usize,
        ) -> i32;
        fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(
            module: *mut std::ffi::c_void,
            name: *const u8,
        ) -> *mut std::ffi::c_void;
        fn GetLastError() -> u32;
    }

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

    log.step(format!("[ANALYZE] Scanning process PID {} for API hooks", pid));
    log.info("");

    let handle = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid) };
    if handle.is_null() {
        let err = unsafe { GetLastError() };
        log.error(format!(
            "  Failed to open process {} (error {}). Check permissions.",
            pid, err
        ));
        if err == 5 {
            log.detail("  Access denied — try running as Administrator");
        }
        return;
    }

    let ntdll_name = CString::new(crate::obf::s(crate::obf::NTDLL)).unwrap();
    let ntdll = unsafe { GetModuleHandleA(ntdll_name.as_ptr() as *const u8) };
    if ntdll.is_null() {
        log.error("  Failed to get module handle");
        unsafe { CloseHandle(handle) };
        return;
    }

    let mut hooked_count = 0u32;
    let mut clean_count = 0u32;
    let mut failed_count = 0u32;

    let apis = target_apis();
    for api_name in &apis {
        let c_name = match CString::new(api_name.as_str()) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let func_addr = unsafe { GetProcAddress(ntdll, c_name.as_ptr() as *const u8) };
        if func_addr.is_null() {
            log.detail(format!("  [SKIP] {} — not found in ntdll", api_name));
            failed_count += 1;
            continue;
        }

        let mut buf = [0u8; NUM_BYTES_TO_READ];
        let mut bytes_read: usize = 0;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                func_addr as *const std::ffi::c_void,
                buf.as_mut_ptr(),
                NUM_BYTES_TO_READ,
                &mut bytes_read,
            )
        };

        if ok == 0 || bytes_read < 4 {
            let err = unsafe { GetLastError() };
            log.detail(format!(
                "  [SKIP] {} @ {:p} — read failed (error {})",
                api_name, func_addr, err
            ));
            failed_count += 1;
            continue;
        }

        let read_bytes = &buf[..bytes_read];
        let hook = classify_hook(read_bytes);

        let hex_str: String = read_bytes
            .iter()
            .take(16)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        match hook {
            Some(hook_type) => {
                hooked_count += 1;
                log.warning(format!(
                    "  [HOOKED] {} @ {:p} — {}",
                    api_name, func_addr, hook_type
                ));
                log.detail(format!("           Bytes: {}", hex_str));
            }
            None => {
                clean_count += 1;
                log.info(format!("  [CLEAN]  {} @ {:p}", api_name, func_addr));
                log.detail(format!("           Bytes: {}", hex_str));
            }
        }
    }

    unsafe { CloseHandle(handle) };

    log.info("");
    log.step("  === Summary ===");
    log.info(format!("  Scanned: {} APIs", apis.len()));
    if hooked_count > 0 {
        log.warning(format!("  Hooked:  {}", hooked_count));
    } else {
        log.info(format!("  Hooked:  {}", hooked_count));
    }
    log.info(format!("  Clean:   {}", clean_count));
    if failed_count > 0 {
        log.detail(format!("  Skipped: {}", failed_count));
    }
    log.info("");
}

// ----- Non-Windows stub -----
#[cfg(not(windows))]
pub fn analyze(pid: u32, log: &LogSink) {
    log.step(format!("[ANALYZE] Target PID: {}", pid));
    log.error("  Live hook analysis requires Windows (GetProcAddress + ReadProcessMemory).");
    log.info("  This binary was not compiled on Windows — only dry-run mode is available.");
    log.info("  Build on Windows with: cargo build --release");
    log.info("  Or cross-compile: cargo build --release --target x86_64-pc-windows-gnu");
    log.info("");
}

pub fn dry_run(pid: u32, log: &LogSink) {
    log.info(format!("  Target PID: {}", pid));
    log.info("  Technique: Hook Detection Analysis");
    log.info("");
    log.detail("  What it does:");
    log.detail("    1. Get the address of target APIs via GetProcAddress");
    log.detail("    2. Read the first N bytes of each function");
    log.detail("    3. Compare with known clean prologue patterns");
    log.detail("    4. Report which APIs are hooked and how");
    log.info("");
    log.info("  Detection:");
    log.detail("    - Clean NT API prologue: mov r10, rcx; mov eax, syscall; syscall");
    log.detail("    - Hooked functions may have: JMP, PUSH/POP, INT 3");
    log.detail("    - Some EDRs use more sophisticated hooks (multiple jumps)");
    log.detail("    - Some EDRs detect when their hooks are being enumerated");
    log.detail("    - This technique is used by BOTH attackers and defenders");
    log.info("");
}

pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== Hook Detection Analysis ===");
    log.detail("  Analyzes a target process to determine which Windows APIs");
    log.detail("  have been hooked by security software (EDR, AV, etc.).");
    log.detail("  Hook detection is a legitimate security research technique.");
    log.detail("  EDR developers use it to verify their hooks work correctly.");
    log.detail("  Red teams use it to understand what they're up against.");
    log.info("");
}
