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
    log.info("[DRY RUN] PPID Management".to_string());
    log.detail(format!("  Parent: {parent}"));
    log.detail(format!("  Child: {child}"));
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail(format!("    [1/5] Resolve parent process ('{parent}')"));
    log.detail("    [2/5] Open parent process handle".to_string());
    log.detail("    [3/5] Initialize attribute list (1 attribute)".to_string());
    log.detail("    [4/5] Set parent attribute".to_string());
    log.detail(format!(
        "    [5/5] Create child process (\"{child}\")"
    ));
    log.info(String::new());
    log.detail("  The child process will appear parented by the specified process.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== Parent Attribute Management ===".to_string());
    log.info(String::new());
    log.detail("Creates a process with a specified parent attribute.".to_string());
    log.detail("Supports CREATE_SUSPENDED for combined workflows.".to_string());
}

#[cfg(windows)]
pub fn spawn(config: &PpidConfig, log: &LogSink) -> Result<PpidResult, String> {
    use std::ffi::c_void;
    use crate::resolve;

    const PROCESS_CREATE_PROCESS: u32 = 0x0080;
    const EXTENDED_STARTUPINFO_PRESENT: u32 = 0x00080000;
    const CREATE_SUSPENDED: u32 = 0x00000004;
    const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: usize = 0x00020000;

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
    struct STARTUPINFOEXW {
        startup_info: STARTUPINFOW,
        lp_attribute_list: *mut c_void,
    }

    #[repr(C)]
    struct PROCESS_INFORMATION {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    log.step(format!(
        "[1/5] Open parent process (PID {})",
        config.parent_pid
    ));
    let parent_handle = unsafe {
        resolve::OpenProcess(PROCESS_CREATE_PROCESS, 0, config.parent_pid)
    };
    if parent_handle.is_null() {
        return Err(format!("open parent PID {} failed", config.parent_pid));
    }

    log.step("[2/5] InitializeProcThreadAttributeList".to_string());
    let mut attr_size: usize = 0;
    unsafe {
        resolve::InitializeProcThreadAttributeList(
            std::ptr::null_mut(),
            1,
            0,
            &mut attr_size,
        );
    }
    if attr_size == 0 {
        unsafe { resolve::CloseHandle(parent_handle) };
        return Err("InitializeProcThreadAttributeList returned size 0".to_string());
    }

    let mut attr_buf: Vec<u8> = vec![0u8; attr_size];
    let attr_list = attr_buf.as_mut_ptr() as *mut c_void;

    let ok = unsafe {
        resolve::InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size)
    };
    if ok == 0 {
        unsafe { resolve::CloseHandle(parent_handle) };
        return Err("InitializeProcThreadAttributeList failed".to_string());
    }

    log.step("[3/5] UpdateProcThreadAttribute(PARENT_PROCESS)".to_string());
    let handle_ptr: *const *mut c_void = &parent_handle;
    let ok = unsafe {
        resolve::UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            handle_ptr as *const c_void,
            std::mem::size_of::<*mut c_void>(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe {
            resolve::DeleteProcThreadAttributeList(attr_list);
            resolve::CloseHandle(parent_handle);
        }
        return Err("UpdateProcThreadAttribute failed".to_string());
    }

    log.step(format!(
        "[4/5] Create child process (\"{}\")",
        config.child_command
    ));

    let mut si_ex: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si_ex.startup_info.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si_ex.lp_attribute_list = attr_list;

    let mut creation_flags = EXTENDED_STARTUPINFO_PRESENT;
    if config.suspended {
        creation_flags |= CREATE_SUSPENDED;
    }

    let mut child_cmd: Vec<u16> = config
        .child_command
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let result = unsafe {
        resolve::CreateProcessW(
            std::ptr::null(),
            child_cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            creation_flags,
            std::ptr::null(),
            std::ptr::null(),
            &si_ex as *const _ as *const c_void,
            &mut pi as *mut _ as *mut c_void,
        )
    };

    unsafe {
        resolve::DeleteProcThreadAttributeList(attr_list);
        resolve::CloseHandle(parent_handle);
    }

    if result == 0 {
        return Err("process creation failed".to_string());
    }

    let child_pid = pi.dw_process_id;
    let child_tid = pi.dw_thread_id;

    log.step(format!(
        "[5/5] Process created — child PID {child_pid}, TID {child_tid}"
    ));
    if config.suspended {
        log.info("  Child is SUSPENDED".to_string());
    }
    log.info(format!(
        "  Complete: child PID {child_pid} parented by PID {}",
        config.parent_pid
    ));

    unsafe {
        resolve::CloseHandle(pi.h_process);
        resolve::CloseHandle(pi.h_thread);
    }

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
