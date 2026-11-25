use crate::log::LogSink;

pub struct ExportEntry {
    pub name: String,
    pub rva: u32,
    pub ordinal: u16,
}

pub struct TextSection {
    pub base: usize,
    pub size: usize,
}

#[cfg(windows)]
pub fn get_module_base(dll: &str) -> Result<*const u8, String> {
    use std::ffi::CString;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleA(name: *const u8) -> *mut std::ffi::c_void;
    }

    let c_name = CString::new(dll).map_err(|_| format!("invalid DLL name: {dll}"))?;
    let handle = unsafe { GetModuleHandleA(c_name.as_ptr() as *const u8) };
    if handle.is_null() {
        return Err(format!("{dll} not loaded in current process"));
    }
    Ok(handle as *const u8)
}

#[cfg(windows)]
pub fn parse_exports(base: *const u8, log: &LogSink) -> Result<Vec<ExportEntry>, String> {
    unsafe {
        let dos_e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let pe = base.add(dos_e_lfanew);

        let sig = *(pe as *const u32);
        if sig != 0x0000_4550 {
            return Err("invalid PE signature".to_string());
        }

        let optional_header = pe.add(24);
        let magic = *(optional_header as *const u16);
        let export_dir_rva_offset: usize = if magic == 0x20B { 112 } else { 96 };

        let export_rva =
            *(optional_header.add(export_dir_rva_offset) as *const u32) as usize;
        let export_size =
            *(optional_header.add(export_dir_rva_offset + 4) as *const u32) as usize;

        if export_rva == 0 || export_size == 0 {
            return Err("no export directory".to_string());
        }

        let export_dir = base.add(export_rva);
        let num_names = *(export_dir.add(24) as *const u32) as usize;
        let addr_table_rva = *(export_dir.add(28) as *const u32) as usize;
        let name_table_rva = *(export_dir.add(32) as *const u32) as usize;
        let ordinal_table_rva = *(export_dir.add(36) as *const u32) as usize;
        let ordinal_base = *(export_dir.add(16) as *const u32) as u16;

        let addr_table = base.add(addr_table_rva) as *const u32;
        let name_table = base.add(name_table_rva) as *const u32;
        let ordinal_table = base.add(ordinal_table_rva) as *const u16;

        log.detail(format!("  PE exports: {num_names} named functions"));

        let mut entries = Vec::with_capacity(num_names);
        for i in 0..num_names {
            let name_rva = *name_table.add(i) as usize;
            let name_ptr = base.add(name_rva);
            let name = std::ffi::CStr::from_ptr(name_ptr as *const i8)
                .to_string_lossy()
                .into_owned();
            let ordinal_index = *ordinal_table.add(i) as usize;
            let func_rva = *addr_table.add(ordinal_index);
            entries.push(ExportEntry {
                name,
                rva: func_rva,
                ordinal: ordinal_base.wrapping_add(ordinal_index as u16),
            });
        }
        Ok(entries)
    }
}

#[cfg(windows)]
pub fn find_text_section(base: *const u8) -> Result<TextSection, String> {
    unsafe {
        let dos_e_lfanew = *(base.add(0x3C) as *const u32) as usize;
        let pe = base.add(dos_e_lfanew);

        let num_sections = *(pe.add(6) as *const u16) as usize;
        let optional_header_size = *(pe.add(20) as *const u16) as usize;
        let first_section = pe.add(24 + optional_header_size);

        for i in 0..num_sections {
            let section = first_section.add(i * 40);
            let mut name_buf = [0u8; 8];
            std::ptr::copy_nonoverlapping(section, name_buf.as_mut_ptr(), 8);
            let name = std::str::from_utf8(&name_buf)
                .unwrap_or("")
                .trim_end_matches('\0');
            if name == ".text" {
                let virtual_size = *(section.add(8) as *const u32) as usize;
                let virtual_address = *(section.add(12) as *const u32) as usize;
                return Ok(TextSection {
                    base: base as usize + virtual_address,
                    size: virtual_size,
                });
            }
        }
        Err("no .text section found".to_string())
    }
}

#[cfg(windows)]
pub fn scan_for_pattern(region_base: usize, region_size: usize, pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || region_size < pattern.len() {
        return Vec::new();
    }
    let mut results = Vec::new();
    let slice = unsafe { std::slice::from_raw_parts(region_base as *const u8, region_size) };
    for i in 0..=(region_size - pattern.len()) {
        if &slice[i..i + pattern.len()] == pattern {
            results.push(region_base + i);
        }
    }
    results
}

#[cfg(windows)]
pub fn find_export_address(base: *const u8, func_name: &str, log: &LogSink) -> Result<*const u8, String> {
    let exports = parse_exports(base, log)?;
    for entry in &exports {
        if entry.name == func_name {
            return Ok(unsafe { base.add(entry.rva as usize) });
        }
    }
    Err(format!("{func_name} not found in export table"))
}

#[cfg(not(windows))]
pub fn get_module_base(_dll: &str) -> Result<*const u8, String> {
    Err("PE parsing requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn parse_exports(_base: *const u8, _log: &LogSink) -> Result<Vec<ExportEntry>, String> {
    Err("PE parsing requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn find_text_section(_base: *const u8) -> Result<TextSection, String> {
    Err("PE parsing requires Windows".to_string())
}

#[cfg(not(windows))]
pub fn scan_for_pattern(_base: usize, _size: usize, _pattern: &[u8]) -> Vec<usize> {
    Vec::new()
}

#[cfg(not(windows))]
pub fn find_export_address(_base: *const u8, _func_name: &str, _log: &LogSink) -> Result<*const u8, String> {
    Err("PE parsing requires Windows".to_string())
}
