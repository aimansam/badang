use crate::log::LogSink;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[cfg(windows)]
pub fn scan(log: &LogSink) -> Vec<ProcessInfo> {
    use crate::resolve;

    const TH32CS_SNAPPROCESS: u32 = 0x00000002;
    const MAX_PATH: usize = 260;

    #[repr(C)]
    struct PROCESSENTRY32 {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u8; MAX_PATH],
    }

    log.step("[SCAN] Enumerating running processes...");

    let snapshot = unsafe { resolve::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    let invalid_handle = -1isize as *mut std::ffi::c_void;
    if snapshot.is_null() || snapshot == invalid_handle {
        log.error("CreateToolhelp32Snapshot failed");
        return Vec::new();
    }

    let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
    entry.dw_size = std::mem::size_of::<PROCESSENTRY32>() as u32;

    let mut processes = Vec::new();

    if unsafe { resolve::Process32First(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } != 0 {
        loop {
            let name = entry
                .sz_exe_file
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as char)
                .collect::<String>();

            processes.push(ProcessInfo {
                pid: entry.th32_process_id,
                name,
            });

            if unsafe { resolve::Process32Next(snapshot, &mut entry as *mut _ as *mut std::ffi::c_void) } == 0 {
                break;
            }
        }
    }

    unsafe { resolve::CloseHandle(snapshot) };

    processes.sort_by_key(|p| p.pid);
    log.info(format!("  Found {} processes", processes.len()));
    processes
}

#[cfg(not(windows))]
pub fn scan(log: &LogSink) -> Vec<ProcessInfo> {
    log.step("[SCAN] Enumerating running processes...");

    let mut processes = Vec::new();
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => {
            log.error("  Cannot read /proc — process scanning not available on this platform");
            return processes;
        }
    };

    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if let Ok(pid) = name_str.parse::<u32>() {
            let comm_path = format!("/proc/{}/comm", pid);
            let proc_name = std::fs::read_to_string(&comm_path)
                .unwrap_or_default()
                .trim()
                .to_string();
            if !proc_name.is_empty() {
                processes.push(ProcessInfo {
                    pid,
                    name: proc_name,
                });
            }
        }
    }

    processes.sort_by_key(|p| p.pid);
    log.info(format!("  Found {} processes", processes.len()));
    processes
}

pub fn print_table(processes: &[ProcessInfo], log: &LogSink) {
    log.info(format!("  {:<8} {}", "PID", "NAME"));
    log.info(format!("  {:<8} {}", "---", "----"));
    for p in processes {
        log.info(format!("  {:<8} {}", p.pid, p.name));
    }
}

pub fn scan_and_print(log: &LogSink) {
    let processes = scan(log);
    if !processes.is_empty() {
        log.info("");
        print_table(&processes, log);
    }
}

pub fn filter(processes: &[ProcessInfo], query: &str) -> Vec<ProcessInfo> {
    let q = query.to_lowercase();
    processes
        .iter()
        .filter(|p| p.name.to_lowercase().contains(&q))
        .cloned()
        .collect()
}
