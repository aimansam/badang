use crate::log::LogSink;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

#[cfg(windows)]
pub fn scan(log: &LogSink) -> Vec<ProcessInfo> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    };

    log.step("[SCAN] Enumerating running processes...");

    let snapshot = match unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) } {
        Ok(h) => h,
        Err(e) => {
            log.error(format!("CreateToolhelp32Snapshot failed: {e}"));
            return Vec::new();
        }
    };

    let mut entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut processes = Vec::new();

    if unsafe { Process32First(snapshot, &mut entry) }.is_ok() {
        loop {
            let name = entry
                .szExeFile
                .iter()
                .take_while(|&&c| c != 0)
                .map(|&c| c as u8 as char)
                .collect::<String>();

            processes.push(ProcessInfo {
                pid: entry.th32ProcessID,
                name,
            });

            if unsafe { Process32Next(snapshot, &mut entry) }.is_err() {
                break;
            }
        }
    }

    let _: Result<(), _> = unsafe { CloseHandle(snapshot) };

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
