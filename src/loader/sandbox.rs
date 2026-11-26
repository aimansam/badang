use crate::log::LogSink;

pub struct CheckResult {
    pub name: String,
    pub detected: bool,
    pub detail: String,
}

pub fn is_suspicious_username(name: &str) -> bool {
    let lower = name.to_lowercase();
    ["sandbox", "malware", "virus", "test", "sample", "analyst", "cuckoo", "john doe"]
        .iter()
        .any(|&s| lower.contains(s))
}

pub fn is_suspicious_disk(total_bytes: u64) -> bool {
    total_bytes < 60 * 1024 * 1024 * 1024 // < 60 GB
}

pub fn is_suspicious_memory(total_bytes: u64) -> bool {
    total_bytes < 2 * 1024 * 1024 * 1024 // < 2 GB
}

pub fn is_suspicious_process_count(count: u32) -> bool {
    count < 50
}

#[cfg(windows)]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.push(check_sleep_acceleration(log));
    results.push(check_process_count(log));
    results.push(check_disk_size(log));
    results.push(check_username(log));
    results.push(check_memory(log));
    results
}

#[cfg(not(windows))]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    log.detail("  Environment checks require target platform");
    vec![CheckResult {
        name: String::from("Platform"),
        detected: false,
        detail: String::from("Not on target platform"),
    }]
}

#[cfg(windows)]
fn check_sleep_acceleration(log: &LogSink) -> CheckResult {
    log.step("  Checking timing consistency...");
    unsafe {
        let before = crate::resolve::GetTickCount64();
        crate::resolve::Sleep(10000);
        let after = crate::resolve::GetTickCount64();
        let elapsed = after.saturating_sub(before);
        let detected = elapsed < 9000;
        let detail = format!("Expected ~10000ms, measured {}ms", elapsed);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Timing"), detected, detail }
    }
}

#[cfg(windows)]
fn check_process_count(log: &LogSink) -> CheckResult {
    log.step("  Checking running process count...");
    let procs = crate::process::scan(log);
    let count = procs.len() as u32;
    let detected = is_suspicious_process_count(count);
    let detail = format!("{} processes (threshold: 50)", count);
    log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
    CheckResult { name: String::from("Process Count"), detected, detail }
}

#[cfg(windows)]
fn check_disk_size(log: &LogSink) -> CheckResult {
    log.step("  Checking disk capacity...");
    unsafe {
        let mut total: u64 = 0;
        let path = b"C:\\\0";
        crate::resolve::GetDiskFreeSpaceExA(
            path.as_ptr(),
            std::ptr::null_mut(),
            &mut total,
            std::ptr::null_mut(),
        );
        let gb = total / (1024 * 1024 * 1024);
        let detected = is_suspicious_disk(total);
        let detail = format!("{}GB total (threshold: 60GB)", gb);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Disk Size"), detected, detail }
    }
}

#[cfg(windows)]
fn check_username(log: &LogSink) -> CheckResult {
    log.step("  Checking current user...");
    unsafe {
        let mut buf = [0u8; 256];
        let mut size: u32 = buf.len() as u32;
        crate::resolve::GetUserNameA(buf.as_mut_ptr(), &mut size);
        let name = String::from_utf8_lossy(&buf[..size.saturating_sub(1) as usize]).to_string();
        let detected = is_suspicious_username(&name);
        let detail = format!("User: {}", name);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Username"), detected, detail }
    }
}

#[cfg(windows)]
fn check_memory(log: &LogSink) -> CheckResult {
    log.step("  Checking physical memory...");
    unsafe {
        #[repr(C)]
        struct MemoryStatusEx {
            length: u32,
            memory_load: u32,
            total_phys: u64,
            avail_phys: u64,
            total_page_file: u64,
            avail_page_file: u64,
            total_virtual: u64,
            avail_virtual: u64,
            avail_extended_virtual: u64,
        }
        let mut status = std::mem::zeroed::<MemoryStatusEx>();
        status.length = std::mem::size_of::<MemoryStatusEx>() as u32;
        crate::resolve::GlobalMemoryStatusEx(&mut status as *mut _ as *mut std::ffi::c_void);
        let gb = status.total_phys / (1024 * 1024 * 1024);
        let detected = is_suspicious_memory(status.total_phys);
        let detail = format!("{}GB RAM (threshold: 2GB)", gb);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Memory"), detected, detail }
    }
}
