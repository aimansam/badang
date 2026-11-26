use crate::log::LogSink;
use super::sandbox::CheckResult;

#[cfg(windows)]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.push(check_is_debugger_present(log));
    results.push(check_debug_port(log));
    results.push(check_debug_flags(log));
    results.push(check_timing(log));
    results
}

#[cfg(not(windows))]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    log.detail("  Process inspection requires target platform");
    vec![CheckResult {
        name: String::from("Platform"),
        detected: false,
        detail: String::from("Not on target platform"),
    }]
}

#[cfg(windows)]
fn check_is_debugger_present(log: &LogSink) -> CheckResult {
    log.step("  Checking process flags...");
    unsafe {
        let result = crate::resolve::IsDebuggerPresent();
        let detected = result != 0;
        let detail = format!("Flag value: {}", result);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Process Flag"), detected, detail }
    }
}

#[cfg(windows)]
fn check_debug_port(log: &LogSink) -> CheckResult {
    log.step("  Checking process debug port...");
    unsafe {
        let current = -1isize as *mut std::ffi::c_void; // NtCurrentProcess
        let mut port: usize = 0;
        let status = crate::resolve::NtQueryInformationProcess(
            current,
            7, // ProcessDebugPort
            &mut port as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
        let detected = status == 0 && port != 0;
        let detail = format!("Port: 0x{:X}, status: 0x{:X}", port, status as u32);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Debug Port"), detected, detail }
    }
}

#[cfg(windows)]
fn check_debug_flags(log: &LogSink) -> CheckResult {
    log.step("  Checking process debug flags...");
    unsafe {
        let current = -1isize as *mut std::ffi::c_void;
        let mut flags: u32 = 1;
        let status = crate::resolve::NtQueryInformationProcess(
            current,
            0x1F, // ProcessDebugFlags
            &mut flags as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
        );
        let detected = status == 0 && flags == 0;
        let detail = format!("Flags: 0x{:X}, status: 0x{:X}", flags, status as u32);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Debug Flags"), detected, detail }
    }
}

#[cfg(windows)]
fn check_timing(log: &LogSink) -> CheckResult {
    log.step("  Checking execution timing...");
    unsafe {
        let before = crate::resolve::GetTickCount64();
        crate::resolve::Sleep(500);
        let after = crate::resolve::GetTickCount64();
        let elapsed = after.saturating_sub(before);
        let detected = elapsed > 1500;
        let detail = format!("Expected ~500ms, measured {}ms", elapsed);
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Timing Check"), detected, detail }
    }
}
