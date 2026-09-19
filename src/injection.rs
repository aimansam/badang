// Badang — Process Injection Module
// Demonstrates process injection techniques for EDR evasion research
// For authorized security research only.

/// Injection technique types
pub enum InjectionTechnique {
    CreateRemoteThread,
    APC,
    ThreadHijack,
}

impl InjectionTechnique {
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

/// Analyze injection technique for a target
pub fn analyze(technique: &str) {
    dry_run(0, technique);
}

/// Dry-run: print technique information
pub fn dry_run(pid: u32, technique: &str) {
    if let Some(t) = InjectionTechnique::from_str(technique) {
        eprintln!("  Target PID: {}", pid);
        eprintln!("  Technique: {}", t.name());

        match t {
            InjectionTechnique::CreateRemoteThread => {
                eprintln!("  Steps:");
                eprintln!("    1. OpenProcess (PROCESS_ALL_ACCESS) on target PID");
                eprintln!("    2. NtAllocateVirtualMemory / VirtualAllocEx in target process");
                eprintln!("    3. NtWriteVirtualMemory / WriteProcessMemory to write payload");
                eprintln!("    4. NtProtectVirtualMemory to set PAGE_EXECUTE_READ");
                eprintln!("    5. NtCreateThreadEx / CreateRemoteThread to execute");
                eprintln!("    6. WaitForSingleObject to wait for completion");
                eprintln!();
                eprintln!("  Detection:");
                eprintln!("    - ALL of these APIs are heavily hooked by EDRs");
                eprintln!("    - RWX memory pages are a major indicator");
                eprintln!("    - Cross-process memory writes are monitored");
                eprintln!("    - Remote thread creation is a key indicator");
            }
            InjectionTechnique::APC => {
                eprintln!("  Steps:");
                eprintln!("    1. OpenProcess on target PID");
                eprintln!("    2. Allocate + write memory in target");
                eprintln!("    3. Enumerate threads via NtGetNextThread / Thread32First");
                eprintln!("    4. Queue APC to target thread via NtQueueApcThread");
                eprintln!("    5. APC executes when thread enters alertable state");
                eprintln!();
                eprintln!("  Detection:");
                eprintln!("    - APC queue manipulation is monitored");
                eprintln!("    - Thread enumeration across processes is flagged");
                eprintln!("    - Memory allocation + write + APC queue = strong signal");
            }
            InjectionTechnique::ThreadHijack => {
                eprintln!("  Steps:");
                eprintln!("    1. OpenProcess on target PID");
                eprintln!("    2. SuspendThread on target thread");
                eprintln!("    3. Allocate + write memory in target");
                eprintln!("    4. SetThreadContext to redirect thread to injected code");
                eprintln!("    5. ResumeThread to execute");
                eprintln!();
                eprintln!("  Detection:");
                eprintln!("    - Thread suspension + context modification is monitored");
                eprintln!("    - Suspended threads are a known indicator");
                eprintln!("    - Memory write + context change = strong signal");
            }
        }
    } else {
        eprintln!("  Unknown technique: {}", technique);
        eprintln!("  Known techniques: createremote, apc, hijack");
    }
}

/// Print technique information
pub fn print_info() {
    eprintln!();
    eprintln!("=== Process Injection Techniques ===");
    eprintln!();
    eprintln!("What it does:");
    eprintln!("  Inserts code into another process's address space and executes it.");
    eprintln!("  This is a fundamental technique for malware, red teams, and");
    eprintln!("  security research. EDRs detect this through API hooking and");
    eprintln!("  behavioral analysis.");
    eprintln!();
    eprintln!("Techniques implemented:");
    eprintln!("  1. CreateRemoteThread");
    eprintln!("     - Classic remote thread creation via NtCreateThreadEx");
    eprintln!("     - Allocate memory in target, write payload, execute");
    eprintln!("     - Heavily detected — almost all EDRs hook these APIs");
    eprintln!();
    eprintln!("  2. APC Injection");
    eprintln!("     - Queue an APC to a target thread");
    eprintln!("     - Code executes when thread enters alertable state");
    eprintln!("     - Also heavily monitored");
    eprintln!();
    eprintln!("  3. Thread Hijack (SetThreadContext)");
    eprintln!("     - Suspend a thread, modify its context to point to injected code");
    eprintln!("     - Resume thread to execute");
    eprintln!("     - Suspended thread manipulation is monitored");
    eprintln!();
    eprintln!("Detection considerations:");
    eprintln!("  - All these techniques are WELL KNOWN to EDR vendors");
    eprintln!("  - Modern EDRs hook the underlying NT APIs");
    eprintln!("  - Behavioral analysis looks for the injection pattern");
    eprintln!("  - RWX memory pages are a major red flag");
    eprintln!("  - Cross-process operations are heavily monitored");
    eprintln!("  - This is an arms race — techniques evolve, EDRs adapt");
    eprintln!();
    eprintln!("Ethical note:");
    eprintln!("  These techniques are used by malware AND by security researchers.");
    eprintln!("  Understanding them is essential for defense. Use responsibly.");
    eprintln!();
}
