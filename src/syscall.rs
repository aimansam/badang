// Badang — Syscall Module
// Direct syscall invocation to bypass user-mode API hooks
// For authorized security research only.

/// Known syscall numbers for common Windows versions (x64)
/// WARNING: These numbers vary by Windows version and build.
/// Never hardcode syscall numbers in production tools.
/// The syscall table changes between Windows versions.
pub const SYS_NT_CREATE_THREAD_EX: u32 = 0x5A;
pub const SYS_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x4B;
pub const SYS_NT_WRITE_VIRTUAL_MEMORY: u32 = 0x3A;
pub const SYS_NT_PROTECT_VIRTUAL_MEMORY: u32 = 0x4D;
pub const SYS_NT_MAP_VIEW_OF_SECTION: u32 = 0x5B;
pub const SYS_NT_QUEUE_APC_THREAD: u32 = 0x2B;
pub const SYS_NT_CREATE_FILE: u32 = 0x55;
pub const SYS_NT_OPEN_FILE: u32 = 0x53;
pub const SYS_NT_READ_FILE: u32 = 0x3F;
pub const SYS_NT_WRITE_FILE: u32 = 0x50;
pub const SYS_NT_DEVICE_IO_CONTROL_FILE: u32 = 0x52;
pub const SYS_NT_CLOSE: u32 = 0x0C;
pub const SYS_NT_WAIT_FOR_SINGLE_OBJECT: u32 = 0x66;

/// Syscall table mapping function names to their syscall numbers
/// across multiple Windows versions
pub struct SyscallTable {
    pub func_name: String,
    pub win7_sp1: u32,
    pub win10_1809: u32,
    pub win10_22h2: u32,
    pub win11_22h2: u32,
}

impl SyscallTable {
    pub fn new(func_name: &str, win7: u32, win10_1809: u32, win10_22h2: u32, win11: u32) -> Self {
        SyscallTable {
            func_name: func_name.to_string(),
            win7_sp1: win7,
            win10_1809,
            win10_22h2,
            win11_22h2: win11,
        }
    }

    pub fn describe(&self) {
        eprintln!("  Function: {}", self.func_name);
        eprintln!("    Windows 7 SP1:      syscall {}", self.win7_sp1);
        eprintln!("    Windows 10 1809:   syscall {}", self.win10_1809);
        eprintln!("    Windows 10 22H2:   syscall {}", self.win10_22h2);
        eprintln!("    Windows 11 22H2:   syscall {}", self.win11_22h2);
        eprintln!("    Note: syscall numbers change between versions — never hardcode");
    }
}

/// Get the syscall number for a function name (returns None if unknown)
pub fn get_syscall_number(func_name: &str) -> Option<u32> {
    match func_name {
        "NtCreateThreadEx" => Some(0x5A),
        "NtAllocateVirtualMemory" => Some(0x4B),
        "NtWriteVirtualMemory" => Some(0x3A),
        "NtProtectVirtualMemory" => Some(0x4D),
        "NtMapViewOfSection" => Some(0x5B),
        "NtQueueApcThread" => Some(0x2B),
        "NtCreateFile" => Some(0x55),
        "NtOpenFile" => Some(0x53),
        "NtReadFile" => Some(0x3F),
        "NtWriteFile" => Some(0x50),
        "NtDeviceIoControlFile" => Some(0x52),
        "NtClose" => Some(0x0C),
        "NtWaitForSingleObject" => Some(0x66),
        _ => None,
    }
}

/// Attempt to invoke a function via direct syscall
/// WARNING: This is a research/demonstration stub.
/// Real syscall invocation requires:
///   - Proper syscall number resolution per Windows version
///   - Correct argument passing (rcx, rdx, r8, r9, then stack)
///   - Handling of variadic arguments
///   - Stack alignment
pub fn invoke_syscall(func_name: &str, args: Vec<u64>) -> std::io::Result<u64> {
    let syscall_num = get_syscall_number(func_name)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "Unknown syscall"))?;

    eprintln!("[DRY RUN] Direct Syscall Invocation");
    eprintln!("  Function: {}", func_name);
    eprintln!("  Syscall number: 0x{:X}", syscall_num);
    eprintln!("  Arguments: {} (would pass via rcx, rdx, r8, r9, stack)", args.len());
    eprintln!("  Technique: Direct syscall bypasses user-mode hooks");
    eprintln!("  Detection: kernel callbacks and syscall monitoring may still detect");
    eprintln!();
    eprintln!("  How it works:");
    eprintln!("    1. Get syscall number for target function (varies by OS version)");
    eprintln!("    2. Set up registers: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4");
    eprintln!("    3. Additional args pushed on stack");
    eprintln!("    4. rax = syscall number");
    eprintln!("    5. Execute syscall instruction");
    eprintln!("    6. Return value in rax");
    eprintln!();
    eprintln!("  Why it bypasses EDR:");
    eprintln!("    - EDRs typically hook user-mode API DLLs (ntdll.dll, kernel32.dll)");
    eprintln!("    - Direct syscall skips the hooked DLL entirely");
    eprintln!("    - Goes straight from user-mode to kernel-mode");
    eprintln!("  Limitations:");
    eprintln!("    - Syscall numbers change per Windows version (must resolve dynamically)");
    eprintln!("    - Kernel callbacks still see the syscall");
    eprintln!("    - Not all functions are available via direct syscall");
    eprintln!("    - EDRs increasingly monitor syscall patterns");
    eprintln!();
    eprintln!("  Known syscall numbers (Windows 10 22H2 x64):");
    eprintln!("    NtCreateThreadEx:          0x5A");
    eprintln!("    NtAllocateVirtualMemory:   0x4B");
    eprintln!("    NtWriteVirtualMemory:      0x3A");
    eprintln!("    NtMapViewOfSection:        0x5B");
    eprintln!("    NtQueueApcThread:         0x2B");
    eprintln!("    NtCreateFile:             0x55");
    eprintln!("  WARNING: These numbers change per version! Never hardcode.");
    eprintln!();

    Ok(0)
}

/// Analyze syscall technique for dry-run mode
pub fn dry_run(func_name: &str) {
    if let Some(num) = get_syscall_number(func_name) {
        eprintln!("  Function: {}", func_name);
        eprintln!("  Syscall number: 0x{:X}", num);
    } else {
        eprintln!(
            "  Function: {} (unknown — would need dynamic resolution)",
            func_name
        );
    }
    eprintln!("  Technique: Direct syscall invocation bypasses user-mode hooks");
    eprintln!("  Detection: kernel callbacks and syscall monitoring may still detect");
    eprintln!();
    eprintln!("  How it works:");
    eprintln!(
        "    1. Resolve syscall number for target function (varies by OS version)"
    );
    eprintln!("    2. Set up arguments in registers (x64 calling convention)");
    eprintln!("       rcx=arg1, rdx=arg2, r8=arg3, r9=arg4, stack for extras");
    eprintln!("    3. Set rax = syscall number");
    eprintln!("    4. Execute syscall instruction");
    eprintln!("  Why it bypasses EDR:");
    eprintln!("    - EDRs hook user-mode DLLs (ntdll.dll, kernel32.dll)");
    eprintln!("    - Direct syscall skips the hooked DLL entirely");
    eprintln!("  Limitations:");
    eprintln!("    - Syscall numbers change per Windows version");
    eprintln!("    - Kernel callbacks still see the syscall");
    eprintln!("    - Not all functions available via direct syscall");
    eprintln!("    - EDRs increasingly monitor syscall patterns");
    eprintln!();
}

/// Analyze syscall technique for a target function
pub fn analyze(func_name: &str) {
    dry_run(func_name);
}

/// Print technique information
pub fn print_info() {
    eprintln!();
    eprintln!("=== Direct Syscall Invocation ===");
    eprintln!();
    eprintln!("What it does:");
    eprintln!("  Invokes Windows kernel functions directly via the syscall instruction,");
    eprintln!("  bypassing user-mode API hooks placed by EDR/AV in ntdll.dll.");
    eprintln!();
    eprintln!("How it works:");
    eprintln!("  1. Resolve the syscall number for the target function");
    eprintln!("     (syscall numbers vary by Windows version — must be dynamic)");
    eprintln!("  2. Set up arguments in registers (x64 calling convention)");
    eprintln!("     - rcx = first arg, rdx = second, r8 = third, r9 = fourth");
    eprintln!("     - Additional args pushed on stack");
    eprintln!("  3. Set rax = syscall number");
    eprintln!("  4. Execute syscall instruction (assembles to 0F 05)");
    eprintln!("  5. Return value comes back in rax");
    eprintln!();
    eprintln!("  This skips the entire ntdll.dll/WinAPI layer:");
    eprintln!("    User code → syscall → kernel mode (no ntdll.dll hook possible)");
    eprintln!();
    eprintln!("Why it bypasses EDR:");
    eprintln!("  - EDRs typically hook user-mode API DLLs (ntdll.dll, kernel32.dll)");
    eprintln!("  - Direct syscall skips the hooked DLL entirely");
    eprintln!("  - Goes straight from user-mode to kernel-mode");
    eprintln!();
    eprintln!("Limitations:");
    eprintln!("  - Syscall numbers change per Windows version (must resolve dynamically)");
    eprintln!("  - Kernel callbacks (ETW, callbacks) still see the syscall");
    eprintln!("  - Not all functions are available via direct syscall");
    eprintln!("  - EDRs increasingly monitor syscall patterns");
    eprintln!();
    eprintln!("Ethical note:");
    eprintln!("  Syscall invocation is a legitimate Windows programming technique.");
    eprintln!("  It's used by low-level system tools, debuggers, and security software.");
    eprintln!("  Understanding it is essential for both attackers and defenders.");
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_table() {
        assert!(get_syscall_number("NtCreateThreadEx").is_some());
        assert!(get_syscall_number("NtAllocateVirtualMemory").is_some());
        assert!(get_syscall_number("UnknownFunction").is_none());
    }

    #[test]
    fn test_syscall_numbers() {
        // Verify known syscall numbers are consistent
        assert_eq!(get_syscall_number("NtCreateThreadEx"), Some(0x5A));
        assert_eq!(get_syscall_number("NtAllocateVirtualMemory"), Some(0x4B));
        assert_eq!(get_syscall_number("NtWriteVirtualMemory"), Some(0x3A));
        assert_eq!(get_syscall_number("NtProtectVirtualMemory"), Some(0x4D));
        assert_eq!(get_syscall_number("NtMapViewOfSection"), Some(0x5B));
        assert_eq!(get_syscall_number("NtQueueApcThread"), Some(0x2B));
    }
}
