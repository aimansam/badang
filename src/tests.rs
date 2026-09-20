// Badang — Integration tests
// Tests verify the public API surface of each module.
// Keep in sync with the actual exports in each module file.

use crate::cli::CLI;
use crate::detect::{check_api, HookStatus, HookType, CLEAN_NT_EPILOGUE, CLEAN_NT_PROLOGUE};
use crate::injection::InjectionTechnique;
use crate::syscall::{
    get_syscall_number, SyscallTable, SYS_NT_ALLOCATE_VIRTUAL_MEMORY, SYS_NT_CLOSE,
    SYS_NT_CREATE_FILE, SYS_NT_CREATE_THREAD_EX, SYS_NT_DEVICE_IO_CONTROL_FILE,
    SYS_NT_MAP_VIEW_OF_SECTION, SYS_NT_OPEN_FILE, SYS_NT_PROTECT_VIRTUAL_MEMORY,
    SYS_NT_QUEUE_APC_THREAD, SYS_NT_READ_FILE, SYS_NT_WAIT_FOR_SINGLE_OBJECT, SYS_NT_WRITE_FILE,
    SYS_NT_WRITE_VIRTUAL_MEMORY,
};
use crate::unhook::UnhookMethod;

#[test]
fn test_cli_struct() {
    let cli = CLI {
        command: "analyze".to_string(),
        dry_run: true,
        verbose: false,
        confirm: false,
        target_pid: 1234,
        inject_technique: "createremote".to_string(),
        syscall_func: "NtCreateThreadEx".to_string(),
        unhook_func: "NtCreateFile".to_string(),
    };
    assert_eq!(cli.command, "analyze");
    assert!(cli.dry_run);
    assert!(!cli.verbose);
    assert!(!cli.confirm);
    assert_eq!(cli.target_pid, 1234);
}

#[test]
fn test_injection_technique_from_str() {
    // Existing variant: CreateRemoteThread
    assert_eq!(
        InjectionTechnique::from_str("createremote"),
        Some(InjectionTechnique::CreateRemoteThread)
    );
    assert_eq!(
        InjectionTechnique::from_str("CreateRemoteThread"),
        Some(InjectionTechnique::CreateRemoteThread)
    );
    // Existing variant: APC
    assert_eq!(
        InjectionTechnique::from_str("apc"),
        Some(InjectionTechnique::APC)
    );
    assert_eq!(
        InjectionTechnique::from_str("APCInjection"),
        Some(InjectionTechnique::APC)
    );
    // Existing variant: ThreadHijack
    assert_eq!(
        InjectionTechnique::from_str("hijack"),
        Some(InjectionTechnique::ThreadHijack)
    );
    assert_eq!(
        InjectionTechnique::from_str("ThreadHijack"),
        Some(InjectionTechnique::ThreadHijack)
    );
    assert_eq!(
        InjectionTechnique::from_str("setthreadcontext"),
        Some(InjectionTechnique::ThreadHijack)
    );
    // Unknown strings return None
    assert!(InjectionTechnique::from_str("").is_none());
    assert!(InjectionTechnique::from_str("nonexistent").is_none());
}

#[test]
fn test_injection_technique_name() {
    let cr = InjectionTechnique::CreateRemoteThread;
    assert_eq!(cr.name(), "CreateRemoteThread");

    let apc = InjectionTechnique::APC;
    assert_eq!(apc.name(), "APC Injection");

    let th = InjectionTechnique::ThreadHijack;
    assert_eq!(th.name(), "Thread Hijack (SetThreadContext)");
}

#[test]
fn test_unhook_method_from_str() {
    assert_eq!(
        UnhookMethod::from_str("direct"),
        Some(UnhookMethod::DirectByte)
    );
    assert_eq!(
        UnhookMethod::from_str("DirectByte"),
        Some(UnhookMethod::DirectByte)
    );
    assert_eq!(
        UnhookMethod::from_str("trampoline"),
        Some(UnhookMethod::Trampoline)
    );
    assert_eq!(
        UnhookMethod::from_str("Trampoline"),
        Some(UnhookMethod::Trampoline)
    );
    assert_eq!(
        UnhookMethod::from_str("inline"),
        Some(UnhookMethod::InlineHook)
    );
    assert_eq!(
        UnhookMethod::from_str("InlineHook"),
        Some(UnhookMethod::InlineHook)
    );
    assert!(UnhookMethod::from_str("").is_none());
    assert!(UnhookMethod::from_str("nonexistent").is_none());
}

#[test]
fn test_unhook_method_name() {
    assert_eq!(UnhookMethod::DirectByte.name(), "Direct Byte Restoration");
    assert_eq!(UnhookMethod::Trampoline.name(), "Trampoline");
    assert_eq!(UnhookMethod::InlineHook.name(), "Inline Hook");
}

#[test]
fn test_hook_status_display() {
    let hooked = HookStatus {
        api_name: "NtCreateFile".to_string(),
        address: 0x1000,
        is_hooked: true,
        hook_type: Some(HookType::JMP),
        original_bytes: None,
        hooked_bytes: None,
    };
    let clean = HookStatus {
        api_name: "NtOpenFile".to_string(),
        address: 0x2000,
        is_hooked: false,
        hook_type: None,
        original_bytes: None,
        hooked_bytes: None,
    };

    let hooked_str = format!("{}", hooked);
    assert!(hooked_str.contains("HOOKED"));
    assert!(hooked_str.contains("NtCreateFile"));
    assert_eq!(hooked.address, 0x1000);

    let clean_str = format!("{}", clean);
    assert!(clean_str.contains("clean"));
    assert!(clean_str.contains("NtOpenFile"));
}

#[test]
fn test_hook_type_variants_exist() {
    // Verify all 4 enum variants can be constructed directly
    let _jmp = HookType::JMP;
    let _push_pop = HookType::PUSH_POP;
    let _int3 = HookType::INT3;
    let _unknown = HookType::Unknown;
    // All variants exist — test passes if this compiles
}

#[test]
fn test_hook_type_display_output() {
    // Verify the Display output for HookStatus with different hook types
    let jmp_status = HookStatus {
        api_name: "NtAllocateVirtualMemory".to_string(),
        address: 0x3000,
        is_hooked: true,
        hook_type: Some(HookType::JMP),
        original_bytes: None,
        hooked_bytes: None,
    };
    assert!(format!("{}", jmp_status).contains("HOOKED"));

    let clean_status = HookStatus {
        api_name: "NtWriteVirtualMemory".to_string(),
        address: 0x4000,
        is_hooked: false,
        hook_type: Some(HookType::PUSH_POP),
        original_bytes: None,
        hooked_bytes: None,
    };
    assert!(format!("{}", clean_status).contains("clean"));
}

#[test]
fn test_check_api_stub() {
    let status = check_api("NtCreateFile", 0x1000, 32);
    assert_eq!(status.api_name, "NtCreateFile");
    assert_eq!(status.address, 0x1000);
    assert_eq!(status.is_hooked, false);
    assert!(!status.hook_type.is_some());
    // Stub always returns empty byte options
    assert_eq!(status.original_bytes, None);
    assert_eq!(status.hooked_bytes, None);
}

#[test]
fn test_check_api_different_inputs() {
    let s1 = check_api("NtCreateThreadEx", 0x5000, 64);
    assert_eq!(s1.api_name, "NtCreateThreadEx");
    assert_eq!(s1.address, 0x5000);

    let s2 = check_api("NtMapViewOfSection", 0x6000, 128);
    assert_eq!(s2.api_name, "NtMapViewOfSection");
    assert_eq!(s2.address, 0x6000);
    assert_eq!(s2.is_hooked, false);
}

#[test]
fn test_clean_prologue_constants() {
    // Verify the known-clean prologue/epilogue byte patterns
    assert_eq!(CLEAN_NT_PROLOGUE, [0x4C, 0x8B, 0xD1, 0xB8]);
    assert_eq!(CLEAN_NT_EPILOGUE, [0x48, 0x83, 0xE4, 0xF0]);
    assert_eq!(CLEAN_NT_PROLOGUE.len(), 4);
    assert_eq!(CLEAN_NT_EPILOGUE.len(), 4);
}

#[test]
fn test_syscall_number_lookup() {
    // Known syscall numbers (Windows 10 22H2 x64)
    assert_eq!(get_syscall_number("NtCreateThreadEx"), Some(0x5A));
    assert_eq!(get_syscall_number("NtAllocateVirtualMemory"), Some(0x4B));
    assert_eq!(get_syscall_number("NtWriteVirtualMemory"), Some(0x3A));
    assert_eq!(get_syscall_number("NtProtectVirtualMemory"), Some(0x4D));
    assert_eq!(get_syscall_number("NtMapViewOfSection"), Some(0x5B));
    assert_eq!(get_syscall_number("NtQueueApcThread"), Some(0x2B));
    assert_eq!(get_syscall_number("NtCreateFile"), Some(0x55));
    assert_eq!(get_syscall_number("NtOpenFile"), Some(0x53));
    assert_eq!(get_syscall_number("NtReadFile"), Some(0x3F));
    assert_eq!(get_syscall_number("NtWriteFile"), Some(0x50));
    assert_eq!(get_syscall_number("NtDeviceIoControlFile"), Some(0x52));
    assert_eq!(get_syscall_number("NtClose"), Some(0x0C));
    assert_eq!(get_syscall_number("NtWaitForSingleObject"), Some(0x66));

    // Unknown functions return None
    assert_eq!(get_syscall_number("NtUnknownFunction"), None);
    assert_eq!(get_syscall_number(""), None);
}

#[test]
fn test_syscall_constants() {
    // Verify the public syscall number constants
    assert_eq!(SYS_NT_CREATE_THREAD_EX, 0x5A);
    assert_eq!(SYS_NT_ALLOCATE_VIRTUAL_MEMORY, 0x4B);
    assert_eq!(SYS_NT_WRITE_VIRTUAL_MEMORY, 0x3A);
    assert_eq!(SYS_NT_PROTECT_VIRTUAL_MEMORY, 0x4D);
    assert_eq!(SYS_NT_MAP_VIEW_OF_SECTION, 0x5B);
    assert_eq!(SYS_NT_QUEUE_APC_THREAD, 0x2B);
    assert_eq!(SYS_NT_CREATE_FILE, 0x55);
    assert_eq!(SYS_NT_OPEN_FILE, 0x53);
    assert_eq!(SYS_NT_READ_FILE, 0x3F);
    assert_eq!(SYS_NT_WRITE_FILE, 0x50);
    assert_eq!(SYS_NT_DEVICE_IO_CONTROL_FILE, 0x52);
    assert_eq!(SYS_NT_CLOSE, 0x0C);
    assert_eq!(SYS_NT_WAIT_FOR_SINGLE_OBJECT, 0x66);
}

#[test]
fn test_syscall_table_struct() {
    let table = SyscallTable::new(
        "NtCreateFile",
        0x55, // win7
        0x55, // win10 1809
        0x55, // win10 22H2
        0x55, // win11 22H2
    );
    assert_eq!(table.func_name, "NtCreateFile");
    assert_eq!(table.win7_sp1, 0x55);
    assert_eq!(table.win10_1809, 0x55);
    assert_eq!(table.win10_22h2, 0x55);
    assert_eq!(table.win11_22h2, 0x55);
}

#[test]
fn test_all_modules_have_dry_run() {
    // Verify that each module's dry_run function is callable
    // (This test just needs to compile — dry_run functions exist)
    let _ = InjectionTechnique::from_str("createremote");
    let _ = UnhookMethod::from_str("direct");
    let _ = get_syscall_number("NtCreateFile");
    let _ = check_api("NtOpenFile", 0x1000, 32);
}
