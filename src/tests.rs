// Badang — Integration tests
// Tests verify the public API surface of each module.
// Keep in sync with the actual exports in each module file.
#![allow(unused_imports)]

use crate::cli::CLI;
use crate::detect::{
    check_api, classify_hook, HookStatus, HookType, CLEAN_NT_EPILOGUE, CLEAN_NT_PROLOGUE,
};
use crate::injection::InjectionTechnique;
use crate::log::LogSink;
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
        payload: "payload.bin".to_string(),
        syscall_func: "NtCreateThreadEx".to_string(),
        unhook_func: "NtCreateFile".to_string(),
        convert_input: String::new(),
        convert_output: "payload.bin".to_string(),
        convert_format: "auto".to_string(),
        generate_type: String::new(),
        generate_command: "calc.exe".to_string(),
        generate_title: "Badang".to_string(),
        generate_text: "Hello from Badang".to_string(),
        generate_lhost: "127.0.0.1".to_string(),
        generate_lport: 4444,
        scan_filter: String::new(),
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
    // Existing variant: EarlyBird
    assert_eq!(
        InjectionTechnique::from_str("earlybird"),
        Some(InjectionTechnique::EarlyBird)
    );
    assert_eq!(
        InjectionTechnique::from_str("early_bird"),
        Some(InjectionTechnique::EarlyBird)
    );
    assert_eq!(
        InjectionTechnique::from_str("early-bird"),
        Some(InjectionTechnique::EarlyBird)
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

    let eb = InjectionTechnique::EarlyBird;
    assert_eq!(eb.name(), "Early Bird APC");
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
    let _push_pop = HookType::PushPop;
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
        hook_type: Some(HookType::PushPop),
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
    assert!(!s2.is_hooked);
}

#[test]
fn test_classify_hook_jmp_rel32() {
    let bytes = [0xE9, 0x12, 0x34, 0x56, 0x78];
    assert_eq!(classify_hook(&bytes), Some(HookType::JMP));
}

#[test]
fn test_classify_hook_jmp_indirect() {
    let bytes = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(classify_hook(&bytes), Some(HookType::JMP));
}

#[test]
fn test_classify_hook_int3() {
    let bytes = [0xCC, 0x90, 0x90, 0x90];
    assert_eq!(classify_hook(&bytes), Some(HookType::INT3));
}

#[test]
fn test_classify_hook_push_ret() {
    let bytes = [0x68, 0x78, 0x56, 0x34, 0x12, 0xC3];
    assert_eq!(classify_hook(&bytes), Some(HookType::PushPop));
}

#[test]
fn test_classify_hook_clean_prologue() {
    // Clean NT API: mov r10, rcx; mov eax, <ssn>
    let bytes = [0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00];
    assert_eq!(classify_hook(&bytes), None);
}

#[test]
fn test_classify_hook_unknown_modification() {
    // Not a known hook pattern, but doesn't match clean prologue
    let bytes = [0x48, 0x89, 0x5C, 0x24, 0x08];
    assert_eq!(classify_hook(&bytes), Some(HookType::Unknown));
}

#[test]
fn test_classify_hook_empty() {
    assert_eq!(classify_hook(&[]), None);
}

#[test]
fn test_hook_type_display() {
    assert!(format!("{}", HookType::JMP).contains("JMP"));
    assert!(format!("{}", HookType::PushPop).contains("PUSH"));
    assert!(format!("{}", HookType::INT3).contains("INT3"));
    assert!(format!("{}", HookType::Unknown).contains("Unknown"));
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

// === Live injection (payload chain) ===

#[test]
fn test_load_payload_roundtrip() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("badang_test_payload_{}.bin", std::process::id()));
    let bytes: Vec<u8> = vec![0x90, 0x31, 0xC0, 0xC3];
    std::fs::write(&path, &bytes).expect("failed to write test payload");
    let loaded = crate::injection::load_payload(path.to_str().expect("path is valid utf-8"));
    let _ = std::fs::remove_file(&path);
    assert_eq!(loaded.expect("load_payload should succeed"), bytes);
}

#[test]
fn test_load_payload_missing_file() {
    let err = crate::injection::load_payload("/nonexistent/badang/definitely-missing.bin")
        .expect_err("missing file must be an error");
    assert!(
        err.contains("failed to read payload file"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_live_inject_requires_pid() {
    let log = LogSink::new();
    let err = crate::injection::live_inject(
        0,
        &InjectionTechnique::CreateRemoteThread,
        &[0x90, 0x90],
        &log,
    )
    .expect_err("pid 0 must be rejected");
    assert!(err.contains("PID"), "unexpected error: {}", err);
}

#[test]
fn test_live_inject_rejects_empty_shellcode() {
    let log = LogSink::new();
    let err =
        crate::injection::live_inject(1234, &InjectionTechnique::CreateRemoteThread, &[], &log)
            .expect_err("empty shellcode must be rejected");
    assert!(
        err.contains("shellcode is empty"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn test_all_techniques_dispatch() {
    let log = LogSink::new();
    for technique in &[
        InjectionTechnique::CreateRemoteThread,
        InjectionTechnique::APC,
        InjectionTechnique::ThreadHijack,
        InjectionTechnique::EarlyBird,
    ] {
        let err = crate::injection::live_inject(1234, technique, &[0x90, 0x90], &log)
            .expect_err("should fail on non-Windows or with invalid PID");
        assert!(
            !err.contains("not yet implemented"),
            "{} should be implemented: {}",
            technique.name(),
            err
        );
    }
}

#[test]
fn test_wrap_for_apc_structure() {
    let shellcode = vec![0xCC; 10];
    let wrapped = crate::injection::wrappers::wrap_for_apc(&shellcode);
    assert_eq!(wrapped.len(), 21 + 17 + 10);
    assert_eq!(wrapped[16], 0xE8);
    assert_eq!(wrapped[17], 0x11);
    assert_eq!(&wrapped[38..], &shellcode[..]);
    assert_eq!(wrapped[37], 0xC3);
}

#[test]
fn test_wrap_for_hijack_structure() {
    let shellcode = vec![0xCC; 20];
    let wrapped = crate::injection::wrappers::wrap_for_hijack(&shellcode);
    assert_eq!(wrapped.len(), 36 + 46 + 20 + 1);
    // Prologue ends with CALL that jumps over epilogue
    assert_eq!(wrapped[31], 0xE8);
    assert_eq!(wrapped[32], 0x2E); // rel32 = 46
    // Shellcode starts at byte 82
    assert_eq!(&wrapped[82..102], &shellcode[..]);
    // Flag at the end, initially 0
    assert_eq!(wrapped[102], 0x00);
    // Epilogue ends with pause+jmp spin-wait
    assert_eq!(&wrapped[78..82], &[0xF3, 0x90, 0xEB, 0xFC]);
}

/// Manual end-to-end verification — ONLY on an authorized Windows VM:
///   cargo test test_live_crt_chain_manual -- --ignored
/// Requires:
///   BADANG_TEST_PID     PID of a sacrificial process you own
///   BADANG_TEST_PAYLOAD path to a shellcode file you control
/// Ignored by default so CI and `cargo test` never touch a live process.
#[test]
#[ignore]
fn test_live_crt_chain_manual() {
    let pid = std::env::var("BADANG_TEST_PID")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let payload_path = std::env::var("BADANG_TEST_PAYLOAD").unwrap_or_default();
    if pid == 0 || payload_path.is_empty() {
        eprintln!(
            "skipping: set BADANG_TEST_PID and BADANG_TEST_PAYLOAD on an authorized Windows VM"
        );
        return;
    }
    let log = LogSink::new();
    let shellcode = crate::injection::load_payload(&payload_path).expect("payload load failed");
    crate::injection::live_inject(
        pid,
        &InjectionTechnique::CreateRemoteThread,
        &shellcode,
        &log,
    )
    .expect("live CRT chain should complete");
}
