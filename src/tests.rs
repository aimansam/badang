// Badang — Module tests
use crate::cli::CLI;
use crate::detect::{check_api, HookStatus, HookType};
use crate::injection::InjectionTechnique;
use crate::unhook::UnhookMethod;

#[test]
fn test_cli_defaults() {
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
    assert_eq!(cli.target_pid, 1234);
}

#[test]
fn test_injection_techniques_parse() {
    // Verify all known technique strings parse correctly
    assert!(InjectionTechnique::from_str("createremote").is_some());
    assert!(InjectionTechnique::from_str("CreateRemoteThread").is_some());
    assert!(InjectionTechnique::from_str("apc").is_some());
    assert!(InjectionTechnique::from_str("APCInjection").is_some());
    assert!(InjectionTechnique::from_str("hijack").is_some());
    assert!(InjectionTechnique::from_str("ThreadHijack").is_some());
    assert!(InjectionTechnique::from_str("setthreadcontext").is_some());
    assert!(InjectionTechnique::from_str("invalid").is_none());
    assert!(InjectionTechnique::from_str("").is_none());
}

#[test]
fn test_injection_technique_variants() {
    // Verify all 3 enum variants exist and can be constructed directly
    let _cr = InjectionTechnique::CreateRemoteThread;
    let _apc = InjectionTechnique::APC;
    let _th = InjectionTechnique::ThreadHijack;
    assert!(true); // Variants exist
}

#[test]
fn test_unhook_methods_parse() {
    assert!(UnhookMethod::from_str("direct").is_some());
    assert!(UnhookMethod::from_str("DirectByte").is_some());
    assert!(UnhookMethod::from_str("trampoline").is_some());
    assert!(UnhookMethod::from_str("Trampoline").is_some());
    assert!(UnhookMethod::from_str("inline").is_some());
    assert!(UnhookMethod::from_str("InlineHook").is_some());
    assert!(UnhookMethod::from_str("invalid").is_none());
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

    let clean_str = format!("{}", clean);
    assert!(clean_str.contains("clean"));
}

#[test]
fn test_check_api_stub() {
    let status = check_api("NtCreateFile", 0x1000, 32);
    assert_eq!(status.api_name, "NtCreateFile");
    assert_eq!(status.address, 0x1000);
    assert!(!status.is_hooked);
}

#[test]
fn test_hook_type_variants() {
    let _jmp = HookType::JMP;
    let _push_pop = HookType::PUSH_POP;
    let _int3 = HookType::INT3;
    let _unknown = HookType::Unknown;
    assert!(true); // Variants exist
}

#[test]
fn test_detect_module_structure() {
    let _status = HookStatus {
        api_name: "test".to_string(),
        address: 0,
        is_hooked: false,
        hook_type: None,
        original_bytes: None,
        hooked_bytes: None,
    };
}
