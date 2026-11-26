use crate::log::LogSink;
use super::sandbox::CheckResult;

pub const VM_MAC_PREFIXES: &[[u8; 3]] = &[
    [0x00, 0x0C, 0x29], // VMware
    [0x00, 0x50, 0x56], // VMware
    [0x08, 0x00, 0x27], // VirtualBox
    [0x00, 0x15, 0x5D], // Hyper-V
    [0x00, 0x1C, 0x42], // Parallels
];

pub fn is_vm_mac(mac: &[u8]) -> bool {
    if mac.len() < 3 {
        return false;
    }
    let prefix = [mac[0], mac[1], mac[2]];
    VM_MAC_PREFIXES.iter().any(|p| *p == prefix)
}

#[cfg(windows)]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    let mut results = Vec::new();
    results.push(check_cpuid_hypervisor(log));
    results.push(check_vm_registry(log));
    results.push(check_mac_prefix(log));
    results
}

#[cfg(not(windows))]
pub fn run_all(log: &LogSink) -> Vec<CheckResult> {
    log.detail("  Hardware fingerprint requires target platform");
    vec![CheckResult {
        name: String::from("Platform"),
        detected: false,
        detail: String::from("Not on target platform"),
    }]
}

#[cfg(windows)]
fn check_cpuid_hypervisor(log: &LogSink) -> CheckResult {
    log.step("  Checking processor features...");
    let detected;
    let detail;
    #[cfg(target_arch = "x86_64")]
    {
        let ecx: u32;
        unsafe {
            std::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "mov {ecx:e}, ecx",
                "pop rbx",
                ecx = out(reg) ecx,
                out("eax") _,
                out("edx") _,
            );
        }
        detected = (ecx >> 31) & 1 == 1;
        detail = format!("CPUID.1 ECX bit 31: {}", if detected { "set" } else { "clear" });
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        detected = false;
        detail = String::from("CPUID not available on this architecture");
    }
    log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
    CheckResult { name: String::from("Hypervisor Bit"), detected, detail }
}

#[cfg(windows)]
fn check_vm_registry(log: &LogSink) -> CheckResult {
    log.step("  Checking system registry...");
    unsafe {
        let hklm = 0x80000002u32 as *mut std::ffi::c_void; // HKEY_LOCAL_MACHINE
        let paths = [
            (crate::obf::VM_REG_VMWARE, "VMware"),
            (crate::obf::VM_REG_VBOX, "VirtualBox"),
            (crate::obf::VM_REG_HYPERV, "Hyper-V"),
        ];
        let mut found = Vec::new();
        for (path_enc, label) in &paths {
            let path = crate::obf::s(path_enc);
            let path_c = std::ffi::CString::new(path).unwrap_or_default();
            let mut key: *mut std::ffi::c_void = std::ptr::null_mut();
            let status = crate::resolve::RegOpenKeyExA(
                hklm,
                path_c.as_ptr() as *const u8,
                0,
                0x20019, // KEY_READ
                &mut key,
            );
            if status == 0 {
                found.push(*label);
                crate::resolve::RegCloseKey(key);
            }
        }
        let detected = !found.is_empty();
        let detail = if detected {
            format!("Found: {}", found.join(", "))
        } else {
            String::from("No known entries found")
        };
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("Registry Keys"), detected, detail }
    }
}

#[cfg(windows)]
fn check_mac_prefix(log: &LogSink) -> CheckResult {
    log.step("  Checking network adapter fingerprint...");
    unsafe {
        let mut buf_size: u32 = 0;
        crate::resolve::GetAdaptersInfo(std::ptr::null_mut(), &mut buf_size);
        if buf_size == 0 {
            let detail = String::from("No adapters found");
            log.detail(format!("    CLEAN — {}", detail));
            return CheckResult { name: String::from("MAC Prefix"), detected: false, detail };
        }
        let mut buf = vec![0u8; buf_size as usize];
        let ret = crate::resolve::GetAdaptersInfo(buf.as_mut_ptr() as *mut std::ffi::c_void, &mut buf_size);
        if ret != 0 {
            let detail = format!("Query failed: {}", ret);
            log.detail(format!("    CLEAN — {}", detail));
            return CheckResult { name: String::from("MAC Prefix"), detected: false, detail };
        }

        // IP_ADAPTER_INFO: AddressLength at offset 400, Address at offset 404
        let mut found = Vec::new();
        let mut ptr = buf.as_ptr();
        loop {
            let next = *(ptr as *const usize); // pNext
            let addr_len = *(ptr.add(400) as *const u32);
            if addr_len >= 3 {
                let mac = std::slice::from_raw_parts(ptr.add(404), 3);
                if is_vm_mac(mac) {
                    found.push(format!("{:02X}:{:02X}:{:02X}", mac[0], mac[1], mac[2]));
                }
            }
            if next == 0 {
                break;
            }
            ptr = next as *const u8;
        }
        let detected = !found.is_empty();
        let detail = if detected {
            format!("Known prefixes: {}", found.join(", "))
        } else {
            String::from("No known prefixes found")
        };
        log.detail(format!("    {} — {}", if detected { "DETECTED" } else { "CLEAN" }, detail));
        CheckResult { name: String::from("MAC Prefix"), detected, detail }
    }
}
