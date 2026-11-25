use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SleepMethod {
    Manual,
    Ekko,
}

impl SleepMethod {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "manual" | "xor" | "basic" => Some(SleepMethod::Manual),
            "ekko" | "rop" | "timer" => Some(SleepMethod::Ekko),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SleepMethod::Manual => "Manual (XOR encrypt/sleep/decrypt)",
            SleepMethod::Ekko => "Ekko (ROP timer queue)",
        }
    }

    pub fn all() -> &'static [SleepMethod] {
        &[SleepMethod::Manual, SleepMethod::Ekko]
    }
}

#[derive(Debug)]
pub struct SleepDemo {
    pub region_base: u64,
    pub region_size: usize,
    pub sleep_ms: u32,
}

pub fn dry_run(method: &str, duration_ms: u32, log: &LogSink) {
    let method_name = SleepMethod::from_str(method)
        .map_or(method.to_string(), |m| m.name().to_string());
    log.info(format!("[DRY RUN] Memory Protection — {method_name}"));
    log.detail(format!("  Duration: {duration_ms} ms"));
    log.info(String::new());
    log.detail("  Steps that would execute (Manual):".to_string());
    log.detail("    [1/6] Allocate test region (RW)".to_string());
    log.detail("    [2/6] Fill with known data, set RX".to_string());
    log.detail("    [3/6] Before sleep: set RW → XOR-encrypt in-place".to_string());
    log.detail("    [4/6] Set NOACCESS — region is unreadable".to_string());
    log.detail(format!("    [5/6] Sleep {duration_ms} ms — scanner sees encrypted garbage"));
    log.detail("    [6/6] Set RW → XOR-decrypt → set RX".to_string());
    log.info(String::new());
    log.detail("  During sleep, region is encrypted + PAGE_NOACCESS.".to_string());
    if method == "ekko" || method == "rop" || method == "timer" {
        log.info(String::new());
        log.detail("  Ekko technique (advanced):".to_string());
        log.detail("    Uses ROP chain via timer queue:".to_string());
        log.detail("    Set RW → encrypt → wait(sleep) → decrypt → set RX".to_string());
        log.detail("    All executed via NtContinue context switches — no explicit API calls".to_string());
    }
}

pub fn print_info(log: &LogSink) {
    log.info("=== Memory Protection ===".to_string());
    log.info(String::new());
    log.detail("Encrypts memory regions during idle periods.".to_string());
    log.detail("Methods: Manual (XOR), Ekko (ROP timer queue).".to_string());
}

#[cfg(windows)]
pub fn demo_manual(duration_ms: u32, log: &LogSink) -> Result<SleepDemo, String> {
    use crate::resolve;

    const MEM_COMMIT: u32 = 0x1000;
    const MEM_RESERVE: u32 = 0x2000;
    const MEM_RELEASE: u32 = 0x8000;
    const PAGE_READWRITE: u32 = 0x04;
    const PAGE_EXECUTE_READ: u32 = 0x20;
    const PAGE_NOACCESS: u32 = 0x01;
    const REGION_SIZE: usize = 4096;
    let xor_key: u8 = 0x5A;

    log.step("[1/6] Allocate test region (RW) — 4096 bytes".to_string());
    let alloc = unsafe {
        resolve::VirtualAlloc(
            std::ptr::null(),
            REGION_SIZE,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };
    if alloc.is_null() {
        return Err("allocation failed".to_string());
    }
    let base = alloc as usize;

    let test_data: Vec<u8> = (0..REGION_SIZE).map(|i| (i & 0xFF) as u8).collect();
    unsafe {
        std::ptr::copy_nonoverlapping(test_data.as_ptr(), alloc as *mut u8, REGION_SIZE);
    }

    log.step("[2/6] Set memory protection (RX)".to_string());
    let mut old_protect: u32 = 0;
    let ok = unsafe {
        resolve::VirtualProtect(alloc, REGION_SIZE, PAGE_EXECUTE_READ, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection (RX) failed".to_string());
    }

    log.step("[3/6] Before sleep: set RW → XOR-encrypt in-place".to_string());
    let ok = unsafe {
        resolve::VirtualProtect(alloc, REGION_SIZE, PAGE_READWRITE, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection (RW) failed".to_string());
    }

    let region = unsafe { std::slice::from_raw_parts_mut(alloc as *mut u8, REGION_SIZE) };
    for byte in region.iter_mut() {
        *byte ^= xor_key;
    }

    log.step("[4/6] Set NOACCESS — region is now unreadable".to_string());
    let ok = unsafe {
        resolve::VirtualProtect(alloc, REGION_SIZE, PAGE_NOACCESS, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection (NOACCESS) failed".to_string());
    }

    log.step(format!("[5/6] Sleep {duration_ms} ms — scanner sees nothing"));
    unsafe { resolve::Sleep(duration_ms) };

    log.step("[6/6] Set RW → XOR-decrypt → set RX".to_string());
    let ok = unsafe {
        resolve::VirtualProtect(alloc, REGION_SIZE, PAGE_READWRITE, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection (RW) post-sleep failed".to_string());
    }

    let region = unsafe { std::slice::from_raw_parts_mut(alloc as *mut u8, REGION_SIZE) };
    for byte in region.iter_mut() {
        *byte ^= xor_key;
    }

    let restored: Vec<u8> = region.to_vec();
    if restored != test_data {
        unsafe { resolve::VirtualFree(alloc as *mut std::ffi::c_void, 0, MEM_RELEASE) };
        return Err("data integrity check failed after decrypt".to_string());
    }

    let ok = unsafe {
        resolve::VirtualProtect(alloc, REGION_SIZE, PAGE_EXECUTE_READ, &mut old_protect)
    };
    if ok == 0 {
        return Err("memory protection (RX) post-decrypt failed".to_string());
    }

    log.info(format!("  Complete at 0x{base:016X}"));
    log.detail(format!("    Region: {REGION_SIZE} bytes, slept {duration_ms} ms"));
    log.detail("    Data integrity verified — encrypt/decrypt cycle successful".to_string());

    unsafe { resolve::VirtualFree(alloc as *mut std::ffi::c_void, 0, MEM_RELEASE) };

    Ok(SleepDemo {
        region_base: base as u64,
        region_size: REGION_SIZE,
        sleep_ms: duration_ms,
    })
}

#[cfg(not(windows))]
pub fn demo_manual(duration_ms: u32, log: &LogSink) -> Result<SleepDemo, String> {
    log.warning(format!(
        "  Memory protection requires Windows. Would demo {duration_ms} ms cycle."
    ));
    Err("memory protection is only available on Windows".to_string())
}

#[cfg(windows)]
pub fn demo_ekko(duration_ms: u32, log: &LogSink) -> Result<SleepDemo, String> {
    log.warning("  Ekko (ROP timer) is documented but not yet implemented.".to_string());
    log.detail("  Requires NtContinue context structures + SystemFunction032.".to_string());
    log.detail("  Use 'manual' method for a working demonstration.".to_string());
    demo_manual(duration_ms, log)
}

#[cfg(not(windows))]
pub fn demo_ekko(duration_ms: u32, log: &LogSink) -> Result<SleepDemo, String> {
    log.warning(format!(
        "  Memory protection requires Windows. Would demo Ekko {duration_ms} ms."
    ));
    Err("memory protection is only available on Windows".to_string())
}
