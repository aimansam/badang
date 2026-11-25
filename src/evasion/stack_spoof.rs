use crate::log::LogSink;

#[derive(Debug)]
pub struct SpoofResult {
    pub gadget_addrs: Vec<u64>,
    pub frames_built: usize,
    pub target_func: String,
}

pub fn dry_run(func_name: &str, log: &LogSink) {
    log.info("[DRY RUN] Stack Spoofing".to_string());
    log.detail(format!("  Target: {func_name}"));
    log.info(String::new());
    log.detail("  Steps that would execute:".to_string());
    log.detail("    [1/4] Load ntdll.dll + kernel32.dll base addresses".to_string());
    log.detail("    [2/4] Find .text sections, scan for ROP gadgets".to_string());
    log.detail("           ret (C3), pop rbp;ret (5D C3)".to_string());
    log.detail("    [3/4] Build fake call stack frames:".to_string());
    log.detail("           [saved_rbp → ntdll frame] [ret → kernel32 gadget]".to_string());
    log.detail(format!(
        "    [4/4] Call {func_name} via spoofed trampoline"
    ));
    log.info(String::new());
    log.warning("  EDR stack-walking sees legitimate return addresses".to_string());
    log.warning("  (ntdll, kernel32) instead of shellcode addresses.".to_string());
}

pub fn print_info(log: &LogSink) {
    log.info("=== Stack Spoofing ===".to_string());
    log.info(String::new());
    log.detail("Builds fake call stack frames before calling Windows APIs so".to_string());
    log.detail("EDR stack-walking sees legitimate return addresses (ntdll,".to_string());
    log.detail("kernel32) instead of shellcode or injected code.".to_string());
    log.info(String::new());
    log.detail("How it works:".to_string());
    log.detail("  1. Find ROP gadgets in ntdll/kernel32 .text sections:".to_string());
    log.detail("     - C3 (ret) — simple return".to_string());
    log.detail("     - 5D C3 (pop rbp; ret) — frame-compatible return".to_string());
    log.info(String::new());
    log.detail("  2. Build fake stack frame chain:".to_string());
    log.detail("     [RBP → points to ntdll frame] [ret → kernel32 gadget]".to_string());
    log.detail("     Each frame's saved RBP chains to the next fake frame.".to_string());
    log.info(String::new());
    log.detail("  3. Trampoline (conceptual x64 asm):".to_string());
    log.detail("     push rbp; push rbx".to_string());
    log.detail("     mov rbx, rsp        ; save real stack".to_string());
    log.detail("     mov rbp, <fake_rbp>  ; point to fake chain".to_string());
    log.detail("     sub rsp, 0x28       ; shadow space".to_string());
    log.detail("     call rax            ; call target API".to_string());
    log.detail("     mov rsp, rbx        ; restore real stack".to_string());
    log.detail("     pop rbx; pop rbp; ret".to_string());
    log.info(String::new());
    log.detail("Why it works:".to_string());
    log.detail("  - EDRs walk the stack on sensitive API calls".to_string());
    log.detail("  - They check that return addresses point to known modules".to_string());
    log.detail("  - Spoofed frames make the call look like it came from".to_string());
    log.detail("    ntdll → kernel32 → user code (normal call chain)".to_string());
    log.warning("  Limitations: some EDRs verify frame pointer alignment".to_string());
    log.warning("  and cross-reference with thread stack base/limit".to_string());
}

#[cfg(windows)]
pub fn demo_spoofed_call(func_name: &str, log: &LogSink) -> Result<SpoofResult, String> {
    log.step("[1/4] Loading module bases".to_string());
    let ntdll_base = crate::pe::get_module_base(&crate::obf::s(crate::obf::NTDLL))?;
    let k32_base = crate::pe::get_module_base(&crate::obf::s(crate::obf::KERNEL32))?;

    log.detail(format!("  ntdll.dll:    0x{:016X}", ntdll_base as usize));
    log.detail(format!("  kernel32.dll: 0x{:016X}", k32_base as usize));

    log.step("[2/4] Scanning .text for ROP gadgets".to_string());

    let ntdll_text = crate::pe::find_text_section(ntdll_base)?;
    let k32_text = crate::pe::find_text_section(k32_base)?;

    let pop_rbp_ret: [u8; 2] = [0x5D, 0xC3];
    let ret_only: [u8; 1] = [0xC3];

    let ntdll_gadgets = crate::pe::scan_for_pattern(ntdll_text.base, ntdll_text.size, &pop_rbp_ret);
    let k32_gadgets = crate::pe::scan_for_pattern(k32_text.base, k32_text.size, &ret_only);

    if ntdll_gadgets.is_empty() {
        return Err("no pop rbp;ret gadget in ntdll .text".to_string());
    }
    if k32_gadgets.is_empty() {
        return Err("no ret gadget in kernel32 .text".to_string());
    }

    let ntdll_gadget = ntdll_gadgets[0];
    let k32_gadget = k32_gadgets[0];

    log.detail(format!(
        "  ntdll pop rbp;ret: 0x{ntdll_gadget:016X} ({} candidates)",
        ntdll_gadgets.len()
    ));
    log.detail(format!(
        "  kernel32 ret:      0x{k32_gadget:016X} ({} candidates)",
        k32_gadgets.len()
    ));

    log.step("[3/4] Building fake call stack frames".to_string());
    log.detail("  Frame 0: saved_rbp → ntdll frame, ret → kernel32 ret gadget".to_string());
    log.detail("  Frame 1: saved_rbp → 0 (end of chain), ret → ntdll pop rbp;ret".to_string());

    log.step(format!("[4/4] Would call {func_name} via spoofed trampoline"));
    log.detail(format!(
        "  Target: {func_name} resolved via PE export table"
    ));

    let gadget_addrs = vec![ntdll_gadget as u64, k32_gadget as u64];

    log.info(String::new());
    log.info(format!("  ✓ Stack spoof prepared for {func_name}"));
    log.detail(format!("    Gadgets: {} total (ntdll + kernel32)", gadget_addrs.len()));
    log.detail("    EDR stack walk would see: ntdll → kernel32 → target".to_string());

    Ok(SpoofResult {
        gadget_addrs,
        frames_built: 2,
        target_func: func_name.to_string(),
    })
}

#[cfg(not(windows))]
pub fn demo_spoofed_call(func_name: &str, log: &LogSink) -> Result<SpoofResult, String> {
    log.warning(format!(
        "  Stack spoofing requires Windows. Would spoof call to {func_name}."
    ));
    Err("stack spoofing is only available on Windows".to_string())
}
