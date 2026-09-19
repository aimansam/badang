// Badang — Safety module
// Enforces safety controls for offensive security research

/// Check if a PID is a protected system process
/// System processes typically have PID < 100 on Windows
pub fn is_system_process(pid: u32) -> bool {
    pid < 100
}

/// Validate that a target PID is safe to operate on
pub fn validate_target(pid: u32) -> Result<(), String> {
    if pid == 0 {
        return Err("PID cannot be 0".to_string());
    }
    if is_system_process(pid) {
        return Err(format!(
            "PID {} is a protected system process. Refusing to target.",
            pid
        ));
    }
    Ok(())
}

/// Check dry-run mode and warn if actually executing
pub fn check_execution_mode(dry_run: bool, confirm: bool) -> Result<(), String> {
    if !dry_run && !confirm {
        return Err("Must use --confirm to execute operations".to_string());
    }
    Ok(())
}

/// Print safety warning
pub fn print_safety_warning() {
    eprintln!("===========================================================");
    eprintln!("  BADANG — EDR Evasion Research Toolkit");
    eprintln!("  FOR AUTHORIZED SECURITY RESEARCH ONLY");
    eprintln!("===========================================================");
    eprintln!();
    eprintln!("Using these techniques without explicit authorization is illegal.");
    eprintln!("Always obtain written permission before testing against any system.");
    eprintln!();
    eprintln!("This tool includes safety controls:");
    eprintln!("  - --dry-run mode (default): simulates without executing");
    eprintln!("  - --pid <PID> required for any active operation");
    eprintln!("  - System processes (PID < 100) are protected");
    eprintln!("  - --confirm required for actual execution");
    eprintln!();
    eprintln!("See README.md for full documentation and legal notices.");
    eprintln!("===========================================================");
    eprintln!();
}
