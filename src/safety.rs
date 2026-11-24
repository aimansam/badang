// Badang — Safety module
// Enforces safety controls for offensive security research

use crate::log::LogSink;

pub fn is_system_process(pid: u32) -> bool {
    pid < 100
}

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

pub fn check_execution_mode(dry_run: bool, confirm: bool) -> Result<(), String> {
    if !dry_run && !confirm {
        return Err("Must use --confirm to execute operations".to_string());
    }
    Ok(())
}

pub fn print_safety_warning(log: &LogSink) {
    log.warning("===========================================================");
    log.warning("  BADANG — EDR Evasion Research Toolkit");
    log.warning("  FOR AUTHORIZED SECURITY RESEARCH ONLY");
    log.warning("===========================================================");
    log.warning("");
    log.warning("Using these techniques without explicit authorization is illegal.");
    log.warning("Always obtain written permission before testing against any system.");
    log.warning("");
    log.warning("This tool includes safety controls:");
    log.warning("  - --dry-run mode (default): simulates without executing");
    log.warning("  - --pid <PID> required for any active operation");
    log.warning("  - System processes (PID < 100) are protected");
    log.warning("  - --confirm required for actual execution");
    log.warning("");
    log.warning("See README.md for full documentation and legal notices.");
    log.warning("===========================================================");
    log.warning("");
}
