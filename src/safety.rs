// Badang — Safety module

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
    log.warning("  BADANG — FOR AUTHORIZED USE ONLY");
    log.warning("===========================================================");
    log.warning("");
    log.warning("  --dry-run (default) | --pid required | --confirm required");
    log.warning("");
}
