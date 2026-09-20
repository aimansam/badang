// Badang — EDR Evasion Research Toolkit
// For authorized security research and red team use only.
// https://github.com/aimansam/badang

#![allow(dead_code)]

mod cli;
mod detect;
mod injection;
mod safety;
mod syscall;
mod tests;
mod unhook;

use cli::CLI;
use safety::{check_execution_mode, print_safety_warning, validate_target};
use std::process;

fn main() {
    let cli = CLI::parse();

    // Print safety warning
    print_safety_warning();

    // Validate target PID for process-targeting commands
    if cli.command == "analyze" || cli.command == "inject" {
        if let Err(e) = validate_target(cli.target_pid) {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }
        if cli.target_pid == 0 {
            eprintln!(
                "ERROR: --pid <PID> is required for {} command.",
                cli.command
            );
            eprintln!("Use --dry-run (default) to simulate without executing.");
            process::exit(1);
        }
    } else {
        // For syscall/unhook, validate if PID provided
        if cli.target_pid > 0 {
            if let Err(e) = validate_target(cli.target_pid) {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }
        }
    }

    // Check execution mode
    if let Err(e) = check_execution_mode(cli.dry_run, cli.confirm) {
        eprintln!("ERROR: {}", e);
        eprintln!("Add --confirm to execute operations.");
        process::exit(1);
    }

    match cli.command.as_str() {
        "analyze" => {
            if cli.dry_run {
                println!("[DRY RUN] Would analyze process PID {}", cli.target_pid);
                detect::dry_run(cli.target_pid);
            } else {
                detect::analyze(cli.target_pid);
            }
        }
        "syscall" => {
            if cli.dry_run {
                println!("[DRY RUN] Would invoke syscall: {}", cli.syscall_func);
                syscall::dry_run(&cli.syscall_func);
            } else {
                syscall::analyze(&cli.syscall_func);
            }
        }
        "inject" => {
            if cli.dry_run {
                println!(
                    "[DRY RUN] Would inject into PID {} using technique {}",
                    cli.target_pid, cli.inject_technique
                );
                injection::dry_run(cli.target_pid, &cli.inject_technique);
            } else {
                injection::analyze(&cli.inject_technique);
            }
        }
        "unhook" => {
            if cli.dry_run {
                println!("[DRY RUN] Would unhook API: {}", cli.unhook_func);
                unhook::dry_run(&cli.unhook_func);
            } else {
                unhook::analyze(&cli.unhook_func);
            }
        }
        _ => {
            eprintln!("Unknown command: {}", cli.command);
            process::exit(1);
        }
    }
}
