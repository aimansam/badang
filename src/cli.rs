// Badang — CLI argument parsing
use std::env;
use std::process;

pub struct CLI {
    pub command: String,
    pub dry_run: bool,
    pub verbose: bool,
    pub confirm: bool,
    pub target_pid: u32,
    pub inject_technique: String,
    pub syscall_func: String,
    pub unhook_func: String,
}

impl CLI {
    pub fn parse() -> Self {
        let args: Vec<String> = env::args().collect();

        let mut cli = CLI {
            command: String::from("help"),
            dry_run: true,
            verbose: false,
            confirm: false,
            target_pid: 0,
            inject_technique: String::from("createremote"),
            syscall_func: String::from("NtAllocateVirtualMemory"),
            unhook_func: String::from("NtCreateThreadEx"),
        };

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--help" | "-h" => {
                    print_help();
                    process::exit(0);
                }
                "--verbose" | "-v" => cli.verbose = true,
                "--dry-run" | "-n" => cli.dry_run = true,
                "--execute" | "-x" => cli.dry_run = false,
                "--confirm" | "-c" => cli.confirm = true,
                "--pid" | "-p" => {
                    i += 1;
                    if i < args.len() {
                        cli.target_pid = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid PID: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--technique" | "-t" => {
                    i += 1;
                    if i < args.len() {
                        cli.inject_technique = args[i].clone();
                    }
                }
                "--syscall" | "-s" | "--func" => {
                    i += 1;
                    if i < args.len() {
                        cli.syscall_func = args[i].clone();
                    }
                }
                "--unhook" | "-u" => {
                    i += 1;
                    if i < args.len() {
                        cli.unhook_func = args[i].clone();
                    }
                }
                "analyze" => cli.command = String::from("analyze"),
                "syscall" => cli.command = String::from("syscall"),
                "inject" => cli.command = String::from("inject"),
                "unhook" => cli.command = String::from("unhook"),
                _ => {
                    eprintln!("Unknown argument: {}", args[i]);
                    print_help();
                    process::exit(1);
                }
            }
            i += 1;
        }

        // PID is required for process-targeting commands
        if cli.command == "analyze" || cli.command == "inject" {
            if cli.target_pid == 0 {
                eprintln!(
                    "ERROR: --pid <PID> is required for {} command.",
                    cli.command
                );
                eprintln!("Use --dry-run (default) to simulate without executing.");
                process::exit(1);
            }
        }

        cli
    }
}

fn print_help() {
    println!("Badang v0.1.0 — EDR Evasion Research Toolkit");
    println!();
    println!("USAGE: badang <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("  analyze    Analyze hooked APIs in a target process");
    println!("  syscall    Direct syscall invocation (bypass user-mode hooks)");
    println!("  inject     Process injection technique demonstration");
    println!("  unhook     API unhooking (restore original function bytes)");
    println!();
    println!("OPTIONS:");
    println!("  -p, --pid <PID>       Target process ID (required)");
    println!("  -s, --syscall <FUNC>  Target syscall function (syscall command)");
    println!("  -f, --func <FUNC>     Target function name (alias for --syscall)");
    println!("  -t, --technique <TEC> Injection technique (inject command)");
    println!("  -u, --unhook <FUNC>   Target API to unhook (unhook command)");
    println!("  -n, --dry-run         Simulate without executing (default)");
    println!("  -x, --execute         Actually perform the operation");
    println!("  -c, --confirm         Confirm before executing");
    println!("  -v, --verbose         Verbose output");
    println!();
    println!("WARNING: For authorized security research only.");
    println!("Using without authorization is illegal.");
}
