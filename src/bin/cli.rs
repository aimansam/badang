// Badang — CLI binary entry point
// For authorized security research and red team use only.

use badang::cli::CLI;
use badang::log::LogSink;
use badang::safety::{check_execution_mode, print_safety_warning, validate_target};
use std::process;

fn drain_to_stderr(log: &LogSink) {
    for entry in log.drain() {
        eprintln!("{}", entry.message);
    }
}

fn main() {
    let cli = CLI::parse();
    let log = LogSink::new();

    print_safety_warning(&log);
    drain_to_stderr(&log);

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
    } else if cli.target_pid > 0 {
        if let Err(e) = validate_target(cli.target_pid) {
            eprintln!("ERROR: {}", e);
            process::exit(1);
        }
    }

    if let Err(e) = check_execution_mode(cli.dry_run, cli.confirm) {
        eprintln!("ERROR: {}", e);
        eprintln!("Add --confirm to execute operations.");
        process::exit(1);
    }

    match cli.command.as_str() {
        "analyze" => {
            if cli.dry_run {
                println!("[DRY RUN] Would analyze process PID {}", cli.target_pid);
                badang::detect::dry_run(cli.target_pid, &log);
            } else {
                badang::detect::analyze(cli.target_pid, &log);
            }
        }
        "syscall" => {
            if cli.dry_run {
                println!("[DRY RUN] Would invoke syscall: {}", cli.syscall_func);
                badang::syscall::dry_run(&cli.syscall_func, &log);
            } else {
                badang::syscall::analyze(&cli.syscall_func, &log);
            }
        }
        "inject" => {
            if cli.dry_run {
                println!(
                    "[DRY RUN] Would inject into PID {} using technique {}",
                    cli.target_pid, cli.inject_technique
                );
                badang::injection::dry_run(cli.target_pid, &cli.inject_technique, &log);
            } else {
                badang::injection::run_live_injection(
                    cli.target_pid,
                    &cli.inject_technique,
                    &cli.payload,
                    &log,
                );
            }
        }
        "load" => match badang::injection::load_payload(&cli.payload) {
            Ok(bytes) => {
                println!("[LOAD] Payload file: {}", cli.payload);
                println!("       Size: {} bytes", bytes.len());
                println!("       First bytes: {:02x?}", &bytes[..bytes.len().min(16)]);
                println!("       (payload loaded successfully — no execution performed)");
                print!("{}", badang::payload::hex_dump(&bytes));
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }
        },
        "convert" => {
            let format = match cli.convert_format.to_lowercase().as_str() {
                "auto" => None,
                "hex" => Some(badang::payload::PayloadFormat::Hex),
                "c" | "carray" => Some(badang::payload::PayloadFormat::CArray),
                "python" | "py" => Some(badang::payload::PayloadFormat::PythonBytes),
                "rust" | "rs" => Some(badang::payload::PayloadFormat::RustArray),
                "decimal" | "dec" => Some(badang::payload::PayloadFormat::Decimal),
                _ => {
                    eprintln!(
                        "ERROR: unknown format '{}'. Use: auto, hex, c, python, rust, decimal",
                        cli.convert_format
                    );
                    process::exit(1);
                }
            };

            // If --payload is set and --input is empty, dump a .bin file as hex
            if cli.convert_input.is_empty() && cli.payload != "shellcode.bin" {
                match badang::injection::load_payload(&cli.payload) {
                    Ok(bytes) => {
                        println!("[DUMP] {} ({} bytes)\n", cli.payload, bytes.len());
                        print!("{}", badang::payload::hex_dump(&bytes));
                        println!("\n--- C array ---");
                        print!("{}", badang::payload::to_c_array(&bytes));
                        println!("\n--- Python ---");
                        println!("{}", badang::payload::to_python_bytes(&bytes));
                        println!("\n--- Rust ---");
                        print!("{}", badang::payload::to_rust_array(&bytes));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            } else if cli.convert_input.is_empty() {
                eprintln!("ERROR: --input <TEXT> is required for convert command.");
                eprintln!("       Or use --payload <FILE> to dump an existing .bin file.");
                process::exit(1);
            } else {
                let (bytes, detected) = if let Some(fmt) = format {
                    match badang::payload::parse(&cli.convert_input, fmt) {
                        Ok(b) => (b, fmt),
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                            process::exit(1);
                        }
                    }
                } else {
                    match badang::payload::auto_parse(&cli.convert_input) {
                        Ok(r) => r,
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                            process::exit(1);
                        }
                    }
                };

                println!(
                    "[CONVERT] Parsed {} bytes (format: {})",
                    bytes.len(),
                    detected.name()
                );
                print!("{}", badang::payload::hex_dump(&bytes));

                match std::fs::write(&cli.convert_output, &bytes) {
                    Ok(()) => {
                        println!("[SAVED] {} bytes -> {}", bytes.len(), cli.convert_output);
                    }
                    Err(e) => {
                        eprintln!("ERROR: failed to write '{}': {}", cli.convert_output, e);
                        process::exit(1);
                    }
                }
            }
        }
        "generate" => {
            let payload_type = match badang::generate::PayloadType::from_str(&cli.generate_type) {
                Some(t) => t,
                None => {
                    eprintln!(
                            "ERROR: unknown payload type '{}'. Use: exec, messagebox, reverse_tcp, bind_tcp",
                            cli.generate_type
                        );
                    process::exit(1);
                }
            };
            let config = badang::generate::PayloadConfig {
                payload_type,
                command: cli.generate_command.clone(),
                title: cli.generate_title.clone(),
                text: cli.generate_text.clone(),
                lhost: cli.generate_lhost.clone(),
                lport: cli.generate_lport,
            };
            match badang::generate::generate(&config) {
                Ok(bytes) => {
                    println!("[GENERATE] {} — {} bytes", payload_type.name(), bytes.len());
                    print!("{}", badang::payload::hex_dump(&bytes));
                    match std::fs::write(&cli.convert_output, &bytes) {
                        Ok(()) => {
                            println!("[SAVED] {} bytes -> {}", bytes.len(), cli.convert_output);
                        }
                        Err(e) => {
                            eprintln!("ERROR: failed to write '{}': {}", cli.convert_output, e);
                            process::exit(1);
                        }
                    }
                }
                Err(e) => {
                    eprintln!("ERROR: {}", e);
                    process::exit(1);
                }
            }
        }
        "scan" => {
            let processes = badang::process::scan(&log);
            if !processes.is_empty() {
                let list = if cli.scan_filter.is_empty() {
                    processes
                } else {
                    let filtered = badang::process::filter(&processes, &cli.scan_filter);
                    log.info(format!(
                        "  Filter '{}': {} matches",
                        cli.scan_filter,
                        filtered.len()
                    ));
                    filtered
                };
                log.info("");
                badang::process::print_table(&list, &log);
            }
        }
        "unhook" => {
            if cli.dry_run {
                println!("[DRY RUN] Would unhook API: {}", cli.unhook_func);
                badang::unhook::dry_run(&cli.unhook_func, &log);
            } else {
                badang::unhook::analyze(&cli.unhook_func, &log);
            }
        }
        _ => {
            eprintln!("Unknown command: {}", cli.command);
            process::exit(1);
        }
    }

    drain_to_stderr(&log);
}
