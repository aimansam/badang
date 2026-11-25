# Build & Architecture

## Build Commands

```bash
# CLI only
cargo build --release

# CLI + GUI
cargo build --release --features gui

# Cross-compile for Windows from Linux
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu --features gui

# Run tests
cargo test
```

## Binaries

| Binary | Source | Feature |
|--------|--------|---------|
| `badang.exe` | `src/bin/gui.rs` | `--features gui` |
| `badang-cli.exe` | `src/bin/cli.rs` | none |

## Modules

| Category | Module | File | Purpose |
|----------|--------|------|---------|
| **analysis/** | detect | `src/analysis/detect.rs` | Hook detection (ReadProcessMemory + classify) |
| | unhook | `src/analysis/unhook.rs` | API unhooking (Direct Byte, Trampoline, Inline) |
| **evasion/** | etw | `src/evasion/etw.rs` | ETW patching (blind EDR telemetry) |
| | amsi | `src/evasion/amsi.rs` | AMSI bypass (patch scan functions) |
| | ppid | `src/evasion/ppid.rs` | PPID spoofing (fake parent process) |
| | sleep_obfs | `src/evasion/sleep_obfs.rs` | Sleep obfuscation (encrypt during sleep) |
| | stack_spoof | `src/evasion/stack_spoof.rs` | Stack spoofing (fake call frames) |
| **syscall/** | direct | `src/syscall/mod.rs` | Syscall number table + direct invocation |
| | indirect | `src/syscall/indirect.rs` | Hell's Gate / Halo's Gate SSN resolution |
| **payload/** | format | `src/payload/format.rs` | Byte format converter + hex dump |
| | encrypt | `src/payload/encrypt.rs` | Shellcode encryption (XOR/RC4 + PIC stubs) |
| | generate | `src/payload/generate.rs` | Shellcode generator (PEB walk + template patch) |
| **injection/** | — | `src/injection/` | Process injection (7 techniques) |
| **root** | pe | `src/pe.rs` | Shared PE helpers (exports, .text, pattern scan) |
| | cli | `src/cli.rs` | Argument parsing |
| | safety | `src/safety.rs` | Execution mode checks, PID validation |
| | log | `src/log.rs` | Shared log sink (CLI → stderr, GUI → panel) |
| | gui/ | `src/gui/` | GUI app, theme, 11 panels |

## Safety Model

- Dry-run mode ON by default — no execution
- Live mode requires `-x` (execute) + `-c` (confirm)
- PID 0, PID 4 (System), and self-targeting are rejected
- Empty shellcode is rejected
- Payload file existence is validated before injection
