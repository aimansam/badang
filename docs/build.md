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

| Module | File | Purpose |
|--------|------|---------|
| detect | `src/detect.rs` | Hook detection (ReadProcessMemory + classify) |
| syscall | `src/syscall.rs` | Syscall number table + direct invocation |
| injection | `src/injection/` | Process injection (CRT, APC, Hijack, Early Bird, Section) |
| unhook | `src/unhook.rs` | API unhooking (Direct Byte, Trampoline, Inline) |
| generate | `src/generate.rs` | Shellcode generator (PEB walk + template patch) |
| payload | `src/payload.rs` | Byte format converter + hex dump |
| cli | `src/cli.rs` | Argument parsing |
| safety | `src/safety.rs` | Execution mode checks, PID validation |
| log | `src/log.rs` | Shared log sink (CLI → stderr, GUI → panel) |
| gui/ | `src/gui/` | GUI app, theme, panels |

## Safety Model

- Dry-run mode ON by default — no execution
- Live mode requires `-x` (execute) + `-c` (confirm)
- PID 0, PID 4 (System), and self-targeting are rejected
- Empty shellcode is rejected
- Payload file existence is validated before injection
