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

1. **Direct Syscall Invocation** — Bypassing user-mode API hooks by calling kernel functions directly via the `syscall` instruction
2. **Process Injection Techniques** — Methods for injecting code into other processes (CreateRemoteThread, APC, Thread Hijack)
3. **API Unhooking** — Restoring original function bytes to neutralize EDR hooks
4. **Hook Detection Analysis** — Identifying which APIs have been hooked by security software

Each technique includes detailed documentation of how it works, why it can bypass EDR, and what detection methods exist.

---

## Features

| Module | Description |
|--------|-------------|
| **Syscall** | Direct syscall invocation with Windows syscall number reference table (13 NT APIs) |
| **Injection** | 3 process injection techniques with step-by-step documentation |
| **Unhook** | API unhooking via memory comparison and byte restoration |
| **Detect** | Hook detection analysis — identify hooked APIs in target processes |
| **Safety** | Built-in safety controls: `--dry-run` mode, `--pid` required, system process protection |

### Safety Framework

Badang includes mandatory safety controls:
- `--dry-run` mode enabled by default — simulates without executing
- `--pid` required for analyze/inject commands
- System processes (PID < 100) are protected and cannot be targeted
- `--confirm` flag required to disable dry-run mode

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

## Quickstart

### Build and Run (5 minutes)

```bash
# Clone
git clone https://github.com/aimansam/badang.git
cd badang

# Build release binary
cargo build --release

# Try it — all commands default to dry-run mode
.\target\release\badang.exe analyze --pid 1234
.\target\release\badang.exe syscall -s NtCreateThreadEx
.\target/release/badang syscall -s NtAllocateVirtualMemory
.\target/release/badang inject -p 4231 -t APC
.\target/release/badang unhook -u NtCreateFile
```

### CI/CD

This project includes a GitHub Actions workflow that:
- Builds on **ubuntu-latest** and **windows-latest**
- Runs `cargo fmt`, `cargo clippy`, `cargo test`
- Verifies Windows cross-compile from Linux
- Runs `cargo audit` for security vulnerability scanning
- Uploads the Windows release binary as an artifact

```bash
# View CI status
gh run list --repo aimansam/badang
```

### Cross-Platform Build

```bash
# Build Windows binary from Linux
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
# Output: target/x86_64-pc-windows-msvc/release/badang.exe
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

# Build
cargo build --release

# Binary location
.\target\release\badang.exe
```

### Cross-Compilation

For Windows targets from Linux/macOS:

```bash
# Add Windows target
rustup target add x86_64-pc-windows-msvc

# Build for Windows
cargo build --release --target x86_64-pc-windows-msvc
```

---

## Usage

### Command Line Interface

```bash
# Show help
badang.exe --help

# Analyze a process for hooked APIs (DRY RUN by default)
badang.exe analyze --pid 1234

# Direct syscall invocation (DRY RUN)
badang.exe syscall --func NtCreateThreadEx

# Process injection technique demonstration (DRY RUN)
badang.exe inject --pid 1234 --technique CreateRemote

# API unhooking demonstration (DRY RUN)
badang.exe unhook --func NtCreateFile
```

### Commands

| Command | Description | Requires `--pid` |
|---------|-------------|------------------|
| `analyze` | Detect hooked APIs in a target process | Yes |
| `syscall` | Invoke a function via direct syscall | No |
| `inject` | Demonstrate process injection technique | Yes |
| `unhook` | Demonstrate API unhooking | No |

### Safety Flags

| Flag | Description |
|------|-------------|
| `--dry-run` | Simulate without executing (default: true) |
| `--confirm` | Disable dry-run and execute (required for real operations) |
| `--pid <PID>` | Target process ID (required for analyze/inject) |
| `--verbose` | Enable verbose output |
| `--func <name>` | Target API/function name (alias for --syscall) |

### Example: Analyze a Process

```bash
# Dry-run analysis (default)
badang.exe analyze --pid 4231

# With confirmation to actually execute
badang.exe analyze --pid 4231 --confirm
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

Badang documents 3 injection techniques:

1. **CreateRemoteThread** — Allocate + write memory in target, create remote thread
2. **APC Injection** — Queue an APC to a target thread to execute injected code
3. **Thread Hijack** — Suspend a thread, modify its context to redirect execution

Each technique is demonstrated in dry-run mode with step-by-step documentation.

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
├── Cargo.toml          # Rust project configuration
├── .github/
│   └── workflows/
│       └── ci.yml      # GitHub Actions CI/CD
├── src/
│   ├── main.rs         # CLI entry point
│   ├── cli.rs          # Command-line argument parsing
│   ├── safety.rs       # Safety controls and validation
│   ├── syscall.rs      # Direct syscall invocation module
│   ├── injection.rs    # Process injection techniques
│   ├── unhook.rs       # API unhooking module
│   ├── detect.rs       # Hook detection analysis
│   └── tests.rs        # Integration tests
├── target/             # Build output (gitignored)
└── README.md           # This file
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
