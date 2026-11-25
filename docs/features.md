# Features

## Analyze (Hook Detection)

Scans a target process for hooked APIs. Opens the process, reads the first 32 bytes of each NT function from `ntdll.dll`, compares against the clean prologue (`4C 8B D1 B8`).

**13 APIs scanned:** NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtMapViewOfSection, NtQueueApcThread, NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile, NtClose, NtWaitForSingleObject, NtDeviceIoControlFile.

Reports each as `[CLEAN]` or `[HOOKED]` with hook type and raw bytes.

## Syscall (Direct Syscall)

Calls the kernel directly using raw syscall numbers, bypassing ntdll hooks entirely. Includes SSN tables for Windows 7 SP1, 10 1809, 10 22H2, and 11 22H2.

## Inject (Process Injection)

Seven live injection techniques (all operational with `-x -c`):

- **CreateRemoteThread** — allocate + write + create thread. 6-step pipeline: OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread → WaitForSingleObject. Simplest, most detected.
- **APC Injection** — wraps shellcode in callee-save trampoline (preserves rbx/rbp/rsi/rdi/r12-r15), writes to target, enumerates threads via ToolHelp, queues APC to all threads. Executes when a thread enters alertable wait. No new thread created.
- **Thread Hijack (SetThreadContext)** — suspends an existing thread, saves full CONTEXT (all GPRs + RFLAGS), redirects RIP to shellcode in a full-register-save trampoline with completion flag. Polls flag via ReadProcessMemory, then restores original context so the thread continues normally. No new thread, no APC.
- **Early Bird APC** — creates a new process with CREATE_SUSPENDED, writes shellcode, queues APC to the main thread, then resumes. The APC fires during process initialization before EDR user-mode hooks are installed. No PID required.
- **Section Mapping (MapViewOfFile)** — creates a shared memory section (CreateFileMappingW), maps locally to write shellcode via memcpy, maps same section into target via MapViewOfFileNuma2 as PAGE_EXECUTE_READ. WriteProcessMemory is never called — EDR hooks on it see nothing. Requires Windows 10 1703+.

- **Callback Execution (EnumWindows)** — allocates local memory, writes shellcode, casts to WNDENUMPROC, calls EnumWindows. No CreateThread or CreateRemoteThread — shellcode fires as a Windows callback. No PID required.
- **Module Stomping** — loads xpsservices.dll with DONT_RESOLVE_DLL_REFERENCES, parses PE to find .text section, overwrites with shellcode. Memory scanners see shellcode inside a Microsoft-signed module. No PID required.

Each technique is in its own file under `src/injection/`. Injection lives alongside the other module categories: `src/analysis/`, `src/evasion/`, `src/syscall/`, and `src/payload/`.

## Unhook (API Restoration)

Restores hooked functions to original bytes. Three methods:

- **Direct Byte Restoration** — overwrite with clean prologue
- **Trampoline** — patch around the hook
- **Inline Hook** — redirect execution flow

## Generate (Payload Generator)

Builds x86_64 Windows shellcode without msfvenom. Uses PEB walking (`gs:[0x60]` → PEB → kernel32) and ROR13 API hashing.

| Type | What it does | Parameters |
|------|-------------|------------|
| exec | Run command via WinExec | `--command "calc.exe"` |
| messagebox | Show MessageBox | `--title "Test" --text "Hello"` |
| reverse_tcp | Connect-back shell | `--lhost IP --lport PORT` |
| bind_tcp | Listen shell | `--lport PORT` |

## Convert (Format Converter)

Auto-detects and converts between: hex, C array, Python bytes, Rust array, decimal.

## Indirect Syscall (Hell's Gate / Halo's Gate)

Resolves SSNs at runtime by parsing ntdll's PE export table in memory, then executes the `syscall` instruction from ntdll's own `.text` section.

- **Hell's Gate**: reads clean function prologue `4C 8B D1 B8 xx xx 00 00` → SSN is bytes[4..8].
- **Halo's Gate**: if function is hooked, walks to neighboring Zw* exports. Clean neighbor at distance ±N → target SSN = neighbor_ssn ∓ N.
- **Gadget**: scans ntdll .text for `0F 05 C3` (syscall; ret), jumps to it with SSN in EAX.

Extends the existing syscall command with `--indirect` flag.

## ETW Patching

Patches `EtwEventWrite`, `EtwEventWriteFull`, or `NtTraceEvent` in ntdll.dll with `0xC3` (ret). Blinds ETW telemetry that EDRs rely on even when user-mode hooks are removed.

## AMSI Bypass

Loads `amsi.dll`, patches `AmsiScanBuffer` or `AmsiScanString` with `B8 57 00 07 80 C3` (mov eax, E_INVALIDARG; ret). Makes AMSI report all scans as invalid.

## Shellcode Encryption

Encrypts shellcode with XOR (single or multi-byte key) or RC4, prepends a PIC x86_64 decryption stub. Output is `[stub + encrypted_payload]` — ready to inject, decrypts and jumps to payload at runtime.

## PPID Spoofing

Creates a process that appears to have a different parent via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. Supports CREATE_SUSPENDED for Early Bird combo. Can resolve parent by name or PID.

## Sleep Obfuscation

Encrypts shellcode in memory during sleep periods. Manual method: VirtualProtect(RW) → XOR-encrypt → VirtualProtect(NOACCESS) → Sleep → decrypt → VirtualProtect(RX). Ekko (ROP timer queue) is documented for future implementation.

## Stack Spoofing

Builds fake call stack frames before calling Windows APIs. Scans ntdll/kernel32 .text for ROP gadgets (ret, pop rbp;ret), constructs fake frame chain. EDR stack-walking sees ntdll → kernel32 instead of shellcode addresses.

## Dynamic API Resolution (IAT Evasion)

All Win32 API calls are resolved at runtime via `GetModuleHandleA` + `GetProcAddress` with XOR-encrypted function names. Only these two bootstrap functions appear in the Import Address Table — Defender's ML model no longer sees VirtualAlloc, WriteProcessMemory, CreateRemoteThread, etc. in the binary's imports.

The `windows` crate was removed entirely. All 20+ modules use `crate::resolve::*` for API calls and raw u32 constants for flags/permissions.

**Before:** 98 KERNEL32.dll IAT entries (full injection API set flagged by ML)
**After:** ~50 entries (standard CRT only, zero injection/evasion APIs)

Combined with XOR string obfuscation (`src/obf.rs`), string sanitization, and PE metadata embedding (`build.rs`), the binary presents a clean static profile to signature and ML-based scanners.

## Static Analysis Evasion

Four layers work together to defeat Defender's static/ML scanner:

### 1. Multi-byte XOR String Obfuscation (`src/obf.rs`)

All sensitive strings are encrypted at compile time with an 8-byte XOR key (`[0xD3, 0x7A, 0x91, 0xE5, 0x2F, 0xB8, 0x64, 0x1C]`) and decrypted at runtime. This covers API names, DLL names, patch bytes, syscall patterns, and shellcode templates. Functions: `obf::s()` (string), `obf::b()` (byte vec), `obf::ba()` (fixed array), `obf::byte()` (single byte).

### 2. Dynamic API Resolution (`src/resolve.rs`)

All Win32 API calls go through runtime resolution instead of static imports. Only `GetModuleHandleA` and `GetProcAddress` appear in the IAT. The 20+ modules call `crate::resolve::VirtualAlloc()` etc. which resolve the real function pointer on first call using XOR-encrypted names from `obf.rs`.

### 3. String Sanitization (all source files)

All user-facing strings — help text, error messages, step annotations, GUI labels — are stripped of offensive keywords that Defender's ML flags: `shellcode`, `inject`, `evasion`, `hook`, `bypass`, `EDR`, `malware`. Win32 API names are removed from error messages (`CreateRemoteThread failed` → `remote thread creation failed`). Technique names use short neutral labels (`CRT`, `Section Map`, `Module Overwrite`).

### 4. PE Metadata (`build.rs`)

The build script embeds a Windows application manifest, version info (CompanyName, FileDescription, etc.), and an application icon via `winresource`. This makes the binary look like a normal application to heuristic scanners that check for missing metadata.

**Release profile** (`Cargo.toml`): `opt-level = 3`, `strip = true`, `lto = true`, `codegen-units = 1`, `panic = "abort"` — maximum optimization + no symbols.

## PE Helpers

Shared module (`src/pe.rs`) for PE parsing: export table walking, .text section finding, byte pattern scanning. Used by indirect syscalls (`src/syscall/indirect.rs`), module stomping (`src/injection/stomp.rs`), and stack spoofing (`src/evasion/stack_spoof.rs`).
