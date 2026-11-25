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
| **root** | resolve | `src/resolve.rs` | Dynamic API resolution (runtime IAT bypass) |
| | obf | `src/obf.rs` | XOR-encrypted strings + API names (8-byte key) |
| | pe | `src/pe.rs` | Shared PE helpers (exports, .text, pattern scan) |
| | process | `src/process.rs` | Process enumeration (ToolHelp snapshot) |
| | cli | `src/cli.rs` | Argument parsing |
| | safety | `src/safety.rs` | Execution mode checks, PID validation |
| | log | `src/log.rs` | Shared log sink (CLI → stderr, GUI → panel) |
| | gui/ | `src/gui/` | GUI app, theme, 11 panels |

## Windows Defender Exclusions

Windows Defender will flag this project (source and binaries) as malicious due to shellcode templates, syscall patterns, and injection API references. This is expected for security research toolkits.

**Add exclusions before building** (run PowerShell as Administrator):

```powershell
# Exclude the project directory (source + build output)
Add-MpPreference -ExclusionPath "C:\path\to\badang"

# Or exclude just the binaries
Add-MpPreference -ExclusionPath "C:\path\to\badang\target"

# Verify exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**If Defender already quarantined files**, restore them first:

```powershell
# List quarantined items
Get-MpThreat

# Restore all quarantined items
Get-MpThreat | ForEach-Object { Remove-MpThreat -ThreatID $_.ThreatID }

# Or use Defender UI: Windows Security → Virus & threat protection
#   → Protection history → Quarantined items → Restore
```

**Alternative: temporarily disable real-time protection** (not recommended long-term):

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Build, test, etc.
Set-MpPreference -DisableRealtimeMonitoring $false
```

> **Note:** These exclusions are only for your development machine. Never disable Defender on production systems. If cross-compiling from Linux, Defender is not an issue.

## Dynamic API Resolution (`src/resolve.rs`)

All suspicious Win32 API calls (VirtualAlloc, WriteProcessMemory, CreateRemoteThread, OpenProcess, etc.) are resolved at runtime instead of appearing in the Import Address Table (IAT). This eliminates the primary static detection signal that Defender's ML model uses.

**How it works:**
- Only two bootstrap functions remain in the IAT: `GetModuleHandleA` and `GetProcAddress` (every legitimate binary imports these)
- All other APIs are resolved at runtime via encrypted names from `obf.rs`
- The `windows` crate dependency was removed entirely — zero function imports from it
- Raw `#[link(name = "kernel32")]` extern blocks are used only for the two bootstrap functions

**Before:** 98 KERNEL32.dll IAT entries including the full injection API set
**After:** ~50 entries (all standard CRT functions) — zero injection/evasion APIs visible

**Usage pattern** (all modules follow this):
```rust
// Instead of:  use windows::Win32::System::Memory::VirtualAlloc;
// Do:          use crate::resolve;
let p = unsafe { resolve::VirtualAlloc(std::ptr::null(), size, 0x3000, 0x04) };
```

Raw u32 constants replace windows crate newtypes (MEM_COMMIT=0x1000, PAGE_READWRITE=0x04, etc.).

**Adding a new Win32 API to the resolver:**

1. Encrypt the function name:
   ```python
   K=[0xd3,0x7a,0x91,0xe5,0x2f,0xb8,0x64,0x1c]
   print([hex(b^K[i%len(K)]) for i,b in enumerate(b'NewFunctionName')])
   ```
2. Add the encrypted const to `src/obf.rs` (in the Win32 API names section, with `W_` prefix)
3. Add a wrapper function to `src/resolve.rs` following the existing pattern:
   ```rust
   #[cfg(windows)]
   pub unsafe fn NewFunctionName(arg1: type1, arg2: type2) -> ReturnType {
       type F = unsafe extern "system" fn(type1, type2) -> ReturnType;
       let f: F = std::mem::transmute(resolve(K32, crate::obf::W_NEW_FUNCTION_NAME));
       f(arg1, arg2)
   }
   ```
4. For DLLs other than kernel32 (e.g. user32), use `U32` instead of `K32`
5. For DLLs not loaded by default (e.g. amsi.dll), use `resolve_load()` instead of `resolve()`

**Converting a module to use dynamic resolution:**

1. Remove all `use windows::` imports
2. Remove any `#[link] extern "system"` blocks (except GetModuleHandleA/GetProcAddress which are bootstrap)
3. Replace API calls: `windows::Win32::...::FunctionName(args)` → `resolve::FunctionName(args)`
4. Replace newtype constants with raw u32 (see table below)
5. Replace `.map_err()` / `Result` patterns with `== 0` or `.is_null()` checks
6. Replace `HANDLE` with `*mut std::ffi::c_void`
7. Add `#[repr(C)]` struct definitions for any Windows structs used (PROCESSENTRY32, STARTUPINFOW, etc.)

**Common Win32 constants (raw u32):**

| Constant | Value | Used for |
|----------|-------|----------|
| MEM_COMMIT | 0x1000 | VirtualAlloc* |
| MEM_RESERVE | 0x2000 | VirtualAlloc* |
| MEM_RELEASE | 0x8000 | VirtualFree* |
| PAGE_NOACCESS | 0x01 | VirtualProtect* |
| PAGE_READWRITE | 0x04 | VirtualProtect* |
| PAGE_EXECUTE_READ | 0x20 | VirtualProtect* |
| PAGE_EXECUTE_READWRITE | 0x40 | VirtualProtect* |
| PROCESS_CREATE_THREAD | 0x0002 | OpenProcess |
| PROCESS_VM_OPERATION | 0x0008 | OpenProcess |
| PROCESS_VM_READ | 0x0010 | OpenProcess |
| PROCESS_VM_WRITE | 0x0020 | OpenProcess |
| PROCESS_CREATE_PROCESS | 0x0080 | OpenProcess (PPID) |
| PROCESS_QUERY_INFORMATION | 0x0400 | OpenProcess |
| THREAD_SUSPEND_RESUME | 0x0002 | OpenThread |
| THREAD_GET_CONTEXT | 0x0008 | OpenThread |
| THREAD_SET_CONTEXT | 0x0010 | OpenThread |
| TH32CS_SNAPPROCESS | 0x00000002 | CreateToolhelp32Snapshot |
| TH32CS_SNAPTHREAD | 0x00000004 | CreateToolhelp32Snapshot |
| CREATE_SUSPENDED | 0x00000004 | CreateProcessW |
| EXTENDED_STARTUPINFO_PRESENT | 0x00080000 | CreateProcessW |
| INFINITE | 0xFFFFFFFF | WaitForSingleObject |
| WAIT_OBJECT_0 | 0 | WaitForSingleObject |
| FILE_MAP_WRITE | 0x0002 | MapViewOfFile |

## PE Metadata (`build.rs`)

The binary embeds version info and a manifest via `winresource` to improve reputation scoring with Defender's ML model. Missing PE metadata (company name, version, manifest) lowers the reputation score and increases detection probability.

**What's embedded:**
- FileDescription, ProductName, CompanyName, FileVersion, ProductVersion
- Application manifest with supported OS GUIDs and execution level
- Resource section (`.rsrc`) visible in the PE structure

## String Obfuscation (`src/obf.rs`)

The release binary uses compile-time multi-byte XOR obfuscation to prevent static AV signature matching. All sensitive data is stored encrypted and decrypted at runtime.

**XOR key:** 8-byte key `[0xD3, 0x7A, 0x91, 0xE5, 0x2F, 0xB8, 0x64, 0x1C]` defined in `src/obf.rs`.

**What's encrypted:**
- API function names (Nt\*, AMSI, ETW targets)
- DLL names (ntdll.dll, amsi.dll, kernel32.dll, user32.dll, ws2\_32.dll, xpsservices.dll)
- Patch byte signatures (AMSI bypass, ETW ret)
- Syscall patterns (prologue, syscall;ret gadget)
- Shellcode templates (PEB walking, find\_function, get\_data\_ptr, all main payloads)

**What's NOT encrypted (intentionally):**
- Display-only strings in help text and dry\_run descriptions — sanitized to remove offensive keywords instead
- Linker directives (`#[link(name = "...")]`) — unavoidable in PE imports
- Match arms in `from_str()` — lowercase user-input patterns, not API signatures

**Adding new sensitive strings:**

1. Encrypt with the 8-byte key:
   ```python
   K=[0xd3,0x7a,0x91,0xe5,0x2f,0xb8,0x64,0x1c]
   print([hex(b^K[i%len(K)]) for i,b in enumerate(b'YourString')])
   ```
2. Add the encrypted const to `src/obf.rs`
3. Use `obf::s()` for strings, `obf::b()` for byte vecs, `obf::ba()` for fixed arrays
4. Never put the plaintext form in non-test Rust code

**String sanitization (all source files):**

All display strings — help text, error messages, step annotations, GUI labels — are stripped of keywords flagged by Defender's ML: `shellcode`, `inject`, `evasion`, `hook`, `bypass`, `EDR`, `malware`. Win32 API names are removed from error messages (e.g. `CreateRemoteThread failed` → `remote thread creation failed`).

**Release profile** (in `Cargo.toml`) complements obfuscation:
- `opt-level = 3` — aggressive optimization removes dead code paths
- `strip = true` — removes symbol table
- `lto = true` — link-time optimization across crates
- `codegen-units = 1` — single compilation unit for maximum optimization
- `panic = "abort"` — no unwinding infrastructure

## Safety Model

- Dry-run mode ON by default — no execution
- Live mode requires `-x` (execute) + `-c` (confirm)
- PID 0, PID 4 (System), and self-targeting are rejected
- Empty shellcode is rejected
- Payload file existence is validated before injection
