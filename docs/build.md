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

## String Obfuscation (`src/obf.rs`)

The release binary uses compile-time XOR obfuscation to prevent static AV signature matching. All sensitive data is stored encrypted and decrypted at runtime.

**What's encrypted:**
- API function names (Nt\*, AMSI, ETW targets)
- DLL names (ntdll.dll, amsi.dll, kernel32.dll, user32.dll, ws2\_32.dll, xpsservices.dll)
- Patch byte signatures (AMSI bypass, ETW ret)
- Syscall patterns (prologue, syscall;ret gadget)
- Shellcode templates (PEB walking, find\_function, get\_data\_ptr, all main payloads)

**What's NOT encrypted (intentionally):**
- Display-only strings in help text and dry\_run descriptions — not part of AV signatures
- Linker directives (`#[link(name = "...")]`) — unavoidable in PE imports
- Match arms in `from_str()` — lowercase user-input patterns, not API signatures

**Adding new sensitive strings:**

1. XOR each byte with `0x4B`: `python3 -c "print([hex(b ^ 0x4B) for b in b'YourString'])"`
2. Add the encrypted const to `src/obf.rs`
3. Use `obf::s()` for strings, `obf::b()` for byte vecs, `obf::ba()` for fixed arrays
4. Never put the plaintext form in non-test Rust code

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
