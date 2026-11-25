# GUI Usage

Binary: `badang.exe` (built with `--features gui`)

## Top Bar

Top-right corner:
- **Dry Run: ON/OFF** — click to toggle. Green = safe mode. Yellow = live mode.
- **Confirm** — checkbox for destructive operations.

## Tabs

### Analyze
Enter a PID. Click **"Switch to Live"** to leave dry-run mode. Click **Analyze**. Results show in the Log panel — each API as CLEAN or HOOKED with raw bytes.

### Syscall
Select an NT function from the dropdown. Toggle "Indirect syscall" checkbox for Hell's Gate / Halo's Gate resolution. Shows syscall number info (dry run) or invokes directly (live).

### Inject
Select technique from dropdown (CreateRemoteThread / APC / Thread Hijack / Early Bird APC / Section Mapping / Callback Execution / Module Stomping), load payload. Enter PID for most techniques; Early Bird, Callback, and Stomp execute locally so PID is not required. Requires live mode + Confirm.

### Load
Three sub-tabs:
- **Load File** — browse and load a `.bin` file, shows hex dump
- **Convert Bytes** — paste shellcode in any format, auto-detects, converts. Save or copy as C/Python/Rust
- **Generate** — select payload type, fill parameters, click Generate. No external tools needed

### Unhook
Select API and unhook method. Live mode restores original bytes.

### ETW
Select target function (EtwEventWrite / EtwEventWriteFull / NtTraceEvent). Patch to disable ETW telemetry. Restore button available after patching.

### AMSI
Select target function (AmsiScanBuffer / AmsiScanString). Patch to bypass AMSI scanning. Restore button available after patching.

### PPID
Enter parent process name or PID, child command. Optional "Create suspended" checkbox for APC injection combo. Spawn button creates the spoofed-parent process.

### Sleep
Select method (Manual / Ekko), set duration in ms. Demo button runs the encrypt/sleep/decrypt cycle. Verifies data integrity after decryption.

### Spoof
Select target NT function. Demo button scans for ROP gadgets and builds fake call stack frames. Shows gadget addresses and frame count.

## Log Panel

Bottom panel. Shows all output — scan results, hex dumps, errors. Click **Clear** to reset.
