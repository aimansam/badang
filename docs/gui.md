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
Select technique from dropdown (CreateRemoteThread / APC / Thread Hijack / Early Bird APC / Section Mapping / Callback Execution / Module Stomping / Process Hollowing), load payload. Enter PID for most techniques; Early Bird, Callback, Stomp, and Hollowing execute locally so PID is not required. Requires live mode + Confirm.

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

### Persist
Select method from dropdown (Registry / Scheduled Task / WMI / DLL Placement / COM / Service). Enter name, target (for hijack/COM), and payload path. Execute configures the selected persistence mechanism. Requires live mode + Confirm.

### Comms
Select channel from dropdown (Secure Web Channel / Name Resolution Channel / Network Share Channel). Enter host, port, path, interval, jitter, and RC4 hex key. Optional "Sleep obfuscation" checkbox encrypts memory during sleep. Dry run shows the callback sequence; live mode connects and enters the callback loop. Info button lists available channels and their status.

### Loader
Select check category from dropdown (Full Analysis / Environment Analysis / Process Inspection / Hardware Fingerprint). Select fail action (Report Only / Terminate on Detection). Dry run shows the check sequence; live mode runs checks and displays results as CLEAN or FLAGGED per check with detail text. Info button lists all check categories.

### PostEx
Select post-exploitation module from dropdown (Memory Snapshot / Registry Export / Session Delegation / Remote Service / Remote Execution WMI / Remote Execution WinRM / Staged Transfer / Proxy Relay / Port Relay). Fields change based on selection — credential modules show PID and output path, lateral modules show remote host, credentials, command/payload, exfil modules show file path, remote host/port, and optional RC4 key, tunnel modules show listen port and remote host/port. Dry run shows the step sequence; live mode executes and displays results. Info button lists all modules.

## Log Panel

Bottom panel. Shows all output — scan results, hex dumps, errors. Click **Clear** to reset.
