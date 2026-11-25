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
Select an NT function from the dropdown. Shows syscall number info (dry run) or invokes directly (live).

### Inject
Select technique from dropdown (CreateRemoteThread / APC / Thread Hijack / Early Bird APC / Section Mapping), load payload. Enter PID for most techniques; Early Bird spawns its own process so PID is not required. Requires live mode + Confirm.

### Load
Three sub-tabs:
- **Load File** — browse and load a `.bin` file, shows hex dump
- **Convert Bytes** — paste shellcode in any format, auto-detects, converts. Save or copy as C/Python/Rust
- **Generate** — select payload type, fill parameters, click Generate. No external tools needed

### Unhook
Select API and unhook method. Live mode restores original bytes.

## Log Panel

Bottom panel. Shows all output — scan results, hex dumps, errors. Click **Clear** to reset.
