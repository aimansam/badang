# Roadmap

Five projects cover the full kill chain, named after the legendary Malay warriors of the *Hikayat Hang Tuah*.

---

## The 5 Projects

| # | Project | Named After | Role | Status |
|---|---------|-------------|------|--------|
| 1 | **Badang** | Hang Badang — the strongman | **Dual role:** attacker-side (generate, encrypt, convert, package) + target-side implant (loader, evasion, inject, persist, comms, post-ex) | All phases complete |
| 2 | **Jebat** | Hang Jebat — the commander | C2 server — listeners, task queue, implant management, operator UI | All phases complete |
| 3 | **Tuah** | Hang Tuah — the greatest warrior | Binary testing sandbox — QEMU VM orchestration, deploy + detonate Badang builds, verify Jebat checkin, Defender evasion scoring | Planned |
| 4 | **Kasturi** | Hang Kasturi — kasturi means "musk" (the lure) | Phishing toolkit — email templates, macro/HTA/LNK/ISO packaging, tracking | Planned |
| 5 | **Lekir** | Hang Lekir — the scout | Recon/OSINT — subdomain enum, email harvest, tech fingerprint, breach lookup | Planned |

---

## Kill Chain Coverage

```
┌──────────────────────────────────────────────────────────────────────┐
│                         RED TEAM KILL CHAIN                          │
│              4 warriors, full recon → post-ex coverage                │
├──────────────┬───────────────────────────────────────────────────────┤
│              │                                                       │
│  1. RECON    │  [5] LEKIR (the scout)                                │
│              │      Subdomain enum, email harvest, tech fingerprint   │
│              │      Breach lookup, social profiling                   │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  2. WEAPON-  │  [1] BADANG (the strongman) — RUNS ON ATTACKER        │
│     IZE      │      badang-cli generate (exec, reverse, bind, stager)│
│              │      badang-cli encrypt (XOR/RC4 + PIC stubs)         │
│              │      badang-cli package (Exe, Ps1, CSharp, Dll)       │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  2b. TEST    │  [3] TUAH (the sandbox)                               │
│              │      QEMU VM orchestration, deploy + execute binary   │
│              │      Verify Jebat checkin, Defender evasion scoring   │
│              │      Shell task validation, automated test reports    │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  3. DELIVER  │  [4] KASTURI (the lure) — takes Badang-generated       │
│              │      payloads, wraps in macro/HTA/LNK/ISO packaging   │
│              │      Landing page cloner, delivery tracking            │
│              │  [1] BADANG — Loader module (runs on TARGET)           │
│              │      Anti-sandbox, anti-debug, anti-VM, staged fetch   │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  4. EXPLOIT  │  [1] BADANG — Loader + Evasion                        │
│              │      Sandbox detection, anti-debug, in-memory exec     │
│              │      ETW patching, AMSI bypass, indirect syscalls      │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  5. INSTALL  │  [1] BADANG — Injection + Persistence                 │
│              │      8 injection techniques (CRT, APC, hijack, early   │
│              │      bird, section map, callback, stomp, hollowing)    │
│              │      6 persistence methods (registry, schtask, WMI,    │
│              │      COM, DLL hijack, service creation)                │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  6. C2       │  [1] BADANG — Comms module (target-side)              │
│              │      Beacon loop, jitter, HTTPS/DNS/SMB channels,     │
│              │      RC4 transport encryption                          │
│              │  [2] JEBAT (the commander, attacker-side)             │
│              │      Listeners, task queue, operator web UI,           │
│              │      implant tracking, payload builder                 │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  7. ACTIONS  │  [1] BADANG — Post-ex modules (9 modules)             │
│              │      Credentials — LSASS dump, SAM/SYSTEM, tokens     │
│              │      Lateral    — PsExec, WMI, WinRM                  │
│              │      Exfil      — staged TCP, 64KB chunks, RC4        │
│              │      Tunnel     — SOCKS5 proxy, port forward           │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  EVASION     │  [1] BADANG — active throughout every stage           │
│  (all        │      XOR string obfuscation (8-byte key)              │
│   stages)    │      Dynamic API resolution (clean IAT)               │
│              │      String sanitization (no flagged keywords)         │
│              │      Indirect syscalls (Hell's Gate / Halo's Gate)    │
│              │      Sleep obfuscation (encrypt memory during sleep)  │
│              │      Stack spoofing (fake call frames)                │
│              │      PE metadata (look like normal application)        │
│              │      Defender static analysis bypass (proven)          │
│              │                                                       │
└──────────────┴───────────────────────────────────────────────────────┘
```

---

## Architecture

```
ATTACKER MACHINE                                            TARGET MACHINE
────────────────                                            ──────────────

┌──────────────────┐
│  LEKIR (recon)   │
│  subdomain enum  │
│  email harvest   │
│  tech fingerprint│
│  breach lookup   │
└────────┬─────────┘
         │  targets
         ▼
┌──────────────────┐
│ KASTURI (phish)  │
│ email templates  │
│ macro/HTA/LNK   │
│ landing pages    │
│ delivery track   │
└────────┬─────────┘
         │  payload
         ▼
┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  JEBAT (C2)      │  │ BADANG (builder) │  │  TUAH (sandbox)  │
│                  │  │                  │  │                  │
│  ┌────────────┐ │  │  generate        │  │  QEMU VM mgmt    │
│  │ Listeners  │ │  │  encrypt         │  │  deploy binary   │
│  │  HTTPS     │ │  │  convert         │  │  verify checkin  │
│  │  DNS       │ │  │  package         │  │  Defender check  │
│  │  SMB       │ │  │  (Exe/Ps1/       │  │  shell task test │
│  ├────────────┤ │  │   CSharp/Dll)    │  │  test report     │
│  │ Task Queue │ │  └────────┬─────────┘  └────────┬─────────┘
│  │ Implant DB │ │           │  binary             │  tests
│  │ File Store │ │           │                     │  against
│  │ Event Bus  │◄├───────────┼─────────────────────┘
│  ├────────────┤ │           └───────────────►┌─────────────────────────────────┐
│  │ Operator   │ │  HTTPS                     │       BADANG (implant)          │
│  │  Web UI    │ │◄──────────────────────────►│                                 │
│  │  CLI       │ │  DNS                       │  ┌──────────┐  ┌─────────────┐ │
│  │  Builder   │ │  SMB                       │  │ Loader   │  │ Evasion     │ │
│  └────────────┘ │  RC4 encrypted             │  │ anti-sb  │  │ ETW/AMSI    │ │
└──────────────────┘                            │  │ anti-dbg │  │ sleep obfs  │ │
                                                │  │ anti-vm  │  │ stack spoof │ │
                                                │  └────┬─────┘  └──────┬──────┘ │
                                                │  ┌────▼───────────────▼──────┐ │
                                                │  │ Injection (8 techniques)  │ │
                                                │  └────────────┬──────────────┘ │
                                                │  ┌────────────▼──────────────┐ │
                                                │  │ Comms (beacon loop)       │ │
                                                │  │ RC4 transport              │ │
                                                │  └────────────┬──────────────┘ │
                                                │  ┌────────────▼──────────────┐ │
                                                │  │ Persistence (6 methods)   │ │
                                                │  └────────────┬──────────────┘ │
                                                │  ┌────────────▼──────────────┐ │
                                                │  │ Post-Ex (9 modules)       │ │
                                                │  │ creds │ lateral │ exfil   │ │
                                                │  │ socks │ portfwd           │ │
                                                │  └───────────────────────────┘ │
                                                └─────────────────────────────────┘
```

---

## Badang — Build Phases

### Phase 1: Core Platform (DONE)

All shipped and pushed. Badang has a dual role: the CLI runs on the **attacker machine** (generate, encrypt, convert, package) to produce binaries, while those binaries run on the **target machine** (loader, evasion, inject, persist, comms, post-ex).

| Module | What | Status |
|--------|------|--------|
| Injection | 8 techniques (CRT, APC, hijack, early bird, section map, callback, stomp, hollowing) | Done |
| Persistence | 6 methods (registry, schtask, WMI, DLL hijack, COM, service) | Done |
| Payload | 6 types (exec, messagebox, reverse_tcp, bind_tcp, stager) + encryption (XOR/RC4) | Done |
| Packaging | 4 output formats (Exe, Ps1, CSharp, Dll source templates) | Done |
| Evasion | ETW patch, AMSI bypass, PPID spoof, sleep obfuscation, stack spoofing | Done |
| Syscalls | Direct (SSN tables) + Indirect (Hell's Gate / Halo's Gate) | Done |
| Analysis | Hook detection (13 APIs) + API restoration (3 methods) | Done |
| IAT Evasion | Dynamic API resolution (40+ wrappers), XOR string obfuscation, string sanitization | Done |

### Phase 2: Communications Module (DONE)

Beacon loop with HTTPS channel, RC4-encrypted binary wire protocol, task execution.

```
src/comms/
  mod.rs        — beacon loop, Channel enum, CommsConfig, jitter/interval, dry_run
  protocol.rs   — binary wire format (checkin, task list, result), RC4 encrypt/decrypt
  https.rs      — HTTPS channel via WinINet (dynamic resolve, same pattern as resolve.rs)
  task.rs       — task executor (shell via CreateProcessW + pipe capture)
  dns.rs        — DNS channel stub (planned)
  smb.rs        — SMB named pipe stub (planned)
```

| Feature | Detail |
|---------|--------|
| Beacon loop | Configurable interval + jitter (percentage-based randomization) |
| HTTPS channel | WinINet via dynamic resolve, TLS, configurable host/port/path |
| Wire protocol | Binary little-endian, 3 message types (checkin, task list, result) |
| Transport crypto | RC4 symmetric encryption with configurable hex key |
| Task types | Shell (cmd.exe /c with pipe capture), sleep change, exit, nop |
| Error handling | Exponential backoff on connection errors, max retry limit |
| DNS channel | Stub — planned for future |
| SMB channel | Stub — planned for future |

### Phase 3: Loader Module (DONE)

Pre-execution environment checks — anti-sandbox, anti-debug, anti-VM.

```
src/loader/
  mod.rs         — CheckCategory enum, LoaderConfig, run_checks orchestrator, dry_run
  sandbox.rs     — 5 checks: timing, process count, disk, username, memory
  antidebug.rs   — 4 checks: IsDebuggerPresent, debug port, debug flags, timing
  antivm.rs      — 3 checks: CPUID hypervisor, registry VM keys, MAC prefix OUI
```

| Check | Technique |
|-------|-----------|
| Sandbox | Sleep acceleration (sleep 10s, check elapsed < 9s = detected) |
| Sandbox | Process count < 50 = detected |
| Sandbox | Disk size < 60GB = detected |
| Sandbox | Username contains sandbox/malware/virus/test/sample = detected |
| Sandbox | Physical memory < 2GB = detected |
| Debug | `IsDebuggerPresent()` non-zero = detected |
| Debug | `NtQueryInformationProcess(ProcessDebugPort=7)` non-zero = detected |
| Debug | `NtQueryInformationProcess(ProcessDebugFlags=0x1F)` zero = detected |
| Debug | Timing: Sleep(500) elapsed > 1500ms = detected |
| VM | CPUID bit 31 (hypervisor present) |
| VM | Registry `HKLM\SOFTWARE\VMware` / `VirtualBox` / `Hyper-V` |
| VM | MAC prefix `00:0C:29` (VMware), `08:00:27` (VBox), `00:15:5D` (Hyper-V) |

### Phase 4: Post-Exploitation — Credentials + Lateral (DONE)

Post-ex capabilities with credential harvesting and lateral movement.

```
src/postex/
  mod.rs       — PostExModule enum (9 variants), dispatch, dry_run, print_info
  creds.rs     — LSASS dump (MiniDumpWriteDump), SAM/SYSTEM export, token delegation
  lateral.rs   — PsExec (service-based), WMI exec, WinRM exec
```

| Module | Technique |
|--------|-----------|
| Memory Snapshot | SeDebugPrivilege → OpenProcess → MiniDumpWriteDump |
| Registry Export | reg.exe save HKLM\SAM + HKLM\SYSTEM |
| Session Delegation | OpenProcessToken → DuplicateTokenEx → ImpersonateLoggedOnUser |
| Remote Service | WNetAddConnection2A → CopyFileA → CreateServiceA → StartServiceA |
| Remote Execution (WMI) | wmic /node:target process call create |
| Remote Execution (WinRM) | winrs -r:target command |

Comms protocol extended with task types 4–7 (FileUpload, FileDownload, CredDump, LateralMove).

### Phase 5: Post-Exploitation — Exfil + Tunnel (DONE)

Data exfiltration and network tunneling to complete the post-ex suite.

```
src/postex/
  exfil.rs     — staged file extraction via raw sockets, 64KB chunks, optional RC4 encryption
  tunnel.rs    — SOCKS5 proxy (no-auth, IPv4/domain), port forwarding, select()-based relay
```

| Module | Technique |
|--------|-----------|
| Staged Transfer | CreateFileA → GetFileSize → read chunks → RC4 encrypt → socket send |
| Proxy Relay | WSAStartup → bind → listen → accept → SOCKS5 handshake → relay |
| Port Relay | WSAStartup → bind → listen → accept → connect remote → relay |

Comms protocol extended with task types 8–10 (Exfil, SocksConnect, PortForward). 12 ws2_32 socket API wrappers added to resolve.rs.

---

## Jebat — C2 Server

Separate repository (`jebat/`). The attacker-side command and control server that Badang implants talk to. Named after Hang Jebat — the warrior who takes command.

### Architecture

```
jebat/
├── server/                  Rust backend (axum)
│   ├── listeners/           Protocol-specific listener threads
│   │   ├── https.rs         HTTPS listener (TLS termination, RC4 wire protocol)
│   │   ├── dns.rs           DNS listener (TXT record exfil, A record tasking)
│   │   └── smb.rs           SMB named pipe listener
│   ├── protocol/            Badang wire protocol implementation
│   │   ├── wire.rs          Binary LE parser (checkin, task list, result)
│   │   ├── crypto.rs        RC4 transport encryption/decryption
│   │   └── tasks.rs         Task type definitions (must match Badang's 11 types)
│   ├── core/                Core server logic
│   │   ├── implants.rs      Implant registry (ID, OS, user, IP, last seen, config)
│   │   ├── taskqueue.rs     Per-implant FIFO task queue
│   │   ├── sessions.rs      Operator session management + auth
│   │   └── events.rs        Event bus (implant checkin, task complete, listener state)
│   ├── api/                 REST API for operator UI
│   │   ├── implants.rs      GET /implants, GET /implants/:id, DELETE /implants/:id
│   │   ├── tasks.rs         POST /tasks, GET /tasks/:id, GET /implants/:id/tasks
│   │   ├── listeners.rs     POST /listeners, DELETE /listeners/:id, GET /listeners
│   │   ├── files.rs         POST /files/upload, GET /files/:id/download
│   │   ├── builder.rs       POST /builder/generate (implant config generator)
│   │   └── ws.rs            WebSocket endpoint for real-time event push
│   ├── storage/             Persistent storage
│   │   ├── db.rs            SQLite (implants, tasks, events, files, operator logs)
│   │   └── files.rs         File store (uploads, downloads, loot, screenshots)
│   └── main.rs              Server entrypoint, config loading, signal handling
├── web/                     Operator dashboard (React + TypeScript)
│   ├── pages/
│   │   ├── Dashboard.tsx    Overview — active implants, recent events, listener status
│   │   ├── Implants.tsx     Implant table — sortable, filterable, real-time status
│   │   ├── Interact.tsx     Single implant — shell, file browser, task history, info
│   │   ├── Tasks.tsx        Global task queue — pending, running, completed, failed
│   │   ├── Listeners.tsx    Listener management — start/stop/config per protocol
│   │   ├── Files.tsx        File manager — uploads, downloads, loot organized by implant
│   │   ├── Builder.tsx      Implant config generator — C2 URL, jitter, persistence
│   │   └── Logs.tsx         Operator audit log — who did what, when
│   └── components/
│       ├── Terminal.tsx      Interactive shell (xterm.js, streams task output)
│       ├── ImplantMap.tsx    Network topology graph (implant → pivot → implant)
│       └── EventFeed.tsx     Real-time event sidebar (WebSocket-driven)
├── cli/                     Operator CLI (alternative to web UI)
│   └── main.rs              REPL — interact, task, listeners, same API as web
└── config/
    ├── jebat.toml           Server config (bind addr, TLS certs, DB path, auth)
    └── profiles/            Pre-built implant profiles (stealth, noisy, pivot)
```

### Core Components

| Component | What |
|-----------|------|
| **Listeners** | Multi-protocol (HTTPS, DNS, SMB). Each runs in its own async task. Hot-start/stop without server restart. TLS via rustls with configurable certs. |
| **Wire Protocol** | Must match Badang's `src/comms/protocol.rs` exactly — binary little-endian, 3 message types (checkin 0x01, task list 0x02, result 0x03), RC4 transport layer. |
| **Task Queue** | Per-implant FIFO. 11 task types matching Badang: Nop, Shell, SleepChange, Exit, FileUpload, FileDownload, CredDump, LateralMove, Exfil, SocksConnect, PortForward. |
| **Implant Registry** | Tracks: 16-byte agent ID, hostname, OS version, username, internal IP, external IP, last checkin time, sleep interval, jitter, active listener, implant version. |
| **Event Bus** | Internal pub/sub for real-time updates. Events: implant_checkin, implant_new, implant_dead, task_queued, task_complete, task_failed, listener_start, listener_stop. Pushed to web UI via WebSocket. |
| **Storage** | SQLite for structured data (implants, tasks, events). Filesystem for binary blobs (uploaded/downloaded files, loot). Operator audit trail for all actions. |
| **Operator Auth** | Token-based auth. Multi-operator support. Role-based: admin (full), operator (task/interact), viewer (read-only). |
| **Builder** | Generates Badang implant configs — embeds C2 URL, channel, jitter, interval, RC4 key, persistence method, loader checks. Outputs a ready-to-compile config block. |

### Build Phases

#### Phase 1: Core Server + HTTPS Listener (DONE)

Minimum viable C2 — accept Badang checkins and dispatch tasks.

| Module | What | Status |
|--------|------|--------|
| HTTPS listener | TLS termination (rustls), parse Badang wire protocol, RC4 decrypt/encrypt | Done |
| Wire protocol | Implement checkin parsing, task list serialization, result parsing | Done |
| Implant registry | In-memory registry, track agent ID + metadata from checkin | Done |
| Task queue | Per-implant FIFO, shell task support | Done |
| REST API | Basic endpoints: list implants, queue task, get results | Done |
| SQLite storage | Schema: implants, tasks, events tables | Done |
| Server CLI | `jebat serve --config jebat.toml` — start listeners, bind API | Done |

#### Phase 2: Operator Web UI (DONE)

Interactive dashboard for real-time implant management.

| Module | What | Status |
|--------|------|--------|
| Dashboard page | Active implant count, recent events, listener status cards | Done |
| Implants page | Sortable table (ID, host, user, OS, last seen, interval), row click → interact | Done |
| Interact page | Shell terminal (xterm.js), task history, implant info panel | Done |
| Tasks page | Global task list — filter by implant, status, type | Done |
| Listeners page | Listener config display, protocol info | Done |
| WebSocket events | Real-time push: new implant, checkin, task complete (tokio broadcast) | Done |
| Auth | Login page, JWT tokens, role-based access | Done |

#### Phase 3: File Operations + Loot (DONE)

Full file I/O pipeline between operator and implant.

| Module | What | Status |
|--------|------|--------|
| File store | Disk-backed loot storage organized by agent ID + type | Done |
| Loot auto-collection | CredDump, FileUpload, FileDownload results auto-stored as loot | Done |
| Upload API | Multipart file upload with agent + type metadata | Done |
| Download API | Stream loot files from disk with content-disposition headers | Done |
| Files page | Browse all loot, filter by agent/type, download from UI | Done |

#### Phase 4: Advanced Tasking (DONE)

Extended task types matching Badang's full post-ex suite.

| Module | What | Status |
|--------|------|--------|
| Task chaining | Sequential execution with auto-advance on completion | Done |
| Batch tasks | Queue multiple independent tasks in one API call | Done |
| Bulk sleep | Change sleep interval across all or selected implants | Done |
| SOCKS proxy | Start SOCKS5 tunnel via implant, track in tunnels table | Done |
| Port forwarding | Set up port relay through implant, track in tunnels table | Done |
| Tunnel management | List active tunnels, close by ID | Done |

#### Phase 5: DNS + SMB Listeners (DONE)

Alternative channels for restricted environments.

| Module | What | Status |
|--------|------|--------|
| DNS listener | UDP listener, TXT record exfil, hex-encoded RC4 wire protocol | Done |
| SMB listener | TCP listener with length-prefixed framing, same wire protocol | Done |
| Multi-protocol config | Per-listener protocol selection (https/dns/smb) in jebat.toml | Done |

#### Phase 6: Operator CLI + Builder (DONE)

Command-line alternative to web UI + implant configuration generator.

| Module | What | Status |
|--------|------|--------|
| Operator REPL | Interactive shell: implants, interact, tasks, build, partial ID resolution | Done |
| Interact mode | Per-implant shell: queue tasks by name, view results, task history | Done |
| Builder API | REST endpoint for profile listing and config generation | Done |
| Profiles | Pre-built configs: stealth (60s, indirect syscalls), noisy (5s, fast), pivot (SMB) | Done |

### Protocol Contract

Jebat must implement Badang's wire protocol byte-for-byte:

```
Checkin (0x01):  [16B agent_id][payload: hostname, OS, user, IP as null-terminated strings]
Task List (0x02): [4B count][for each: [1B task_type][4B data_len][data]]
Result (0x03):   [16B agent_id][1B task_type][1B success][4B data_len][data]
```

Transport: RC4 encrypt the entire message body with the shared hex key. HTTPS wraps it in a POST/GET to the configured path. The RC4 key is configured at build time in Badang and at runtime in Jebat's listener config.

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Same ecosystem as Badang, memory safety, async via tokio |
| HTTP framework | axum | Async, tower middleware, good WebSocket support |
| TLS | rustls | Pure Rust, no OpenSSL dependency |
| Database | SQLite (rusqlite) | Zero-config, single file, good enough for ops scale |
| Frontend | React + TypeScript | Standard, xterm.js for terminal, TanStack Table for grids |
| Build | Vite (frontend) + cargo (backend) | Fast dev builds, single binary with embedded assets |

---

## Tuah — Binary Testing Sandbox

Separate repository (`tuah/`). Lightweight detonation sandbox — automates testing Badang binaries against a Windows VM before engagement. Named after Hang Tuah — the greatest warrior, the one who proves the others are ready.

**Runs on:** Attacker machine (Linux)

### Architecture

```
tuah/
├── src/
│   ├── main.rs            CLI entry (clap subcommands)
│   ├── config.rs          TOML config structs
│   ├── vm.rs              QEMU lifecycle (start, stop, snapshot revert, wait SSH)
│   ├── ssh.rs             SSH/SCP command wrappers (shells out to ssh/scp)
│   ├── deploy.rs          File transfer + binary execution on VM
│   ├── jebat.rs           Jebat API client (login, list implants, queue task, poll)
│   ├── defender.rs        Defender status via SSH + PowerShell
│   └── report.rs          Test result formatting (pass/fail per check)
├── config/
│   └── tuah.toml          VM image path, SSH creds, Jebat server, test params
├── Cargo.toml
├── .gitignore
└── README.md
```

### Test Flow

```
tuah test <binary>
  1. Revert VM to clean snapshot         (qemu-img snapshot -a)
  2. Boot VM                             (qemu-system-x86_64)
  3. Wait for SSH ready                  (TCP connect poll)
  4. Copy binary to VM                   (scp)
  5. Record pre-execution implant list   (GET /api/implants on Jebat)
  6. Execute binary on VM                (ssh)
  7. Poll Jebat for new implant checkin  (GET /api/implants, diff)
  8. Check Defender detection status      (PowerShell Get-MpThreatDetection)
  9. Queue shell task + verify result    (POST /api/tasks, poll completion)
  10. Print test report
  11. Shutdown VM
```

### Core Components

| Component | What |
|-----------|------|
| **VM Manager** | QEMU orchestration — snapshot revert, boot with SSH port forward, clean shutdown. No heavy VM libraries, shells out to `qemu-system-x86_64` and `qemu-img`. |
| **Deployer** | SCP binary into VM, SSH execute with fire-and-forget (Badang runs in background). |
| **Jebat Client** | Same REST API pattern as `jebat-cli` — JWT login, list implants, queue task, poll task result. Detects new checkin by diffing implant list before/after execution. |
| **Defender Checker** | PowerShell over SSH — `Get-MpThreatDetection` for detections, `Get-MpComputerStatus` for real-time protection status. Reports threat name and action if detected. |
| **Reporter** | Structured test report: pass/fail per step, timing, agent ID, Defender status. |

### CLI Commands

```
tuah test <binary>     Full test cycle (revert → boot → deploy → verify → report → shutdown)
tuah vm start          Boot VM from clean snapshot
tuah vm stop           Shutdown VM
tuah vm revert         Revert to clean snapshot
tuah vm ssh            Open interactive SSH session to VM
tuah status            Check VM and Jebat connectivity
```

### Prerequisites

- QEMU installed (`qemu-system-x86_64`, `qemu-img`)
- Windows QCOW2 image with OpenSSH server enabled
- Clean snapshot saved (`qemu-img snapshot -c clean windows.qcow2`)
- `sshpass` (optional, for password-based SSH; key-based recommended)
- Jebat C2 server running and accessible

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Consistent with ecosystem |
| HTTP | reqwest | Jebat API client, same as jebat-cli |
| CLI | clap | Same as all other tools |
| VM | QEMU (shell out) | Lightweight, no library deps, snapshot support |
| SSH | ssh/scp (shell out) | Simple, leverages existing SSH config |

---

## Kasturi — Phishing Toolkit

Separate repository (`kasturi/`). Delivery platform — crafts and sends the lure that gets Badang onto the target. Named after Hang Kasturi — kasturi means "musk", the scent that draws you in.

**Runs on:** Attacker machine (Linux/macOS/Windows)

### Architecture

```
kasturi/
├── server/                  Rust backend
│   ├── campaigns/           Campaign management (create, schedule, track, report)
│   ├── templates/           Email template engine (HTML + plaintext, variable substitution)
│   ├── payloads/            Payload packaging (macro, HTA, LNK, ISO, VBS, OneNote)
│   ├── cloner/              Landing page cloner (fetch, rewrite links, host)
│   ├── tracking/            Open tracking (pixel), click tracking (redirect), download tracking
│   ├── smtp/                SMTP sender (direct, relay, provider API), DKIM signing
│   ├── api/                 REST API for web UI
│   └── main.rs              Server entrypoint
├── web/                     Operator dashboard
│   ├── Campaigns.tsx        Campaign builder — target list, template, payload, schedule
│   ├── Templates.tsx        Email template editor (live preview, variable list)
│   ├── Payloads.tsx         Payload builder — select type, embed Badang stager, preview
│   ├── Cloner.tsx           URL input → cloned page preview → host config
│   ├── Results.tsx          Campaign results — opened, clicked, downloaded, by target
│   └── Domains.tsx          Sending domain management, DNS record checker
└── config/
    └── kasturi.toml         SMTP config, tracking domain, TLS certs
```

### Core Components

| Component | What |
|-----------|------|
| **Campaign Engine** | Create campaigns: target list (CSV/manual), template, payload attachment, schedule (immediate/delayed/drip). Track per-target status: sent, opened, clicked, downloaded. |
| **Template Engine** | HTML email templates with variable substitution (`{{first_name}}`, `{{company}}`, `{{tracking_url}}`). Plaintext fallback. Import/export. Library of presets (invoice, delivery, IT alert, meeting). |
| **Payload Packager** | Wrap Badang stager in delivery formats: Office macro (.docm/.xlsm), HTA, LNK, ISO/IMG, VBS, OneNote (.one), HTML smuggling. Each format embeds the encrypted payload with auto-execute or one-click trigger. |
| **Landing Page Cloner** | Input a URL → fetch page + assets → rewrite links to point at Kasturi → host as a credential capture page. Captured creds logged per campaign. |
| **Tracking** | Invisible 1x1 tracking pixel (email open), redirect link (click tracking), download beacon (payload execution). All events tied to campaign + target. |
| **SMTP** | Direct send, relay via provider (SendGrid, Mailgun, AWS SES), or custom SMTP. DKIM signing, SPF-aware sending domain rotation. |

### Build Phases

| Phase | What |
|-------|------|
| 1 | Campaign engine + SMTP sender + email templates |
| 2 | Payload packager (macro, HTA, LNK) |
| 3 | Landing page cloner + credential capture |
| 4 | Tracking (open, click, download) + results dashboard |
| 5 | Extended payloads (ISO, HTML smuggling, OneNote) |
| 6 | Domain management + DNS health checker |

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Consistent with ecosystem, async SMTP via lettre |
| HTTP framework | axum | Same as Jebat, shared patterns |
| Email | lettre | Rust SMTP client, DKIM support |
| Template | tera | Jinja2-style templating, good for email HTML |
| Frontend | React + TypeScript | Same as Jebat |
| Clone engine | reqwest + scraper | Fetch + parse + rewrite HTML |

---

## Lekir — Recon/OSINT

Separate repository (`lekir/`). Intelligence gathering — maps the target's attack surface before anything else runs. Named after Hang Lekir — the scout who gathers information before the fight.

**Runs on:** Attacker machine (Linux/macOS/Windows)

### Architecture

```
lekir/
├── core/                    Rust backend
│   ├── domains/             Domain intelligence
│   │   ├── subdomains.rs    Subdomain enumeration (brute, cert transparency, DNS records)
│   │   ├── dns.rs           DNS record lookup (A, AAAA, MX, TXT, NS, CNAME, SOA)
│   │   ├── whois.rs         WHOIS lookup + registrar info
│   │   └── certs.rs         Certificate transparency log search (crt.sh)
│   ├── people/              People intelligence
│   │   ├── emails.rs        Email harvesting (Hunter, public sources, pattern guessing)
│   │   ├── social.rs        Social media profile discovery (LinkedIn, GitHub, Twitter)
│   │   └── breaches.rs      Breach database lookup (HaveIBeenPwned, DeHashed)
│   ├── infra/               Infrastructure intelligence
│   │   ├── ports.rs         Port scanning (TCP connect, SYN where available)
│   │   ├── services.rs      Service fingerprinting (banner grab, version detect)
│   │   ├── tech.rs          Technology stack detection (Wappalyzer-style, headers, response)
│   │   └── cloud.rs         Cloud asset discovery (S3 buckets, Azure blobs, GCP storage)
│   ├── passive/             Passive collection
│   │   ├── shodan.rs        Shodan API integration
│   │   ├── censys.rs        Censys API integration
│   │   └── archive.rs       Wayback Machine URL scraping
│   ├── report/              Output + reporting
│   │   ├── json.rs          Machine-readable JSON output
│   │   ├── html.rs          HTML report with charts and tables
│   │   └── feed.rs          Live output feed to Kasturi (target lists) and Jebat (infra map)
│   └── main.rs              CLI entrypoint
├── web/                     Web dashboard (optional)
│   ├── Targets.tsx          Target organization management
│   ├── Domains.tsx          Domain tree view — subs, DNS, certs, ports
│   ├── People.tsx           Email/social discovery results
│   ├── Infra.tsx            Infrastructure map — IPs, ports, services, tech stack
│   └── Reports.tsx          Generated reports, export
└── config/
    ├── lekir.toml           API keys (Shodan, Censys, Hunter), scan config
    └── wordlists/           Subdomain brute-force wordlists
```

### Core Components

| Component | What |
|-----------|------|
| **Subdomain Enum** | Multi-source: DNS brute-force (wordlist), certificate transparency (crt.sh), search engine dorking, DNS zone transfer attempt, recursive CNAME/NS following. |
| **Email Harvest** | Pattern-based guessing (first.last, flast, firstl), Hunter.io API, LinkedIn scraping, public document metadata (PDF/DOCX author fields), PGP key servers. |
| **Tech Fingerprint** | HTTP response analysis: headers (Server, X-Powered-By), HTML meta tags, JavaScript library detection, cookie names, favicon hash. Wappalyzer-compatible rule engine. |
| **Port Scan** | TCP connect scan (default), SYN scan (Linux, requires root). Service banner grabbing on open ports. Configurable port ranges and rate limiting. |
| **Breach Lookup** | HaveIBeenPwned API, DeHashed API. Checks discovered emails against breach databases. Reports which services were compromised and when. |
| **Cloud Discovery** | Brute-force S3 bucket names (`target-backup`, `target-dev`, etc.), Azure blob containers, GCP storage buckets. Check for public access misconfigurations. |
| **Report Engine** | Aggregate all findings into JSON (machine-readable, feeds into Kasturi/Jebat) or HTML (operator-readable, charts + tables). Auto-generate target email list for Kasturi campaigns. |

### Build Phases

| Phase | What |
|-------|------|
| 1 | Subdomain enum (brute + cert transparency + DNS) + DNS record lookup |
| 2 | Email harvesting (pattern guess + Hunter API + public sources) |
| 3 | Port scanning + service fingerprint + tech stack detection |
| 4 | Breach lookup (HIBP + DeHashed) + social profile discovery |
| 5 | Cloud asset discovery (S3, Azure, GCP) + passive collection (Shodan, Censys) |
| 6 | Report engine (JSON + HTML) + live feed to Kasturi/Jebat |

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Async I/O for concurrent scanning, same ecosystem |
| HTTP | reqwest | Async HTTP client for API calls and web scraping |
| DNS | trust-dns / hickory-dns | Async DNS resolver, supports all record types |
| Concurrency | tokio | Async runtime, rate-limited task spawning |
| Output | serde_json + tera | JSON export + HTML report templating |
| Frontend | React + TypeScript (optional) | Web dashboard, same stack as Jebat/Kasturi |

---

## Where Each Project Runs

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  ATTACKER MACHINE (Linux/macOS/Windows)                         │
│                                                                 │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐               │
│  │   LEKIR    │  │  KASTURI   │  │   JEBAT    │               │
│  │   recon    │─►│  phishing  │  │  C2 server │               │
│  │            │  │            │  │            │               │
│  │ runs here  │  │ runs here  │  │ runs here  │               │
│  └────────────┘  └─────┬──────┘  └──────┬─────┘               │
│                        │                │                      │
│  ┌─────────────────────┴────────────────┘                      │
│  │  BADANG (builder side)                                      │
│  │  generate, encrypt, convert, package                        │
│  │  runs here — produces the binary that runs on target        │
│  └────────┬──────────────────────────┬─────────────────────┐   │
│           │                          │                     │   │
│           │               ┌──────────▼─────────┐           │   │
│           │               │  TUAH (sandbox)    │           │   │
│           │               │  QEMU VM test      │           │   │
│           │               │  deploy + detonate  │           │   │
│           │               │  verify checkin    │──────────►│   │
│           │               │  Defender check    │  Jebat    │   │
│           │               └────────────────────┘  API      │   │
│           │                                                │   │
└───────────┼────────────────────────────────────────────────┼───┘
            │  delivers payload          commands            │
            │  (email/USB/web)           (HTTPS/DNS/SMB)     │
            ▼                                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  TARGET MACHINE (Windows)                                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────┐      │
│  │                BADANG (implant side)                   │      │
│  │                                                       │      │
│  │  loader → evasion → inject → persist → comms → postex │      │
│  │                                                       │      │
│  │  runs here (the only code that touches the target)    │      │
│  └──────────────────────────────────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Build Order

| Phase | What | Project | Runs On | Status |
|-------|------|---------|---------|--------|
| 1 | Core platform (8 inject, 6 persist, stager, packaging, evasion, syscalls) | Badang | Attacker (build) + Target (run) | **Done** |
| 2 | Comms module (beacon loop + HTTPS channel + RC4 transport) | Badang | Target (Windows) | **Done** |
| 3 | Loader module (anti-sandbox + anti-debug + anti-VM) | Badang | Target (Windows) | **Done** |
| 4 | Post-ex: credentials + lateral movement | Badang | Target (Windows) | **Done** |
| 5 | Post-ex: exfiltration + tunneling | Badang | Target (Windows) | **Done** |
| 6 | Core server + HTTPS listener | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 7 | Operator web UI | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 8 | File operations + loot management | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 9 | Advanced tasking (lateral, exfil, tunnel) | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 10 | DNS + SMB listeners | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 11 | Operator CLI + implant builder | Jebat | Attacker (Linux/macOS/Win) | **Done** |
| 12 | VM orchestration + deploy + Jebat checkin verify + Defender check + report | Tuah | Attacker (Linux) | Planned |
| 13 | Campaign engine + SMTP + templates | Kasturi | Attacker (Linux/macOS/Win) | Planned |
| 14 | Payload packager + landing page cloner | Kasturi | Attacker (Linux/macOS/Win) | Planned |
| 15 | Tracking + results dashboard | Kasturi | Attacker (Linux/macOS/Win) | Planned |
| 16 | Subdomain enum + DNS + email harvest | Lekir | Attacker (Linux/macOS/Win) | Planned |
| 17 | Port scan + tech fingerprint + breach lookup | Lekir | Attacker (Linux/macOS/Win) | Planned |
| 18 | Cloud discovery + passive collection + reporting | Lekir | Attacker (Linux/macOS/Win) | Planned |

Badang and Jebat are complete. Build order: Tuah → Kasturi → Lekir.

---

## Shared Design Principles

All projects follow the patterns established in Badang:

| Principle | Implementation |
|-----------|---------------|
| **Language** | Rust — memory safety, small binaries, no runtime dependency |
| **Safety** | Dry-run by default, explicit confirmation for live/destructive ops |
| **Dual interface** | CLI for automation, web UI for interactive use |
| **Cross-platform** | Badang: cross-compile to Windows from Linux. Jebat/Kasturi/Lekir: native Linux/macOS/Windows |
| **CI/CD** | GitHub Actions — fmt, clippy, test, audit, cross-compile, artifact upload |

Badang-specific (target-side only):

| Principle | Implementation |
|-----------|---------------|
| **String obfuscation** | Multi-byte XOR at compile time, decrypt at runtime |
| **API resolution** | Dynamic via GetModuleHandleA + GetProcAddress |
| **IAT hygiene** | Minimal imports — only bootstrap functions visible |
| **String sanitization** | No offensive keywords in compiled binary |
| **PE metadata** | Version info, manifest, icon — look like a normal app |
| **Release profile** | `strip`, `lto`, `opt-level = 3`, `codegen-units = 1`, `panic = abort` |
| **Defender bypass** | Every binary passes static analysis out of the box |

---

*All tools are for authorized security research and red team operations only.*
