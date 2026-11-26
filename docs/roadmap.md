# Roadmap

Five projects cover the full kill chain, named after the legendary Malay warriors of the *Hikayat Hang Tuah*.

---

## The 5 Projects

| # | Project | Named After | Role | Status |
|---|---------|-------------|------|--------|
| 1 | **Badang** | Hang Badang — the strongman | **Dual role:** attacker-side (generate, encrypt, convert, package) + target-side implant (loader, evasion, inject, persist, comms, post-ex) | All phases complete |
| 2 | **Jebat** | Hang Jebat — the commander | C2 server — listeners, task queue, implant management, operator UI | All phases complete |
| 3 | **Tuah** | Hang Tuah — the greatest warrior | Binary testing sandbox — Docker + Wine + ClamAV + YARA, execute Badang builds, verify Jebat checkin, AV evasion scoring | Complete |
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

Separate repository (`tuah/`). Docker-based detonation sandbox — runs Badang binaries under Wine in disposable containers, scans with ClamAV + YARA, and verifies Jebat C2 checkin. Named after Hang Tuah — the greatest warrior, the one who proves the others are ready.

**Runs on:** Any machine with Docker (Linux, macOS, Windows/WSL)

### Architecture

```
tuah/
├── src/
│   ├── main.rs         CLI entry (clap subcommands)
│   ├── config.rs       TOML config structs
│   ├── sandbox.rs      Docker container lifecycle (scan, run, stop, check)
│   ├── scanner.rs      ClamAV + YARA scan result types
│   ├── jebat.rs        Jebat API client (login, implants, tasks)
│   └── report.rs       Test result formatting (pass/fail per step)
├── sandbox/
│   ├── Dockerfile      Wine + ClamAV + YARA image (Debian)
│   └── entrypoint.sh   Scan/run/check dispatcher
├── rules/
│   └── badang.yar      YARA detection rules
├── config/
│   └── tuah.toml       Sandbox image, network, Jebat server, test params
├── test.sh             One-command chain test (builds sandbox, starts Jebat, runs test)
├── Cargo.toml
├── Dockerfile          Tuah tool container
├── docker-compose.yml
└── .gitignore
```

### Test Flow

```
tuah test <binary>
  1. Check sandbox Docker image exists
  2. Scan binary with ClamAV + YARA
  3. Connect to Jebat, record implant list
  4. Run binary in Docker container (Wine)
  5. Poll Jebat for new implant checkin
  6. Queue shell task + verify result
  7. Print test report
  8. Remove container
```

Fresh container per test — no snapshots, no boot wait, seconds to spin up.

### Core Components

| Component | What |
|-----------|------|
| **Sandbox** | Docker container management — spin up fresh container per test, mount binary read-only, host networking so Wine-executed implant can reach Jebat, cleanup via `docker rm`. |
| **Scanner** | ClamAV signature scan + YARA custom rules inside the container. Returns JSON: detected/clean per engine, matched rule names. Custom rules in `rules/`. |
| **Jebat Client** | Same REST API pattern as `jebat-cli` — JWT login, list implants, queue task, poll task result. Detects new checkin by diffing implant list before/after execution. |
| **Reporter** | Structured test report: pass/fail per step, timing, agent ID, AV scan results. |

### CLI Commands

```
tuah test <binary>     Full chain test (scan → execute → checkin → task → report)
tuah scan <binary>     Scan binary with ClamAV + YARA (no execution)
tuah build             Build the sandbox Docker image
tuah status            Check Docker, sandbox image, and Jebat connectivity
```

### Prerequisites

- Docker installed
- Jebat C2 server running and accessible
- Badang binary cross-compiled for Windows

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Consistent with ecosystem |
| HTTP | reqwest | Jebat API client |
| CLI | clap | Same as all other tools |
| Sandbox | Docker + Wine | Portable, no KVM/QEMU required, seconds to spin up |
| AV | ClamAV + YARA | Signature + custom rule scanning, tunable detection |
| Config | TOML (toml crate) | Same as all other tools |

---

## Kasturi — Phishing Toolkit

Separate repository (`kasturi/`). Delivery platform — crafts and sends the lure that gets Badang onto the target. Named after Hang Kasturi — kasturi means "musk", the scent that draws you in.

**Runs on:** Attacker machine (Linux/macOS/Windows)

### Architecture

```
kasturi/
├── server/                      Rust backend (axum)
│   └── src/
│       ├── main.rs              Server entry + config loading
│       ├── config.rs            TOML config structs
│       ├── state.rs             Shared app state (db, event bus)
│       ├── storage/db.rs        SQLite schema + queries
│       ├── campaigns/
│       │   ├── engine.rs        Campaign lifecycle (create, schedule, execute, pause)
│       │   └── targets.rs       Target list (CSV import, manual add, dedup)
│       ├── templates/
│       │   ├── engine.rs        Tera rendering with variable substitution
│       │   └── presets.rs       Built-in template library
│       ├── smtp/sender.rs       lettre SMTP (direct, relay, provider API)
│       ├── payloads/
│       │   ├── hta.rs           HTA wrapper (mshta.exe, embedded VBScript)
│       │   ├── lnk.rs           LNK shortcut (PowerShell download cradle)
│       │   ├── vbs.rs           VBS dropper (WScript.Shell.Run)
│       │   ├── macro_gen.rs     VBA macro source for Office docs
│       │   ├── iso.rs           ISO container (LNK + hidden payload)
│       │   ├── smuggle.rs       HTML smuggling (JS blob, auto-download)
│       │   └── onenote.rs       OneNote .one with embedded payload
│       ├── cloner/engine.rs     Page fetch + rewrite + serve + cred capture
│       ├── tracking/
│       │   ├── pixel.rs         1x1 PNG open tracking per target
│       │   ├── redirect.rs      Click tracking via redirect
│       │   └── download.rs      Payload download tracking
│       ├── domains/health.rs    SPF/DKIM/DMARC DNS validation
│       ├── core/events.rs       Event bus (tokio broadcast)
│       └── api/
│           ├── mod.rs           Router assembly
│           ├── auth.rs          JWT auth
│           ├── campaigns.rs     Campaign CRUD + send trigger
│           ├── templates.rs     Template CRUD + preview
│           ├── targets.rs       Target list management
│           ├── payloads.rs      Payload generation
│           ├── cloner.rs        Clone + credential capture
│           ├── results.rs       Campaign results + stats
│           ├── domains.rs       Domain management
│           └── ws.rs            WebSocket events
├── web/                         Operator dashboard (React + TypeScript)
│   └── src/
│       ├── App.tsx              Layout + routing + dark theme
│       ├── pages/
│       │   ├── Login.tsx        Terminal-style login
│       │   ├── Dashboard.tsx    Campaign stats overview
│       │   ├── Campaigns.tsx    Campaign list + create wizard
│       │   ├── Templates.tsx    Template editor + preview
│       │   ├── Payloads.tsx     Payload generator UI
│       │   ├── Cloner.tsx       URL clone → preview → host
│       │   ├── Results.tsx      Per-campaign results (table + charts)
│       │   └── Domains.tsx      Sending domain management
│       ├── components/EventFeed.tsx
│       └── lib/                 API client, auth, WebSocket
├── config/
│   ├── kasturi.toml             Server + SMTP config
│   └── templates/               Pre-built email templates
│       ├── invoice.html
│       ├── it_alert.html
│       ├── delivery.html
│       └── meeting.html
├── Dockerfile                   Multi-stage: rust + node + debian:trixie-slim
├── docker-compose.yml           Port 8080, kasturi-data volume
├── .dockerignore
├── Cargo.toml                   Workspace root
└── .gitignore
```

### Core Components

| Component | What |
|-----------|------|
| **Campaign Engine** | Create campaigns: target list (CSV/manual), template, payload attachment, schedule (immediate/delayed/drip). Track per-target status: sent, opened, clicked, downloaded. |
| **Template Engine** | HTML email templates with variable substitution (`{{first_name}}`, `{{company}}`, `{{tracking_url}}`). Plaintext fallback. Import/export. Library of presets (invoice, delivery, IT alert, meeting). |
| **Payload Packager** | Wrap Badang stager in delivery formats: HTA, LNK, VBS, Office macro, ISO/IMG, OneNote, HTML smuggling. Each format embeds the encrypted payload with auto-execute or one-click trigger. |
| **Landing Page Cloner** | Input a URL → fetch page + assets → rewrite links to point at Kasturi → host as a credential capture page. Captured creds logged per campaign. |
| **Tracking** | Invisible 1x1 tracking pixel (email open), redirect link (click tracking), download beacon (payload execution). All events tied to campaign + target. |
| **SMTP** | Direct send, relay via provider (SendGrid, Mailgun, AWS SES), or custom SMTP. DKIM signing, SPF-aware sending domain rotation. |

### Build Phases

#### Phase 1: Core Server + SMTP + Campaign Engine + Templates

Minimum viable phishing platform — create a campaign, write templates, import targets, send emails.

| Module | What | Status |
|--------|------|--------|
| Server bootstrap | axum + SQLite + config + JWT auth (same pattern as Jebat) | **Done** |
| Campaign engine | Create, schedule (immediate/delayed/drip), execute, pause campaigns | **Done** |
| Target management | CSV import, manual add, dedup, per-target status tracking | **Done** |
| Template engine | Tera-based HTML + plaintext rendering, variable substitution | **Done** |
| Template presets | 4 built-in templates: invoice, IT alert, delivery, meeting invite | **Done** |
| SMTP sender | lettre crate — direct send, relay, provider API (SendGrid/SES) | **Done** |
| REST API | Campaign/template/target CRUD, send trigger, preview endpoint | **Done** |

**DB tables:** `campaigns` (id, name, template_id, status, send_mode, schedule), `targets` (id, campaign_id, email, first_name, last_name, company, position, status), `templates` (id, name, subject, body_html, body_text, sender_name, sender_email), `events` (id, event_type, campaign_id, target_id, detail)

**Template variables:** `{{first_name}}`, `{{last_name}}`, `{{email}}`, `{{company}}`, `{{position}}`, `{{tracking_url}}`, `{{payload_url}}`, `{{date}}`

#### Phase 2: Payload Packager + Landing Page Cloner

Wrap Badang stagers in delivery formats, clone login pages for credential harvesting.

| Module | What | Status |
|--------|------|--------|
| HTA wrapper | mshta.exe auto-runs embedded VBScript, downloads + executes stager | **Done** |
| LNK generator | Windows shortcut with hidden PowerShell download cradle | **Done** |
| VBS dropper | WScript.Shell.Run downloads and executes stager | **Done** |
| Macro generator | Auto_Open VBA code for .docm with Shell download cradle | **Done** |
| Page cloner | reqwest + scraper: fetch page + assets, rewrite links, serve via Kasturi | **Done** |
| Credential capture | Form interception on cloned pages, log to DB per campaign + target | **Done** |

**DB tables:** `payloads` (id, campaign_id, payload_type, stager_path, filename, data), `cloned_pages` (id, campaign_id, source_url, serve_path), `captured_creds` (id, page_id, campaign_id, target_id, username, password, ip_address, user_agent)

**Public endpoints:** `GET /c/:path` (serve cloned page), `POST /c/:path` (capture form submission)

#### Phase 3: Tracking + Results + Web UI

Real-time campaign tracking and operator dashboard.

| Module | What | Status |
|--------|------|--------|
| Open tracking | 1x1 PNG pixel with unique token per target — `GET /t/:token` | **Done** |
| Click tracking | Redirect through Kasturi with logging — `GET /r/:token` | **Done** |
| Download tracking | Payload served with event logging — `GET /d/:token` | **Done** |
| Results API | Per-campaign stats (sent/opened/clicked/downloaded), timeline, event feed | **Done** |
| WebSocket events | Real-time push: email sent, opened, clicked, downloaded (tokio broadcast) | **Done** |
| React web UI | Dashboard, Campaigns, Templates, Payloads, Cloner, Results, Domains pages | **Done** |
| JWT auth | Login page, token-based access (same pattern as Jebat) | **Done** |

**Tracking token:** Base64-encoded `{campaign_id}:{target_id}:{random}` — unique per email per target. Embedded in template as `{{tracking_url}}` (pixel), link wrapper (redirect), `{{payload_url}}` (download).

#### Phase 4: Extended Payloads + Domain Management

Advanced delivery formats for email gateway bypass and sending infrastructure management.

| Module | What | Status |
|--------|------|--------|
| ISO container | LNK + hidden payload inside .iso — Windows auto-mounts on double-click | **Done** |
| HTML smuggling | JavaScript blob construction, auto-download trigger, bypasses email filters | **Done** |
| OneNote embed | .one file with embedded payload behind "click to view" overlay | **Done** |
| Domain management | Add/remove sending domains, per-domain SMTP credentials | **Done** |
| DNS health checker | SPF (TXT), DKIM (TXT), DMARC (TXT) validation per domain | **Done** |
| Domain rotation | Campaign engine cycles through verified domains to avoid blocklisting | **Done** |

**DB table:** `domains` (id, domain, smtp_host, smtp_port, smtp_user, smtp_pass, spf_valid, dkim_valid, dmarc_valid, last_checked)

### Tech Stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Language | Rust | Consistent with ecosystem, async SMTP via lettre |
| HTTP framework | axum | Same as Jebat, shared patterns |
| Email | lettre | Rust SMTP client, DKIM support |
| Template | tera | Jinja2-style templating, good for email HTML |
| Frontend | React + TypeScript | Same as Jebat |
| Clone engine | reqwest + scraper | Fetch + parse + rewrite HTML |
| DNS | hickory-dns | Async DNS resolver for SPF/DKIM/DMARC checks |

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
│           │               │  Docker sandbox    │           │   │
│           │               │  Wine + ClamAV     │           │   │
│           │               │  YARA scan         │──────────►│   │
│           │               │  verify checkin    │  Jebat    │   │
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
| 12 | Docker sandbox + Wine exec + ClamAV/YARA scan + Jebat checkin verify + report | Tuah | Attacker (any with Docker) | **Done** |
| 13 | Core server + SMTP sender + campaign engine + email templates | Kasturi | Attacker (Linux/macOS/Win) | **Done** |
| 14 | Payload packager (HTA, LNK, VBS, macro) + landing page cloner | Kasturi | Attacker (Linux/macOS/Win) | **Done** |
| 15 | Tracking (pixel, click, download) + results + React web UI | Kasturi | Attacker (Linux/macOS/Win) | **Done** |
| 16 | Extended payloads (ISO, HTML smuggling, OneNote) + domain management | Kasturi | Attacker (Linux/macOS/Win) | **Done** |
| 17 | Subdomain enum + DNS + email harvest | Lekir | Attacker (Linux/macOS/Win) | Planned |
| 18 | Port scan + tech fingerprint + breach lookup | Lekir | Attacker (Linux/macOS/Win) | Planned |
| 19 | Cloud discovery + passive collection + reporting | Lekir | Attacker (Linux/macOS/Win) | Planned |

Badang, Jebat, Tuah, and Kasturi are complete. Build order next: Lekir.

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
