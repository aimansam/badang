# Roadmap

Two projects cover the full kill chain. Badang is the implant — everything that runs on the target. Jebat is the next project — the attacker-side command and control server.

---

## The 2 Projects

| # | Project | Role | Status |
|---|---------|------|--------|
| 1 | **Badang** (implant) | Target-side platform — evasion, injection, persistence, comms, loader, post-ex | All phases complete |
| 2 | **Jebat** (C2 server) | Attacker-side — listeners, task queue, implant management, operator web UI | Planned |

Future additions (separate projects):

| # | Project | Role |
|---|---------|------|
| 3 | **Phishing Toolkit** | Delivery — email templates, macro/HTA/LNK/ISO packaging, tracking, landing page cloner |
| 4 | **Recon/OSINT** | Reconnaissance — subdomain enum, email harvest, tech fingerprint, breach lookup |

---

## Kill Chain Coverage

```
┌──────────────────────────────────────────────────────────────────────┐
│                         RED TEAM KILL CHAIN                          │
│                 2 projects, full target + attacker coverage           │
├──────────────┬───────────────────────────────────────────────────────┤
│              │                                                       │
│  1. RECON    │  [4] Recon/OSINT (future)                             │
│              │      Subdomain enum, email harvest, tech fingerprint   │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  2. WEAPON-  │  [1] Badang                                           │
│     IZE      │      Payload generation (exec, reverse, bind, stager) │
│              │      Payload encryption (XOR/RC4 + PIC stubs)         │
│              │      Output formats (Exe, Ps1, CSharp, Dll)           │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  3. DELIVER  │  [3] Phishing Toolkit (future)                        │
│              │      Email templates, macro/HTA/LNK/ISO packaging     │
│              │  [1] Badang — Loader module                            │
│              │      Anti-sandbox, anti-debug, anti-VM, staged fetch   │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  4. EXPLOIT  │  [1] Badang — Loader + Evasion                        │
│              │      Sandbox detection, anti-debug, in-memory exec     │
│              │      ETW patching, AMSI bypass, indirect syscalls      │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  5. INSTALL  │  [1] Badang — Injection + Persistence                 │
│              │      8 injection techniques (CRT, APC, hijack, early   │
│              │      bird, section map, callback, stomp, hollowing)    │
│              │      6 persistence methods (registry, schtask, WMI,    │
│              │      COM, DLL hijack, service creation)                │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  6. C2       │  [1] Badang — Comms module (target-side)              │
│              │      Beacon loop, jitter, HTTPS/DNS/SMB channels,     │
│              │      RC4 transport encryption                          │
│              │  [2] Jebat (attacker-side)                            │
│              │      Listeners, task queue, operator web UI,           │
│              │      implant tracking, payload builder                 │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  7. ACTIONS  │  [1] Badang — Post-ex modules (9 modules)              │
│              │      Credentials — LSASS dump, SAM/SYSTEM, tokens     │
│              │      Lateral    — PsExec, WMI, WinRM                  │
│              │      Exfil      — staged TCP, 64KB chunks, RC4        │
│              │      Tunnel     — SOCKS5 proxy, port forward           │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  EVASION     │  [1] Badang — active throughout every stage           │
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
TARGET MACHINE                              ATTACKER MACHINE
──────────────                              ────────────────

┌─────────────────────────────────┐
│          BADANG (main)          │
│                                 │
│  ┌──────────┐  ┌─────────────┐ │
│  │ Loader   │  │ Evasion     │ │
│  │ anti-sb  │  │ ETW/AMSI    │ │
│  │ anti-dbg │  │ sleep obfs  │ │         ┌──────────────────┐
│  │ anti-vm  │  │ stack spoof │ │         │   JEBAT           │
│  └────┬─────┘  └──────┬──────┘ │         │   (C2 server)    │
│       │               │        │         │                  │
│  ┌────▼───────────────▼──────┐ │  HTTPS  │  ┌────────────┐ │
│  │ Injection (8 techniques)  │ │ ◄──────►│  │ Listeners  │ │
│  └────────────┬──────────────┘ │  DNS    │  │ Task Queue │ │
│               │                │  SMB    │  │ Web UI     │ │
│  ┌────────────▼──────────────┐ │         │  │ Tracking   │ │
│  │ Comms (beacon loop)       │─┼─────────┼──┤            │ │
│  │ HTTPS / DNS / SMB channel │ │         │  └────────────┘ │
│  │ RC4 transport              │ │         │                  │
│  └────────────┬──────────────┘ │         └──────────────────┘
│               │                │
│  ┌────────────▼──────────────┐ │
│  │ Persistence (6 methods)   │ │
│  └────────────┬──────────────┘ │
│               │                │
│  ┌────────────▼──────────────┐ │
│  │ Post-Ex modules           │ │
│  │ creds │ lateral │ exfil   │ │
│  │ tunnel │ ...              │ │
│  └───────────────────────────┘ │
│                                 │
│  Payload gen + packaging        │
│  (builds output for delivery)   │
└─────────────────────────────────┘
```

---

## Badang — Build Phases

### Phase 1: Core Platform (DONE)

All shipped and pushed. Badang is the weaponize + exploit + install platform.

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

#### Phase 1: Core Server + HTTPS Listener

Minimum viable C2 — accept Badang checkins and dispatch tasks.

| Module | What |
|--------|------|
| HTTPS listener | TLS termination (rustls), parse Badang wire protocol, RC4 decrypt/encrypt |
| Wire protocol | Implement checkin parsing, task list serialization, result parsing |
| Implant registry | In-memory registry, track agent ID + metadata from checkin |
| Task queue | Per-implant FIFO, shell task support |
| REST API | Basic endpoints: list implants, queue task, get results |
| SQLite storage | Schema: implants, tasks, task_results tables |
| Server CLI | `jebat serve --config jebat.toml` — start listeners, bind API |

**Verification:** Start Jebat, point a Badang implant at it, confirm checkin → shell task → result round-trip.

#### Phase 2: Operator Web UI

Interactive dashboard for real-time implant management.

| Module | What |
|--------|------|
| Dashboard page | Active implant count, recent events, listener status cards |
| Implants page | Sortable table (ID, host, user, OS, last seen, interval), row click → interact |
| Interact page | Shell terminal (xterm.js), task history, implant info panel, file browser |
| Tasks page | Global task list — filter by implant, status, type |
| Listeners page | Start/stop listeners, configure TLS certs, view connection log |
| WebSocket events | Real-time push: new implant, checkin, task complete |
| Auth | Login page, JWT tokens, role-based route guards |

#### Phase 3: File Operations + Loot

Full file I/O pipeline between operator and implant.

| Module | What |
|--------|------|
| File upload | Operator uploads file → queued as FileUpload task → Badang writes to disk |
| File download | Operator requests file → FileDownload task → Badang reads and returns |
| Loot storage | Auto-organize downloaded files by implant ID + timestamp |
| Credential dump | Trigger CredDump task → store result as loot (LSASS dump, SAM/SYSTEM) |
| Files page | Browse all uploads/downloads, filter by implant, download from UI |

#### Phase 4: Advanced Tasking

Extended task types matching Badang's full post-ex suite.

| Module | What |
|--------|------|
| Lateral movement | Queue LateralMove tasks — psexec, wmi, winrm with params |
| Exfiltration | Queue Exfil tasks — trigger staged file transfer from implant |
| SOCKS proxy | Queue SocksConnect — start SOCKS5 proxy on implant, relay through Jebat |
| Port forwarding | Queue PortForward — set up port relay through implant |
| Task chaining | Queue multiple tasks as a sequence — execute in order, abort on failure |
| Sleep management | Bulk sleep change across implants, per-implant override |

#### Phase 5: DNS + SMB Listeners

Alternative channels for restricted environments.

| Module | What |
|--------|------|
| DNS listener | TXT record exfil (data in DNS queries), A record tasking (responses encode tasks) |
| SMB listener | Named pipe listener for internal network pivoting |
| Channel switching | Implant can switch channels without re-deployment (via SleepChange-like task) |
| Redirectors | Support for domain fronting (HTTPS) and DNS redirector configs |

#### Phase 6: Operator CLI + Builder

Command-line alternative to web UI + implant configuration generator.

| Module | What |
|--------|------|
| Operator CLI | REPL interface: `interact <id>`, `shell <cmd>`, `upload/download`, `listeners` |
| Implant builder | Generate Badang config: C2 URL, channel, keys, jitter, persistence, loader checks |
| Profiles | Pre-built configs: stealth (long interval, DNS), noisy (short interval, HTTPS), pivot (SMB) |
| Export | Generate ready-to-compile Rust config block or TOML for Badang |

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

## Build Order

| Phase | What | Project | Status |
|-------|------|---------|--------|
| 1 | Core platform (8 inject, 6 persist, stager, packaging, evasion, syscalls) | Badang | **Done** |
| 2 | Comms module (beacon loop + HTTPS channel + RC4 transport) | Badang | **Done** |
| 3 | Loader module (anti-sandbox + anti-debug + anti-VM) | Badang | **Done** |
| 4 | Post-ex: credentials + lateral movement | Badang | **Done** |
| 5 | Post-ex: exfiltration + tunneling | Badang | **Done** |
| 6 | Core server + HTTPS listener | Jebat | Planned |
| 7 | Operator web UI | Jebat | Planned |
| 8 | File operations + loot management | Jebat | Planned |
| 9 | Advanced tasking (lateral, exfil, tunnel) | Jebat | Planned |
| 10 | DNS + SMB listeners | Jebat | Planned |
| 11 | Operator CLI + implant builder | Jebat | Planned |
| 12 | Phishing toolkit + Recon/OSINT | New projects | Future |

Badang is complete — Jebat is the next project to build.

---

## Shared Design Principles

All projects follow the patterns established in Badang:

| Principle | Implementation |
|-----------|---------------|
| **Language** | Rust — memory safety, small binaries, no runtime dependency |
| **String obfuscation** | Multi-byte XOR at compile time, decrypt at runtime |
| **API resolution** | Dynamic via GetModuleHandleA + GetProcAddress |
| **IAT hygiene** | Minimal imports — only bootstrap functions visible |
| **String sanitization** | No offensive keywords in compiled binary |
| **PE metadata** | Version info, manifest, icon — look like a normal app |
| **Release profile** | `strip`, `lto`, `opt-level = 3`, `codegen-units = 1`, `panic = abort` |
| **Safety** | Dry-run by default, explicit confirmation for live ops |
| **Dual interface** | CLI for automation, native GUI for interactive use |
| **Cross-compile** | Build Windows binaries from Linux via mingw-w64 |
| **CI/CD** | GitHub Actions — fmt, clippy, test, audit, cross-compile, artifact upload |
| **Defender bypass** | Every binary passes static analysis out of the box |

---

*All tools are for authorized security research and red team operations only.*
