# Roadmap

Two projects cover the full kill chain. Badang is the main project — everything that runs on the target. The C2 server is the next project — the attacker-side control plane.

---

## The 2 Projects

| # | Project | Role | Status |
|---|---------|------|--------|
| 1 | **Badang** (main) | Target-side platform — evasion, injection, persistence, comms, loader, post-ex | All phases complete |
| 2 | **C2 Server** (next) | Attacker-side — listeners, task queue, operator web UI | Planned |

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
│              │  [2] C2 Server (attacker-side)                        │
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
│  │ anti-vm  │  │ stack spoof │ │         │   C2 SERVER      │
│  └────┬─────┘  └──────┬──────┘ │         │   (next project) │
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

## C2 Server — Next Project

Separate repository. The attacker-side control plane that Badang's comms module talks to.

```
badang-c2/
├── server/              Rust backend
│   ├── listeners/       HTTPS, DNS, SMB listener threads
│   ├── tasks/           Task queue per implant (FIFO)
│   ├── crypto/          Session key management, RC4
│   ├── tracking/        Implant registry (ID, OS, user, last seen)
│   └── api/             REST API for operator web UI
├── web/                 Operator dashboard
│   ├── implants/        Live implant table, status, last checkin
│   ├── tasks/           Task builder, history, output viewer
│   └── listeners/       Listener management (start/stop/config)
└── builder/             Implant config generator
    └── profiles/        Pre-built configs (stealth, noisy, pivot)
```

| Component | What |
|-----------|------|
| **Listeners** | HTTPS (TLS termination, RC4 wire protocol), DNS (planned), SMB (planned) |
| **Task Queue** | Per-implant FIFO, task types: shell, upload, download, module load, config update |
| **Implant Tracking** | ID, hostname, OS version, username, internal IP, last checkin, sleep interval |
| **Operator UI** | Web dashboard — implant table, task builder, output viewer, listener management |
| **Builder** | Generate Badang implant configs — C2 URL, channels, jitter, persistence method |

The C2 server must implement Badang's binary wire protocol (see `src/comms/protocol.rs`) and RC4 transport encryption. Built with the same Rust patterns as Badang (string obfuscation, dynamic resolve) for the implant-facing components. Server components can use standard Rust web frameworks (axum/actix).

---

## Build Order

| Phase | What | Project | Status |
|-------|------|---------|--------|
| 1 | Core platform (8 inject, 6 persist, stager, packaging, evasion, syscalls) | Badang | **Done** |
| 2 | Comms module (beacon loop + HTTPS channel + RC4 transport) | Badang | **Done** |
| 3 | Loader module (anti-sandbox + anti-debug + anti-VM) | Badang | **Done** |
| 4 | C2 Server (listeners + task queue + web UI) | badang-c2 | Planned |
| 5 | Post-ex: credentials + lateral movement | Badang | **Done** |
| 6 | Post-ex: exfiltration + tunneling | Badang | **Done** |
| 7 | Phishing toolkit + Recon/OSINT | New projects | Future |

Phases 2–3 and 4 can overlap — comms module needs a server to talk to, server needs an implant to manage.

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
