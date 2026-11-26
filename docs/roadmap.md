# Red Team Toolchain Roadmap

A complete offensive toolchain built in Rust, sharing a common evasion foundation. Each project builds on the last.

---

## Toolchain

| # | Project | Purpose | Status |
|---|---------|---------|--------|
| 1 | **Badang** | EDR evasion, process injection, syscalls, telemetry blinding, payload generation | Done |
| 2 | **Loader/Stager** | Fileless delivery — fetch encrypted payload, decrypt in memory, execute. Sandbox detection, anti-debug, multiple channels (HTTPS, DNS, SMB) | Next |
| 3 | **C2 Framework** | Command & control — encrypted comms, task queuing, modular post-ex, operator web UI | Planned |
| 4 | **Phishing Toolkit** | Initial access — email templates, payload embedding (macro, HTA, LNK, ISO/IMG), tracking, SMTP relay, landing page cloner | Planned |
| 5 | **Recon/OSINT Tool** | Pre-engagement intelligence — subdomain enum, email harvesting, tech stack fingerprinting, credential breach lookup | Planned |
| 6 | **Credential Harvester** | Post-ex — LSASS dump (direct syscall), SAM/SYSTEM extraction, Kerberos tickets, DPAPI, browser credentials | Planned |
| 7 | **Lateral Movement Kit** | Network spread — PsExec (SCM), WMI, DCOM, WinRM, Pass-the-Hash, overpass-the-hash, Kerberoasting, token impersonation | Planned |
| 8 | **Persistence Toolkit** | Survive reboots — registry, scheduled tasks, WMI subscriptions, DLL hijacking, COM hijacking, services | Planned |
| 9 | **Exfiltration Tool** | Data theft — staged transfer over DNS/HTTPS/cloud APIs, steganography, encrypted archives, throttling | Planned |
| 10 | **Network Tunneler** | Pivot — SOCKS5 proxy, port forwarding, DNS tunneling, ICMP tunneling, reverse SSH, multi-hop chaining | Planned |

---

## Kill Chain Coverage

```
┌─────────────────────────────────────────────────────────────────────┐
│                        RED TEAM KILL CHAIN                          │
├─────────────┬───────────────────────────────────────────────────────┤
│             │                                                       │
│  1. RECON   │  [5] OSINT Tool                                       │
│             │      Subdomain enum, email harvest, tech fingerprint   │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  2. WEAPON- │  [1] Badang          Payload generation + encryption   │
│     IZE     │  [2] Loader/Stager   Package payload for delivery     │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  3. DELIVER │  [4] Phishing Kit    Email, macro, HTA, LNK, ISO     │
│             │  [2] Loader/Stager   HTTPS/DNS/SMB fetch              │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  4. EXPLOIT │  [2] Loader/Stager   Sandbox detection, anti-debug    │
│             │  [1] Badang          ETW/AMSI patching                │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  5. INSTALL │  [1] Badang          7 injection techniques           │
│             │  [8] Persistence     Registry, tasks, WMI, COM, DLL   │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  6. C2      │  [3] C2 Framework    Encrypted comms, task queue      │
│             │  [10] Tunneler       SOCKS5, DNS tunnel, multi-hop    │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  7. ACTIONS │  [6] Cred Harvester  LSASS, SAM, Kerberos, DPAPI     │
│             │  [7] Lateral Move    PtH, WMI, DCOM, Kerberoast      │
│             │  [9] Exfiltration    DNS/HTTPS/cloud, stego, encrypt  │
│             │                                                       │
├─────────────┼───────────────────────────────────────────────────────┤
│             │                                                       │
│  EVASION    │  [1] Badang          Active throughout every stage     │
│  (all       │      XOR obfuscation, dynamic API resolution,         │
│   stages)   │      string sanitization, indirect syscalls,           │
│             │      sleep obfuscation, stack spoofing                 │
│             │                                                       │
└─────────────┴───────────────────────────────────────────────────────┘
```

---

## Dependency Graph

```
                    [5] Recon/OSINT
                         │
                         ▼
                    [4] Phishing ──────────────┐
                         │                     │
                         ▼                     │
        ┌───────── [2] Loader/Stager           │
        │                │                     │
        │                ▼                     │
        │           [3] C2 Framework ◄─────────┘
        │                │
        │       ┌────────┼────────┬──────────┐
        │       ▼        ▼        ▼          ▼
        │  [6] Creds  [7] Lat  [8] Persist  [10] Tunnel
        │       │      Move        │
        │       └────────┬─────────┘
        │                ▼
        │          [9] Exfiltration
        │
        └──► [1] BADANG (evasion layer for all projects)
```

---

## Build Phases

### Phase 1: Core Chain (Projects 2–3)

**Goal**: End-to-end implant chain — generate payload, deliver, control.

The stager fetches Badang-encrypted payloads and executes them in memory. The C2 server manages implants, queues tasks, and provides an operator interface. Together with Badang, this is a minimum viable red team toolkit.

**Shared foundation from Badang**:
- Multi-byte XOR string obfuscation (`obf.rs` pattern)
- Dynamic API resolution (`resolve.rs` pattern)
- String sanitization (no flagged keywords in binary)
- PE metadata embedding (`build.rs` pattern)
- Release profile (strip, LTO, single codegen unit)

### Phase 2: Initial Access (Projects 4–5)

**Goal**: Get implants onto targets without manual delivery.

Recon gathers intelligence (subdomains, emails, tech stack). The phishing toolkit packages stagers into convincing delivery vehicles and tracks opens/clicks. This removes the "transfer the .exe manually" step.

### Phase 3: Post-Exploitation (Projects 6–8)

**Goal**: Operate inside a network — escalate, spread, persist.

Credential harvesting runs as a C2 post-ex module (LSASS dump via direct syscall to avoid EDR). Lateral movement uses harvested credentials to spread. Persistence ensures implants survive reboots.

### Phase 4: Complete (Projects 9–10)

**Goal**: Achieve objectives and extract data.

Exfiltration handles staged, encrypted data transfer over covert channels. The tunneler provides network pivoting to reach internal segments the C2 can't reach directly.

---

## Shared Design Principles

All projects follow the same patterns established in Badang:

| Principle | Implementation |
|-----------|---------------|
| **Language** | Rust — memory safety, small binaries, no runtime dependency |
| **String obfuscation** | Multi-byte XOR at compile time, decrypt at runtime |
| **API resolution** | Dynamic resolution via GetModuleHandleA + GetProcAddress |
| **IAT hygiene** | Minimal imports — only bootstrap functions visible |
| **String sanitization** | No offensive keywords in compiled binary |
| **PE metadata** | Version info, manifest, icon — look like a normal app |
| **Release profile** | `strip`, `lto`, `opt-level = 3`, `codegen-units = 1`, `panic = abort` |
| **Safety** | Dry-run by default, explicit confirmation for live ops |
| **Dual interface** | CLI for automation, native GUI for interactive use |
| **Cross-compile** | Build Windows binaries from Linux via mingw-w64 |
| **CI/CD** | GitHub Actions — fmt, clippy, test, audit, cross-compile, artifact upload |

---

*All tools are for authorized security research and red team operations only.*
