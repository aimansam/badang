# Badang

**EDR Evasion Research Toolkit** — demonstrates and documents Windows EDR evasion techniques for authorized security research and educational purposes only.

[![Rust](https://img.shields.io/badge/Rust-1.98+-orange?logo=rust)](https://www.rust-lang.org/)
[![Windows](https://img.shields.io/badge/Windows-x86_64-blue?logo=windows)](https://windows.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Research](https://img.shields.io/badge/Security-Research-red?logo=security)](https://github.com/aimansam/badang)

## Overview

Badang is a Windows-based research toolkit that explores common EDR (Endpoint Detection and Response) evasion techniques. It is built for security researchers, defenders, and red teamers who need to understand how detection logic works — and where gaps exist.

> **Disclaimer:** This toolkit is for authorized security research and educational use only. Do not use against targets without explicit written permission.

## Features

- ~~DLL injection via `CreateRemoteThread`~~ (deprecated in v2)
- Syscall-based execution (`NtCreateThreadEx` / `RtlCreateUserThread`)
- AMSI bypass research notes
- ETW patching references
- Process manipulation: handle duplication, token abuse
- Payload staging via .NET reflection and PE parsing

## Structure

```
badang/
├── src/                  # Rust source
│   ├── lib.rs
│   ├── syscalls.rs
│   ├── loaders/
│   └── helpers/
├── tests/                # unit + integration
├── docs/                 # technique write-ups
└── Cargo.toml
```

## Building

Requires Rust 1.98+ and a Windows target.

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release
```

The binary lands in `target/release/badang.exe`.

## Usage

```powershell
# List available modules
.\badang.exe --list

# Run a specific technique (research only)
.\badang.exe --module syscalls --args ...
```

## Research Notes

Each technique includes a write-up in `docs/` covering:
- How the evasion works
- What EDR telemetry it touches
- Detection ideas and gaps
- References to real incidents or blog posts

## Disclaimer

Badang is a research tool. Techniques documented here are well-known and widely discussed in the security community. The goal is understanding — not weaponization.

Use only on systems you own or have explicit written permission to test.

## License

MIT — see [LICENSE](LICENSE).

---

*Badang* — named after the Malaysian folklore hero who possessed supernatural strength. A fitting name for a toolkit that pushes against detection boundaries.

*For authorized security research and educational purposes only.*
