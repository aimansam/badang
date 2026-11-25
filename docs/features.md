# Features

## Analyze (Hook Detection)

Scans a target process for hooked APIs. Opens the process, reads the first 32 bytes of each NT function from `ntdll.dll`, compares against the clean prologue (`4C 8B D1 B8`).

**13 APIs scanned:** NtAllocateVirtualMemory, NtProtectVirtualMemory, NtWriteVirtualMemory, NtCreateThreadEx, NtMapViewOfSection, NtQueueApcThread, NtCreateFile, NtOpenFile, NtReadFile, NtWriteFile, NtClose, NtWaitForSingleObject, NtDeviceIoControlFile.

Reports each as `[CLEAN]` or `[HOOKED]` with hook type and raw bytes.

## Syscall (Direct Syscall)

Calls the kernel directly using raw syscall numbers, bypassing ntdll hooks entirely. Includes SSN tables for Windows 7 SP1, 10 1809, 10 22H2, and 11 22H2.

## Inject (Process Injection)

Five live injection techniques (all operational with `-x -c`):

- **CreateRemoteThread** — allocate + write + create thread. 6-step pipeline: OpenProcess → VirtualAllocEx → WriteProcessMemory → VirtualProtectEx → CreateRemoteThread → WaitForSingleObject. Simplest, most detected.
- **APC Injection** — wraps shellcode in callee-save trampoline (preserves rbx/rbp/rsi/rdi/r12-r15), writes to target, enumerates threads via ToolHelp, queues APC to all threads. Executes when a thread enters alertable wait. No new thread created.
- **Thread Hijack (SetThreadContext)** — suspends an existing thread, saves full CONTEXT (all GPRs + RFLAGS), redirects RIP to shellcode in a full-register-save trampoline with completion flag. Polls flag via ReadProcessMemory, then restores original context so the thread continues normally. No new thread, no APC.
- **Early Bird APC** — creates a new process with CREATE_SUSPENDED, writes shellcode, queues APC to the main thread, then resumes. The APC fires during process initialization before EDR user-mode hooks are installed. No PID required.
- **Section Mapping (MapViewOfFile)** — creates a shared memory section (CreateFileMappingW), maps locally to write shellcode via memcpy, maps same section into target via MapViewOfFileNuma2 as PAGE_EXECUTE_READ. WriteProcessMemory is never called — EDR hooks on it see nothing. Requires Windows 10 1703+.

Each technique is in its own file under `src/injection/`.

## Unhook (API Restoration)

Restores hooked functions to original bytes. Three methods:

- **Direct Byte Restoration** — overwrite with clean prologue
- **Trampoline** — patch around the hook
- **Inline Hook** — redirect execution flow

## Generate (Payload Generator)

Builds x86_64 Windows shellcode without msfvenom. Uses PEB walking (`gs:[0x60]` → PEB → kernel32) and ROR13 API hashing.

| Type | What it does | Parameters |
|------|-------------|------------|
| exec | Run command via WinExec | `--command "calc.exe"` |
| messagebox | Show MessageBox | `--title "Test" --text "Hello"` |
| reverse_tcp | Connect-back shell | `--lhost IP --lport PORT` |
| bind_tcp | Listen shell | `--lport PORT` |

## Convert (Format Converter)

Auto-detects and converts between: hex, C array, Python bytes, Rust array, decimal.
