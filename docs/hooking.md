# What is EDR Hooking

EDRs rewrite the first bytes of NT API functions in `ntdll.dll` to redirect calls through their scanner before reaching the kernel.

## Clean vs Hooked

**Clean (no EDR):**
```
Your program → NtAllocateVirtualMemory → kernel
```

**Hooked (EDR active):**
```
Your program → NtAllocateVirtualMemory → JMP to EDR → EDR decides → kernel
```

## Clean Prologue

A clean NT API starts with:
```asm
mov r10, rcx      ; 4C 8B D1
mov eax, <SSN>    ; B8 xx 00 00 00
syscall           ; 0F 05
ret               ; C3
```

## Hook Types

| Type | Opcode | Description |
|------|--------|-------------|
| JMP rel32 | `E9` | Relative jump to EDR code |
| JMP indirect | `FF 25` | Jump through pointer |
| PUSH/RET | `68...C3` | Push address, return to it |
| INT3 | `CC` | Breakpoint, caught by EDR exception handler |
| Unknown | varies | Doesn't match clean prologue |

## Why Unhook

Restoring the original bytes (`4C 8B D1 B8 ...`) removes the EDR's redirect. Your API calls go straight to the kernel — the EDR never sees them.

## Why Direct Syscall

Skip `ntdll.dll` entirely. Call the kernel using the raw syscall number. The hooks are in ntdll — if you never touch ntdll, the hooks don't matter.
