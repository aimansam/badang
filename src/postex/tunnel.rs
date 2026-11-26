use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TunnelMode {
    Socks5,
    PortForward,
}

impl TunnelMode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Socks5 => "Proxy Relay",
            Self::PortForward => "Port Relay",
        }
    }
}

pub struct TunnelConfig {
    pub mode: TunnelMode,
    pub listen_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
}

pub struct TunnelResult {
    pub mode: TunnelMode,
    pub description: String,
}

#[cfg(windows)]
pub fn start_tunnel(config: &TunnelConfig, log: &LogSink) -> Result<TunnelResult, String> {
    log.step(format!("  {}:", config.mode.name()));

    unsafe {
        // Initialize winsock
        let mut wsa_data = [0u8; 408];
        if crate::resolve::WSAStartup(0x0202, wsa_data.as_mut_ptr() as *mut std::ffi::c_void) != 0 {
            return Err("WSAStartup failed".into());
        }

        // Create listener: AF_INET=2, SOCK_STREAM=1
        let listen_sock = crate::resolve::socket(2, 1, 6);
        if listen_sock == usize::MAX {
            crate::resolve::WSACleanup();
            return Err("Failed to create listener socket".into());
        }

        // Bind to 0.0.0.0:listen_port
        let mut bind_addr = [0u8; 16];
        bind_addr[0] = 2; // AF_INET
        bind_addr[2] = (config.listen_port >> 8) as u8;
        bind_addr[3] = (config.listen_port & 0xFF) as u8;

        if crate::resolve::bind(listen_sock, bind_addr.as_ptr() as *const std::ffi::c_void, 16) != 0 {
            crate::resolve::closesocket(listen_sock);
            crate::resolve::WSACleanup();
            return Err(format!("Bind to port {} failed", config.listen_port));
        }

        if crate::resolve::listen(listen_sock, 5) != 0 {
            crate::resolve::closesocket(listen_sock);
            crate::resolve::WSACleanup();
            return Err("Listen failed".into());
        }
        log.detail(format!("    Listening on 0.0.0.0:{}", config.listen_port));

        // Accept one connection
        let mut client_addr = [0u8; 16];
        let mut addr_len: i32 = 16;
        let client = crate::resolve::accept(
            listen_sock,
            client_addr.as_mut_ptr() as *mut std::ffi::c_void,
            &mut addr_len,
        );
        if client == usize::MAX {
            crate::resolve::closesocket(listen_sock);
            crate::resolve::WSACleanup();
            return Err("Accept failed".into());
        }
        log.detail("    Client connected");

        match config.mode {
            TunnelMode::Socks5 => {
                socks5_handshake(client, log)?;
                let (target_host, target_port) = socks5_connect_request(client, log)?;
                let remote = connect_remote(&target_host, target_port)?;
                log.detail(format!("    Relaying to {}:{}", target_host, target_port));
                relay(client, remote, log);
                crate::resolve::closesocket(remote);
            }
            TunnelMode::PortForward => {
                let remote = connect_remote(&config.remote_host, config.remote_port)?;
                log.detail(format!("    Forwarding to {}:{}", config.remote_host, config.remote_port));
                relay(client, remote, log);
                crate::resolve::closesocket(remote);
            }
        }

        crate::resolve::closesocket(client);
        crate::resolve::closesocket(listen_sock);
        crate::resolve::WSACleanup();
    }

    Ok(TunnelResult {
        mode: config.mode,
        description: format!("{} on port {}", config.mode.name(), config.listen_port),
    })
}

#[cfg(not(windows))]
pub fn start_tunnel(_config: &TunnelConfig, _log: &LogSink) -> Result<TunnelResult, String> {
    Err("Tunnel requires target platform".into())
}

#[cfg(windows)]
fn connect_remote(host: &str, port: u16) -> Result<usize, String> {
    unsafe {
        let sock = crate::resolve::socket(2, 1, 6);
        if sock == usize::MAX {
            return Err("Failed to create remote socket".into());
        }

        let parts: Vec<u8> = host.split('.')
            .map(|p| p.parse::<u8>().unwrap_or(0))
            .collect();
        if parts.len() != 4 {
            crate::resolve::closesocket(sock);
            return Err(format!("Invalid IPv4: {}", host));
        }

        let mut addr = [0u8; 16];
        addr[0] = 2; // AF_INET
        addr[2] = (port >> 8) as u8;
        addr[3] = (port & 0xFF) as u8;
        addr[4] = parts[0];
        addr[5] = parts[1];
        addr[6] = parts[2];
        addr[7] = parts[3];

        if crate::resolve::connect(sock, addr.as_ptr() as *const std::ffi::c_void, 16) != 0 {
            crate::resolve::closesocket(sock);
            return Err(format!("Connect to {}:{} failed", host, port));
        }
        Ok(sock)
    }
}

#[cfg(windows)]
fn socks5_handshake(client: usize, log: &LogSink) -> Result<(), String> {
    unsafe {
        let mut buf = [0u8; 258];
        let n = crate::resolve::recv(client, buf.as_mut_ptr(), 258, 0);
        if n < 2 || buf[0] != 0x05 {
            return Err("Invalid SOCKS5 greeting".into());
        }
        // Reply: version 5, no auth
        let reply: [u8; 2] = [0x05, 0x00];
        crate::resolve::send(client, reply.as_ptr(), 2, 0);
        log.detail("    SOCKS5 handshake complete (no auth)");
        Ok(())
    }
}

#[cfg(windows)]
fn socks5_connect_request(client: usize, log: &LogSink) -> Result<(String, u16), String> {
    unsafe {
        let mut buf = [0u8; 263];
        let n = crate::resolve::recv(client, buf.as_mut_ptr(), 263, 0);
        if n < 7 {
            return Err("Truncated SOCKS5 connect request".into());
        }
        if buf[0] != 0x05 || buf[1] != 0x01 {
            return Err("Only CONNECT command supported".into());
        }

        let (host, port_offset) = match buf[3] {
            0x01 => {
                // IPv4
                if n < 10 { return Err("Truncated IPv4".into()); }
                let host = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
                (host, 8usize)
            }
            0x03 => {
                // Domain name
                let dlen = buf[4] as usize;
                if n < (5 + dlen + 2) as i32 { return Err("Truncated domain".into()); }
                let host = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                (host, 5 + dlen)
            }
            _ => return Err(format!("Unsupported address type 0x{:02X}", buf[3])),
        };

        let port = ((buf[port_offset] as u16) << 8) | (buf[port_offset + 1] as u16);
        log.detail(format!("    SOCKS5 CONNECT {}:{}", host, port));

        // Reply: success, bind 0.0.0.0:0
        let reply: [u8; 10] = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        crate::resolve::send(client, reply.as_ptr(), 10, 0);

        Ok((host, port))
    }
}

#[cfg(windows)]
fn relay(sock_a: usize, sock_b: usize, log: &LogSink) {
    unsafe {
        // Set both sockets non-blocking
        let mut mode: u32 = 1;
        crate::resolve::ioctlsocket(sock_a, 0x8004667E_u32 as i32, &mut mode); // FIONBIO
        crate::resolve::ioctlsocket(sock_b, 0x8004667E_u32 as i32, &mut mode);

        let mut buf = [0u8; 8192];
        let mut total: u64 = 0;

        // fd_set: count + array of SOCKETs (max 64 on Windows)
        // We'll use select with a timeout to shuttle data
        loop {
            // Build fd_set for read: both sockets
            let mut read_set = [0u8; 520]; // fd_set for 64 sockets
            *(read_set.as_mut_ptr() as *mut u32) = 2; // count
            *(read_set.as_mut_ptr().add(8) as *mut usize) = sock_a;
            *(read_set.as_mut_ptr().add(8 + std::mem::size_of::<usize>()) as *mut usize) = sock_b;

            // timeval: 1 second
            let timeval: [u8; 16] = {
                let mut t = [0u8; 16];
                *(t.as_mut_ptr() as *mut i64) = 1; // tv_sec = 1
                t
            };

            let ready = crate::resolve::select(
                0, // ignored on windows
                read_set.as_mut_ptr() as *mut std::ffi::c_void,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                timeval.as_ptr() as *const std::ffi::c_void,
            );

            if ready <= 0 { continue; }

            // Try recv from A, send to B
            let n = crate::resolve::recv(sock_a, buf.as_mut_ptr(), 8192, 0);
            if n > 0 {
                crate::resolve::send(sock_b, buf.as_ptr(), n, 0);
                total += n as u64;
            } else if n == 0 {
                break; // connection closed
            }

            // Try recv from B, send to A
            let n = crate::resolve::recv(sock_b, buf.as_mut_ptr(), 8192, 0);
            if n > 0 {
                crate::resolve::send(sock_a, buf.as_ptr(), n, 0);
                total += n as u64;
            } else if n == 0 {
                break;
            }
        }

        log.detail(format!("    Relay closed, {} bytes transferred", total));

        // Reset to blocking
        mode = 0;
        crate::resolve::ioctlsocket(sock_a, 0x8004667E_u32 as i32, &mut mode);
        crate::resolve::ioctlsocket(sock_b, 0x8004667E_u32 as i32, &mut mode);
    }
}
