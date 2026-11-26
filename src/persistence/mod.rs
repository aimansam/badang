pub mod registry;
pub mod schtask;
pub mod wmi;
pub mod hijack;
pub mod com;
pub mod service;

use crate::log::LogSink;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PersistMethod {
    RegistryRun,
    ScheduledTask,
    WmiSubscription,
    DllHijack,
    ComHijack,
    ServiceCreation,
}

impl PersistMethod {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "registry" | "reg" | "registryrun" | "registry_run" => Some(Self::RegistryRun),
            "schtask" | "scheduledtask" | "scheduled_task" | "task" => Some(Self::ScheduledTask),
            "wmi" | "wmisubscription" | "wmi_subscription" => Some(Self::WmiSubscription),
            "dllhijack" | "dll_hijack" | "hijack" => Some(Self::DllHijack),
            "comhijack" | "com_hijack" | "com" => Some(Self::ComHijack),
            "service" | "svc" | "servicecreation" | "service_creation" => Some(Self::ServiceCreation),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::RegistryRun => "Registry Configuration",
            Self::ScheduledTask => "Scheduled Automation",
            Self::WmiSubscription => "Event Subscription",
            Self::DllHijack => "Module Placement",
            Self::ComHijack => "Component Registration",
            Self::ServiceCreation => "Service Configuration",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::RegistryRun,
            Self::ScheduledTask,
            Self::WmiSubscription,
            Self::DllHijack,
            Self::ComHijack,
            Self::ServiceCreation,
        ]
    }
}

pub struct PersistConfig {
    pub method: PersistMethod,
    pub name: String,
    pub target: String,
    pub payload_path: String,
}

pub struct PersistResult {
    pub method: PersistMethod,
    pub description: String,
}

pub fn dry_run(method: &str, name: &str, payload_path: &str, log: &LogSink) {
    let m = PersistMethod::from_str(method);
    match m {
        Some(technique) => {
            log.step(format!("[DRY RUN] Would configure: {}", technique.name()));
            log.detail(format!("  Name: {}", name));
            log.detail(format!("  Payload: {}", payload_path));
            match technique {
                PersistMethod::RegistryRun => {
                    log.detail("  Steps: Open registry key → set value → close key");
                }
                PersistMethod::ScheduledTask => {
                    log.detail("  Steps: Create scheduled task via system utility");
                }
                PersistMethod::WmiSubscription => {
                    log.detail("  Steps: Create event filter → bind consumer → link");
                }
                PersistMethod::DllHijack => {
                    log.detail("  Steps: Verify target directory → place module");
                }
                PersistMethod::ComHijack => {
                    log.detail("  Steps: Open CLSID key → set server path → close key");
                }
                PersistMethod::ServiceCreation => {
                    log.detail("  Steps: Open service manager → create service → close handles");
                }
            }
        }
        None => {
            log.step(format!("[DRY RUN] Unknown method: {}", method));
            log.detail(format!(
                "  Known methods: {}",
                "registry, schtask, wmi, hijack, com, service"
            ));
        }
    }
}

pub fn run_persist(config: &PersistConfig, log: &LogSink) -> Result<PersistResult, String> {
    match config.method {
        PersistMethod::RegistryRun => registry::persist(config, log),
        PersistMethod::ScheduledTask => schtask::persist(config, log),
        PersistMethod::WmiSubscription => wmi::persist(config, log),
        PersistMethod::DllHijack => hijack::persist(config, log),
        PersistMethod::ComHijack => com::persist(config, log),
        PersistMethod::ServiceCreation => service::persist(config, log),
    }
}

pub fn print_info(log: &LogSink) {
    log.step("Persistence Techniques:");
    log.detail("  1. Registry Run    — Registry configuration at logon");
    log.detail("  2. Scheduled Task  — Scheduled automation via system utility");
    log.detail("  3. WMI Subscribe   — Event subscription via system utility");
    log.detail("  4. DLL Placement   — Module placement in search path");
    log.detail("  5. COM Register    — Component registration via registry");
    log.detail("  6. Service Config  — Service configuration via service manager");
}
