pub mod sandbox;
pub mod antidebug;
pub mod antivm;

use crate::log::LogSink;
use sandbox::CheckResult;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CheckCategory {
    Sandbox,
    Debug,
    Vm,
    All,
}

impl CheckCategory {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "sandbox" | "sb" | "env" | "environment" => Some(Self::Sandbox),
            "debug" | "dbg" | "debugger" => Some(Self::Debug),
            "vm" | "virtual" | "hw" | "hardware" => Some(Self::Vm),
            "all" | "full" => Some(Self::All),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Sandbox => "Environment Analysis",
            Self::Debug => "Process Inspection",
            Self::Vm => "Hardware Fingerprint",
            Self::All => "Full Analysis",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::Sandbox, Self::Debug, Self::Vm, Self::All]
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FailAction {
    Report,
    Exit,
}

impl FailAction {
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "report" | "log" => Some(Self::Report),
            "exit" | "abort" | "quit" => Some(Self::Exit),
            _ => None,
        }
    }
}

pub struct LoaderConfig {
    pub category: CheckCategory,
    pub fail_action: FailAction,
}

pub struct LoaderResult {
    pub checks: Vec<CheckResult>,
    pub safe: bool,
}

pub fn dry_run(category: &str, log: &LogSink) {
    let cat = CheckCategory::from_str(category);
    match cat {
        Some(c) => {
            log.step(format!("[DRY RUN] Would perform: {}", c.name()));
            match c {
                CheckCategory::Sandbox => {
                    log.detail("  Steps: Timing analysis → process enumeration → disk check → user check → memory check");
                }
                CheckCategory::Debug => {
                    log.detail("  Steps: Process flag check → debug port query → debug flags query → timing analysis");
                }
                CheckCategory::Vm => {
                    log.detail("  Steps: Processor feature check → registry check → network adapter fingerprint");
                }
                CheckCategory::All => {
                    log.detail("  Steps: Run all environment, process, and hardware checks");
                }
            }
        }
        None => {
            log.step(format!("[DRY RUN] Unknown category: {}", category));
            log.detail("  Known categories: sandbox, debug, vm, all");
        }
    }
}

pub fn run_checks(config: &LoaderConfig, log: &LogSink) -> Result<LoaderResult, String> {
    log.step(format!("Running: {}", config.category.name()));

    let checks = match config.category {
        CheckCategory::Sandbox => sandbox::run_all(log),
        CheckCategory::Debug => antidebug::run_all(log),
        CheckCategory::Vm => antivm::run_all(log),
        CheckCategory::All => {
            let mut all = Vec::new();
            all.extend(sandbox::run_all(log));
            all.extend(antidebug::run_all(log));
            all.extend(antivm::run_all(log));
            all
        }
    };

    let detected_count = checks.iter().filter(|c| c.detected).count();
    let safe = detected_count == 0;

    log.step(format!(
        "Result: {}/{} checks passed",
        checks.len() - detected_count,
        checks.len()
    ));

    if !safe && config.fail_action == FailAction::Exit {
        log.step("Action: Would terminate (analysis environment detected)");
    }

    Ok(LoaderResult { checks, safe })
}

pub fn print_info(log: &LogSink) {
    log.step("Pre-Execution Checks:");
    log.detail("  1. Environment  — Timing, process count, disk, user, memory");
    log.detail("  2. Process      — Flag check, debug port, debug flags, timing");
    log.detail("  3. Hardware     — Processor features, registry, adapter fingerprint");
    log.detail("  4. Full         — All checks combined");
}
