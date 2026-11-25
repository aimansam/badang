use eframe::egui;
use std::sync::mpsc;

use crate::gui::theme;
use crate::injection::{InjectionResult, InjectionTechnique};
use crate::log::LogSink;

const TECHNIQUES: &[(&str, &str)] = &[
    ("createremote", "CreateRemoteThread"),
    ("apc", "APC Injection"),
    ("hijack", "Thread Hijack (SetThreadContext)"),
    ("earlybird", "Early Bird APC"),
];

#[derive(Default)]
pub struct InjectState {
    pub pid_input: String,
    pub selected_technique: usize,
    pub payload_path: String,
    pub error: String,
    pub task_running: bool,
    pub task_rx: Option<mpsc::Receiver<Result<InjectionResult, String>>>,
    pub last_injection: Option<InjectionResult>,
    pub last_injection_pid: u32,
}

pub fn draw(
    ui: &mut egui::Ui,
    state: &mut InjectState,
    dry_run: &mut bool,
    confirm: &mut bool,
    log: &LogSink,
    ctx: &egui::Context,
) {
    // Check background task completion
    if let Some(ref rx) = state.task_rx {
        match rx.try_recv() {
            Ok(Ok(result)) => {
                state.task_running = false;
                state.task_rx = None;
                log.step("[DONE] Injection chain completed.");
                log.info(format!(
                    "  Shellcode at remote address 0x{:X} ({} bytes) — use Cleanup to free",
                    result.remote_base, result.size
                ));
                state.last_injection_pid = state.pid_input.trim().parse().unwrap_or(0);
                state.last_injection = Some(result);
            }
            Ok(Err(e)) => {
                state.task_running = false;
                state.task_rx = None;
                log.error(format!("[FAILED] Injection chain aborted: {}", e));
            }
            Err(mpsc::TryRecvError::Empty) => {
                ctx.request_repaint_after(std::time::Duration::from_millis(100));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                state.task_running = false;
                state.task_rx = None;
                log.error("[FAILED] Background task disconnected");
            }
        }
    }

    ui.heading("Process Injection");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Target PID:");
        ui.text_edit_singleline(&mut state.pid_input);
    });

    ui.horizontal(|ui| {
        ui.label("Technique:");
        egui::ComboBox::from_id_salt("inject_technique")
            .selected_text(TECHNIQUES[state.selected_technique].1)
            .show_ui(ui, |ui| {
                for (i, (_, label)) in TECHNIQUES.iter().enumerate() {
                    ui.selectable_value(&mut state.selected_technique, i, *label);
                }
            });
    });

    ui.horizontal(|ui| {
        ui.label("Payload file:");
        ui.text_edit_singleline(&mut state.payload_path);
        if ui.button("Browse...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select shellcode payload")
                .pick_file()
            {
                state.payload_path = path.display().to_string();
            }
        }
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        let label = if *dry_run {
            "Mode: DRY RUN (educational only)"
        } else {
            "Mode: LIVE INJECTION"
        };
        let color = if *dry_run {
            theme::ACCENT_GREEN
        } else {
            theme::COLOR_WARNING
        };
        ui.colored_label(color, label);
        if ui.button(if *dry_run { "Switch to Live" } else { "Switch to Dry Run" }).clicked() {
            *dry_run = !*dry_run;
        }
        if !*dry_run {
            ui.checkbox(confirm, "Confirm");
        }
    });

    if !state.error.is_empty() {
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }

    ui.add_space(4.0);

    let can_execute = !*dry_run && *confirm;
    let button_label = if state.task_running {
        "Running..."
    } else if *dry_run {
        "Run (Dry Run)"
    } else {
        "Execute Injection"
    };

    let enabled = !state.task_running && (*dry_run || can_execute);
    if ui
        .add_enabled(enabled, egui::Button::new(button_label))
        .clicked()
    {
        state.error.clear();
        let technique_key = TECHNIQUES[state.selected_technique].0;
        let is_earlybird = technique_key == "earlybird";

        let pid = if is_earlybird {
            0
        } else {
            match state.pid_input.trim().parse::<u32>() {
                Ok(p) => p,
                Err(_) => {
                    state.error = "Invalid PID — enter a number".to_string();
                    return;
                }
            }
        };
        if !is_earlybird {
            if let Err(e) = crate::safety::validate_target(pid) {
                state.error = e;
                return;
            }
        }

        if *dry_run {
            if is_earlybird {
                log.step(format!(
                    "[DRY RUN] Would spawn suspended process using technique {}",
                    technique_key
                ));
            } else {
                log.step(format!(
                    "[DRY RUN] Would inject into PID {} using technique {}",
                    pid, technique_key
                ));
            }
            crate::injection::dry_run(pid, technique_key, log);
        } else {
            let payload_path = state.payload_path.trim().to_string();
            if payload_path.is_empty() {
                state.error = "Payload file path is required for live injection".to_string();
                return;
            }
            let shellcode = match crate::injection::load_payload(&payload_path) {
                Ok(bytes) => bytes,
                Err(e) => {
                    state.error = e;
                    return;
                }
            };
            let technique = match InjectionTechnique::from_str(technique_key) {
                Some(t) => t,
                None => {
                    state.error = format!("Unknown technique: {}", technique_key);
                    return;
                }
            };

            log.step(format!("=== LIVE INJECTION — {} ===", technique.name()));
            log.info(format!(
                "  Payload: {} ({} bytes)",
                payload_path,
                shellcode.len()
            ));
            if is_earlybird {
                log.info("  Mode: spawns a new suspended process (PID not required)");
            } else {
                log.info(format!("  Target PID: {}", pid));
            }
            log.warning("  WARNING: this performs REAL Win32 calls against a live process.");

            let (tx, rx) = mpsc::channel::<Result<InjectionResult, String>>();
            let log_clone = log.clone();
            state.task_rx = Some(rx);
            state.task_running = true;

            std::thread::spawn(move || {
                let result = crate::injection::live_inject(pid, &technique, &shellcode, &log_clone);
                let _ = tx.send(result);
            });
        }
    }

    if !*dry_run && !*confirm && !state.task_running {
        ui.colored_label(
            theme::COLOR_WARNING,
            "Enable Confirm to execute live injection",
        );
    }

    if let Some(ref inj) = state.last_injection {
        ui.add_space(8.0);
        ui.separator();
        ui.add_space(4.0);
        ui.colored_label(
            theme::ACCENT_GREEN,
            format!(
                "Injected: 0x{:X} ({} bytes) in PID {}",
                inj.remote_base, inj.size, state.last_injection_pid
            ),
        );
        if ui.button("Cleanup (VirtualFreeEx)").clicked() {
            let pid = state.last_injection_pid;
            let base = inj.remote_base;
            let size = inj.size;
            crate::injection::cleanup_remote(pid, base, size, log);
            state.last_injection = None;
        }
    }
}
