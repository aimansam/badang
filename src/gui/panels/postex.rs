use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::postex::{self, PostExModule};

const MODULES: &[(&str, &str)] = &[
    ("lsass", "Memory Snapshot"),
    ("sam", "Registry Export"),
    ("token", "Session Delegation"),
    ("psexec", "Remote Service"),
    ("wmi", "Remote Execution (WMI)"),
    ("winrm", "Remote Execution (WinRM)"),
];

pub struct PostExState {
    pub selected_module: usize,
    pub pid_text: String,
    pub output_path: String,
    pub remote_host: String,
    pub username: String,
    pub password: String,
    pub command: String,
    pub service_name: String,
    pub payload_path: String,
    pub result_text: String,
    pub error: String,
}

impl Default for PostExState {
    fn default() -> Self {
        Self {
            selected_module: 0,
            pid_text: String::new(),
            output_path: String::new(),
            remote_host: String::new(),
            username: String::new(),
            password: String::new(),
            command: String::new(),
            service_name: String::new(),
            payload_path: String::new(),
            result_text: String::new(),
            error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut PostExState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Post-Exploitation");
    ui.label("Credential harvesting and lateral movement modules.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Module:");
        egui::ComboBox::from_id_salt("postex_module")
            .selected_text(MODULES[state.selected_module].1)
            .show_ui(ui, |ui| {
                for (i, (_, display)) in MODULES.iter().enumerate() {
                    ui.selectable_value(&mut state.selected_module, i, *display);
                }
            });
    });

    let module_key = MODULES[state.selected_module].0;
    let module = PostExModule::from_str(module_key).unwrap();

    ui.add_space(4.0);

    if module.is_credential() {
        if matches!(module, PostExModule::LsassDump | PostExModule::TokenTheft) {
            ui.horizontal(|ui| {
                ui.label("Target PID:");
                ui.text_edit_singleline(&mut state.pid_text);
            });
        }
        if matches!(module, PostExModule::LsassDump | PostExModule::SamDump) {
            ui.horizontal(|ui| {
                ui.label("Output Path:");
                ui.text_edit_singleline(&mut state.output_path);
            });
        }
    }

    if module.is_lateral() {
        ui.horizontal(|ui| {
            ui.label("Remote Host:");
            ui.text_edit_singleline(&mut state.remote_host);
        });
        ui.horizontal(|ui| {
            ui.label("Username:");
            ui.text_edit_singleline(&mut state.username);
        });
        ui.horizontal(|ui| {
            ui.label("Password:");
            ui.text_edit_singleline(&mut state.password);
        });
        if matches!(module, PostExModule::PsExec) {
            ui.horizontal(|ui| {
                ui.label("Payload Path:");
                ui.text_edit_singleline(&mut state.payload_path);
            });
            ui.horizontal(|ui| {
                ui.label("Service Name:");
                ui.text_edit_singleline(&mut state.service_name);
            });
        } else {
            ui.horizontal(|ui| {
                ui.label("Command:");
                ui.text_edit_singleline(&mut state.command);
            });
        }
    }

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if *dry_run {
            ui.colored_label(theme::ACCENT_GREEN, "Dry Run: ON");
        } else {
            ui.colored_label(theme::COLOR_WARNING, "Dry Run: OFF — LIVE MODE");
        }
        if ui.button("Switch").clicked() {
            *dry_run = !*dry_run;
        }
    });

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button("Execute").clicked() {
            state.error.clear();
            state.result_text.clear();

            if *dry_run {
                postex::dry_run(&module, log);
            } else {
                let pid: u32 = state.pid_text.parse().unwrap_or(0);
                let config = postex::PostExConfig {
                    module,
                    pid,
                    output: state.output_path.clone(),
                    remote: state.remote_host.clone(),
                    username: state.username.clone(),
                    password: state.password.clone(),
                    command: state.command.clone(),
                    service_name: state.service_name.clone(),
                    payload_path: state.payload_path.clone(),
                };
                match postex::run_postex(&config, log) {
                    Ok(result) => {
                        state.result_text = format!("{}: {}", result.module, result.description);
                    }
                    Err(e) => {
                        state.error = e;
                    }
                }
            }
        }

        if ui.button("Info").clicked() {
            postex::print_info(log);
        }
    });

    if !state.result_text.is_empty() {
        ui.add_space(8.0);
        ui.colored_label(theme::ACCENT_GREEN, &state.result_text);
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
