use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::persistence::{self, PersistMethod};

const METHODS: &[(&str, &str)] = &[
    ("registry", "Registry Configuration"),
    ("schtask", "Scheduled Automation"),
    ("wmi", "Event Subscription"),
    ("hijack", "Module Placement"),
    ("com", "Component Registration"),
    ("service", "Service Configuration"),
];

pub struct PersistState {
    pub selected: usize,
    pub name: String,
    pub target: String,
    pub payload_path: String,
    pub result: Option<String>,
    pub error: String,
}

impl Default for PersistState {
    fn default() -> Self {
        Self {
            selected: 0,
            name: String::new(),
            target: String::new(),
            payload_path: String::new(),
            result: None,
            error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut PersistState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Persistence");
    ui.label("Configure persistence mechanisms for payload survival.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Method:");
        egui::ComboBox::from_id_salt("persist_method")
            .selected_text(METHODS[state.selected].1)
            .show_ui(ui, |ui| {
                for (i, (_, display)) in METHODS.iter().enumerate() {
                    ui.selectable_value(&mut state.selected, i, *display);
                }
            });
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Name:");
        ui.text_edit_singleline(&mut state.name);
    });

    let method_key = METHODS[state.selected].0;
    if method_key == "hijack" || method_key == "com" {
        ui.horizontal(|ui| {
            let label = if method_key == "hijack" { "Target Dir:" } else { "CLSID:" };
            ui.label(label);
            ui.text_edit_singleline(&mut state.target);
        });
    }

    ui.horizontal(|ui| {
        ui.label("Payload:");
        ui.text_edit_singleline(&mut state.payload_path);
    });

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
            state.result = None;

            if *dry_run {
                persistence::dry_run(method_key, &state.name, &state.payload_path, log);
            } else {
                let method = PersistMethod::from_str(method_key).unwrap();
                let config = persistence::PersistConfig {
                    method,
                    name: state.name.clone(),
                    target: state.target.clone(),
                    payload_path: state.payload_path.clone(),
                };
                match persistence::run_persist(&config, log) {
                    Ok(result) => {
                        state.result = Some(result.description);
                    }
                    Err(e) => {
                        state.error = e;
                    }
                }
            }
        }

        if ui.button("Info").clicked() {
            persistence::print_info(log);
        }
    });

    if let Some(ref desc) = state.result {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, desc);
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
