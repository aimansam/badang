use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::loader::{self, CheckCategory, FailAction};

const CATEGORIES: &[(&str, &str)] = &[
    ("all", "Full Analysis"),
    ("sandbox", "Environment Analysis"),
    ("debug", "Process Inspection"),
    ("vm", "Hardware Fingerprint"),
];

const ACTIONS: &[(&str, &str)] = &[
    ("report", "Report Only"),
    ("exit", "Terminate on Detection"),
];

pub struct LoaderState {
    pub selected_category: usize,
    pub selected_action: usize,
    pub results: Vec<(String, bool, String)>,
    pub safe: Option<bool>,
    pub error: String,
}

impl Default for LoaderState {
    fn default() -> Self {
        Self {
            selected_category: 0,
            selected_action: 0,
            results: Vec::new(),
            safe: None,
            error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut LoaderState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Pre-Execution Checks");
    ui.label("Analyze the runtime environment before proceeding.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Category:");
        egui::ComboBox::from_id_salt("loader_category")
            .selected_text(CATEGORIES[state.selected_category].1)
            .show_ui(ui, |ui| {
                for (i, (_, display)) in CATEGORIES.iter().enumerate() {
                    ui.selectable_value(&mut state.selected_category, i, *display);
                }
            });
    });

    ui.horizontal(|ui| {
        ui.label("On Detection:");
        egui::ComboBox::from_id_salt("loader_action")
            .selected_text(ACTIONS[state.selected_action].1)
            .show_ui(ui, |ui| {
                for (i, (_, display)) in ACTIONS.iter().enumerate() {
                    ui.selectable_value(&mut state.selected_action, i, *display);
                }
            });
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
            state.results.clear();
            state.safe = None;

            let cat_key = CATEGORIES[state.selected_category].0;

            if *dry_run {
                loader::dry_run(cat_key, log);
            } else {
                let category = CheckCategory::from_str(cat_key).unwrap();
                let action_key = ACTIONS[state.selected_action].0;
                let fail_action = FailAction::from_str(action_key).unwrap();
                let config = loader::LoaderConfig { category, fail_action };
                match loader::run_checks(&config, log) {
                    Ok(result) => {
                        state.safe = Some(result.safe);
                        state.results = result.checks.into_iter()
                            .map(|c| (c.name, c.detected, c.detail))
                            .collect();
                    }
                    Err(e) => {
                        state.error = e;
                    }
                }
            }
        }

        if ui.button("Info").clicked() {
            loader::print_info(log);
        }
    });

    if let Some(safe) = state.safe {
        ui.add_space(8.0);
        if safe {
            ui.colored_label(theme::ACCENT_GREEN, "Environment: CLEAR — all checks passed");
        } else {
            ui.colored_label(theme::COLOR_ERROR, "Environment: FLAGGED — detections found");
        }
        ui.add_space(4.0);
        for (name, detected, detail) in &state.results {
            let color = if *detected { theme::COLOR_ERROR } else { theme::ACCENT_GREEN };
            let icon = if *detected { "FLAGGED" } else { "CLEAN" };
            ui.colored_label(color, format!("  [{}] {} — {}", icon, name, detail));
        }
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
