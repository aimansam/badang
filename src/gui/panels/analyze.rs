use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;

#[derive(Default)]
pub struct AnalyzeState {
    pub pid_input: String,
    pub error: String,
}

pub fn draw(ui: &mut egui::Ui, state: &mut AnalyzeState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Hook Detection Analysis");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Target PID:");
        ui.text_edit_singleline(&mut state.pid_input);
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        let label = if *dry_run {
            "Mode: DRY RUN (educational only)"
        } else {
            "Mode: LIVE SCAN (reads process memory)"
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
    });

    if !state.error.is_empty() {
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }

    ui.add_space(4.0);

    if ui.button("Analyze").clicked() {
        state.error.clear();
        match state.pid_input.trim().parse::<u32>() {
            Ok(pid) => {
                if let Err(e) = crate::safety::validate_target(pid) {
                    state.error = e;
                } else if *dry_run {
                    log.step(format!("[DRY RUN] Would analyze process PID {}", pid));
                    crate::detect::dry_run(pid, log);
                } else {
                    log.step(format!("[LIVE] Scanning process PID {} for hooks...", pid));
                    crate::detect::analyze(pid, log);
                }
            }
            Err(_) => {
                state.error = "Invalid PID — enter a number".to_string();
            }
        }
    }
}
