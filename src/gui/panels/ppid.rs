use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::evasion::ppid;

#[derive(Default)]
pub struct PpidState {
    pub parent_input: String,
    pub child_input: String,
    pub suspended: bool,
    pub error: String,
    pub last_result: Option<String>,
}

pub fn draw(ui: &mut egui::Ui, state: &mut PpidState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("PPID Spoofing");
    ui.label("Spawn a process with a spoofed parent PID.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Parent (name or PID):");
        ui.text_edit_singleline(&mut state.parent_input);
    });

    ui.horizontal(|ui| {
        ui.label("Child command:");
        ui.text_edit_singleline(&mut state.child_input);
    });

    ui.checkbox(&mut state.suspended, "Create suspended (for APC injection)");

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
        if ui.button("Spawn").clicked() {
            state.error.clear();
            state.last_result = None;
            let parent = if state.parent_input.is_empty() {
                "explorer.exe"
            } else {
                &state.parent_input
            };
            let child = if state.child_input.is_empty() {
                "notepad.exe"
            } else {
                &state.child_input
            };
            if *dry_run {
                ppid::dry_run(parent, child, log);
            } else {
                let parent_pid = if let Ok(pid) = parent.parse::<u32>() {
                    Ok(pid)
                } else {
                    ppid::find_pid_by_name(parent, log)
                };
                match parent_pid {
                    Ok(pid) => {
                        let config = ppid::PpidConfig {
                            parent_pid: pid,
                            child_command: child.to_string(),
                            suspended: state.suspended,
                        };
                        match ppid::spawn(&config, log) {
                            Ok(result) => {
                                state.last_result = Some(format!(
                                    "Child PID {} (TID {}), parent PID {}{}",
                                    result.child_pid,
                                    result.child_tid,
                                    result.parent_pid,
                                    if result.suspended { " — SUSPENDED" } else { "" }
                                ));
                            }
                            Err(e) => state.error = e,
                        }
                    }
                    Err(e) => state.error = e,
                }
            }
        }

        if ui.button("Info").clicked() {
            ppid::print_info(log);
        }
    });

    if let Some(ref result) = state.last_result {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, format!("✓ {result}"));
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
