use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::evasion::sleep_obfs;

#[derive(Default)]
pub struct SleepState {
    pub selected: usize,
    pub duration_input: String,
    pub error: String,
    pub last_result: Option<String>,
}

pub fn draw(ui: &mut egui::Ui, state: &mut SleepState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Memory Protection");
    ui.label("Encrypt memory regions during idle periods.");
    ui.add_space(8.0);

    let methods = sleep_obfs::SleepMethod::all();
    ui.horizontal(|ui| {
        ui.label("Method:");
        egui::ComboBox::from_id_salt("sleep_method")
            .selected_text(methods[state.selected].name())
            .show_ui(ui, |ui| {
                for (i, m) in methods.iter().enumerate() {
                    ui.selectable_value(&mut state.selected, i, m.name());
                }
            });
    });

    ui.horizontal(|ui| {
        ui.label("Duration (ms):");
        if state.duration_input.is_empty() {
            state.duration_input = "3000".to_string();
        }
        ui.text_edit_singleline(&mut state.duration_input);
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
        if ui.button("Demo").clicked() {
            state.error.clear();
            state.last_result = None;
            let duration: u32 = state.duration_input.trim().parse().unwrap_or(3000);
            let method = methods[state.selected];
            if *dry_run {
                let method_str = match method {
                    sleep_obfs::SleepMethod::Manual => "manual",
                    sleep_obfs::SleepMethod::Ekko => "ekko",
                };
                sleep_obfs::dry_run(method_str, duration, log);
            } else {
                let result = match method {
                    sleep_obfs::SleepMethod::Manual => sleep_obfs::demo_manual(duration, log),
                    sleep_obfs::SleepMethod::Ekko => sleep_obfs::demo_ekko(duration, log),
                };
                match result {
                    Ok(demo) => {
                        state.last_result = Some(format!(
                            "Region 0x{:016X} ({} bytes), slept {} ms",
                            demo.region_base, demo.region_size, demo.sleep_ms
                        ));
                    }
                    Err(e) => state.error = e,
                }
            }
        }

        if ui.button("Info").clicked() {
            sleep_obfs::print_info(log);
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
