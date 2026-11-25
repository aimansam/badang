use eframe::egui;

use crate::evasion::amsi;
use crate::gui::theme;
use crate::log::LogSink;

const TARGETS: &[&str] = &["AmsiScanBuffer", "AmsiScanString"];

pub struct AmsiState {
    pub selected: usize,
    pub patch_state: Option<amsi::PatchState>,
    pub error: String,
}

impl Default for AmsiState {
    fn default() -> Self {
        Self {
            selected: 0,
            patch_state: None,
            error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut AmsiState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("AMSI Bypass");
    ui.label("Patch AMSI functions to disable script/assembly scanning.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Target:");
        egui::ComboBox::from_id_salt("amsi_target")
            .selected_text(TARGETS[state.selected])
            .show_ui(ui, |ui| {
                for (i, name) in TARGETS.iter().enumerate() {
                    ui.selectable_value(&mut state.selected, i, *name);
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
        let target = TARGETS[state.selected];
        let is_patched = state.patch_state.is_some();

        if ui.button("Patch").clicked() {
            state.error.clear();
            if *dry_run {
                amsi::dry_run(target, log);
            } else {
                match amsi::patch(target, log) {
                    Ok(ps) => {
                        state.patch_state = Some(ps);
                    }
                    Err(e) => {
                        state.error = e;
                    }
                }
            }
        }

        if ui
            .add_enabled(is_patched, egui::Button::new("Restore"))
            .clicked()
        {
            if let Some(ref ps) = state.patch_state {
                match amsi::restore(ps, log) {
                    Ok(()) => {
                        state.patch_state = None;
                        state.error.clear();
                    }
                    Err(e) => {
                        state.error = e;
                    }
                }
            }
        }

        if ui.button("Info").clicked() {
            amsi::print_info(log);
        }
    });

    if state.patch_state.is_some() {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, "✓ AMSI function patched");
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
