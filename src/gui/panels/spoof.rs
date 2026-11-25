use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::evasion::stack_spoof;

const FUNCTIONS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtMapViewOfSection",
    "NtQueueApcThread",
    "NtCreateFile",
    "NtOpenFile",
];

#[derive(Default)]
pub struct SpoofState {
    pub selected: usize,
    pub error: String,
    pub last_result: Option<String>,
}

pub fn draw(ui: &mut egui::Ui, state: &mut SpoofState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Stack Spoofing");
    ui.label("Fake call stack frames to bypass EDR stack-walking.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Target function:");
        egui::ComboBox::from_id_salt("spoof_func")
            .selected_text(FUNCTIONS[state.selected])
            .show_ui(ui, |ui| {
                for (i, name) in FUNCTIONS.iter().enumerate() {
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
        if ui.button("Demo").clicked() {
            state.error.clear();
            state.last_result = None;
            let func = FUNCTIONS[state.selected];
            if *dry_run {
                stack_spoof::dry_run(func, log);
            } else {
                match stack_spoof::demo_spoofed_call(func, log) {
                    Ok(result) => {
                        state.last_result = Some(format!(
                            "{} — {} frames, {} gadgets",
                            result.target_func,
                            result.frames_built,
                            result.gadget_addrs.len()
                        ));
                    }
                    Err(e) => state.error = e,
                }
            }
        }

        if ui.button("Info").clicked() {
            stack_spoof::print_info(log);
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
