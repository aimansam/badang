use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;

const COMMON_APIS: &[&str] = &[
    "NtCreateThreadEx",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateFile",
    "NtOpenFile",
    "NtMapViewOfSection",
    "NtQueueApcThread",
    "NtDeviceIoControlFile",
];

#[derive(Default)]
pub struct UnhookState {
    pub selected: usize,
}

pub fn draw(ui: &mut egui::Ui, state: &mut UnhookState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("API Unhooking");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Target API:");
        egui::ComboBox::from_id_salt("unhook_func")
            .selected_text(COMMON_APIS[state.selected])
            .show_ui(ui, |ui| {
                for (i, name) in COMMON_APIS.iter().enumerate() {
                    ui.selectable_value(&mut state.selected, i, *name);
                }
            });
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        let label = if *dry_run {
            "Mode: DRY RUN (educational only)"
        } else {
            "Mode: LIVE"
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

    ui.add_space(4.0);

    if ui.button("Analyze").clicked() {
        let func = COMMON_APIS[state.selected];
        if *dry_run {
            log.step(format!("[DRY RUN] Would unhook API: {}", func));
            crate::unhook::dry_run(func, log);
        } else {
            crate::unhook::analyze(func, log);
        }
    }
}
