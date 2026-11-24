use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;

const FUNCTIONS: &[&str] = &[
    "NtCreateThreadEx",
    "NtAllocateVirtualMemory",
    "NtWriteVirtualMemory",
    "NtProtectVirtualMemory",
    "NtMapViewOfSection",
    "NtQueueApcThread",
    "NtCreateFile",
    "NtOpenFile",
    "NtReadFile",
    "NtWriteFile",
    "NtDeviceIoControlFile",
    "NtClose",
    "NtWaitForSingleObject",
];

#[derive(Default)]
pub struct SyscallState {
    pub selected: usize,
}

pub fn draw(ui: &mut egui::Ui, state: &mut SyscallState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Direct Syscall Invocation");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("NT Function:");
        egui::ComboBox::from_id_salt("syscall_func")
            .selected_text(FUNCTIONS[state.selected])
            .show_ui(ui, |ui| {
                for (i, name) in FUNCTIONS.iter().enumerate() {
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

    if ui.button("Look Up").clicked() {
        let func = FUNCTIONS[state.selected];
        if *dry_run {
            log.step(format!("[DRY RUN] Would invoke syscall: {}", func));
            crate::syscall::dry_run(func, log);
        } else {
            crate::syscall::analyze(func, log);
        }
    }
}
