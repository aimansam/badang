use eframe::egui;

use crate::gui::theme;
use crate::log::{LogEntry, LogLevel};

pub fn draw(ui: &mut egui::Ui, entries: &[LogEntry], on_clear: &mut bool) {
    ui.horizontal(|ui| {
        ui.colored_label(theme::ACCENT_GREEN, "Log Output");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui.small_button("Clear").clicked() {
                *on_clear = true;
            }
        });
    });

    ui.separator();

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .stick_to_bottom(true)
        .show(ui, |ui| {
            for entry in entries {
                let color = match entry.level {
                    LogLevel::Info => theme::TEXT_PRIMARY,
                    LogLevel::Step => theme::COLOR_STEP,
                    LogLevel::Warning => theme::COLOR_WARNING,
                    LogLevel::Error => theme::COLOR_ERROR,
                    LogLevel::Detail => theme::TEXT_DIM,
                };
                ui.colored_label(color, &entry.message);
            }
        });
}
