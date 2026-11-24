use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::process::ProcessInfo;

#[derive(Default)]
pub struct ScanState {
    pub filter: String,
    pub processes: Vec<ProcessInfo>,
    pub scanned: bool,
}

pub fn draw(ui: &mut egui::Ui, state: &mut ScanState, log: &LogSink) {
    ui.heading("Process Scanner");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Filter:");
        ui.text_edit_singleline(&mut state.filter);
        if ui.button("Scan").clicked() {
            state.processes = crate::process::scan(log);
            state.scanned = true;
        }
    });

    ui.add_space(4.0);

    if !state.scanned {
        ui.colored_label(theme::TEXT_DIM, "Click Scan to enumerate running processes.");
        return;
    }

    let filtered: Vec<&ProcessInfo> = if state.filter.is_empty() {
        state.processes.iter().collect()
    } else {
        let q = state.filter.to_lowercase();
        state
            .processes
            .iter()
            .filter(|p| p.name.to_lowercase().contains(&q))
            .collect()
    };

    ui.colored_label(
        theme::ACCENT_GREEN,
        format!("{} processes (showing {})", state.processes.len(), filtered.len()),
    );
    ui.add_space(4.0);

    let row_height = 18.0;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show_rows(ui, row_height, filtered.len(), |ui, row_range| {
            egui::Grid::new("process_grid")
                .striped(true)
                .min_col_width(60.0)
                .show(ui, |ui| {
                    if row_range.start == 0 {
                        ui.colored_label(theme::TEXT_DIM, "PID");
                        ui.colored_label(theme::TEXT_DIM, "NAME");
                        ui.end_row();
                    }
                    for p in &filtered[row_range] {
                        ui.label(format!("{}", p.pid));
                        ui.label(&p.name);
                        ui.end_row();
                    }
                });
        });
}
