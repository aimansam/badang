use eframe::egui;

use crate::gui::panels::{amsi, analyze, etw, inject, load, log_panel, ppid, scan, sleep, spoof, syscall, unhook};
use crate::gui::theme;
use crate::log::{LogEntry, LogSink};

#[derive(PartialEq)]
enum Tab {
    Scan,
    Analyze,
    Syscall,
    Inject,
    Load,
    Unhook,
    Etw,
    Amsi,
    Ppid,
    Sleep,
    Spoof,
}

pub struct BadangApp {
    active_tab: Tab,
    dry_run: bool,
    confirm: bool,

    log_sink: LogSink,
    log_entries: Vec<LogEntry>,

    analyze_state: analyze::AnalyzeState,
    syscall_state: syscall::SyscallState,
    inject_state: inject::InjectState,
    load_state: load::LoadState,
    scan_state: scan::ScanState,
    unhook_state: unhook::UnhookState,
    etw_state: etw::EtwState,
    amsi_state: amsi::AmsiState,
    ppid_state: ppid::PpidState,
    sleep_state: sleep::SleepState,
    spoof_state: spoof::SpoofState,

    theme_applied: bool,
}

impl BadangApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            active_tab: Tab::Scan,
            dry_run: true,
            confirm: false,

            log_sink: LogSink::new(),
            log_entries: Vec::new(),

            analyze_state: analyze::AnalyzeState::default(),
            syscall_state: syscall::SyscallState::default(),
            inject_state: inject::InjectState::default(),
            load_state: load::LoadState::default(),
            scan_state: scan::ScanState::default(),
            unhook_state: unhook::UnhookState::default(),
            etw_state: etw::EtwState::default(),
            amsi_state: amsi::AmsiState::default(),
            ppid_state: ppid::PpidState::default(),
            sleep_state: sleep::SleepState::default(),
            spoof_state: spoof::SpoofState::default(),

            theme_applied: false,
        }
    }
}

impl eframe::App for BadangApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            theme::apply(ctx);
            self.theme_applied = true;
        }

        self.log_entries = self.log_sink.snapshot();

        // Top bar
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.colored_label(theme::ACCENT_GREEN, "BADANG");
                ui.label("v0.2.0");
            });
        });

        // Tab bar
        egui::TopBottomPanel::top("tab_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.active_tab, Tab::Scan, "Scan");
                ui.selectable_value(&mut self.active_tab, Tab::Analyze, "Analyze");
                ui.selectable_value(&mut self.active_tab, Tab::Syscall, "Syscall");
                ui.selectable_value(&mut self.active_tab, Tab::Inject, "Techniques");
                ui.selectable_value(&mut self.active_tab, Tab::Load, "Load");
                ui.selectable_value(&mut self.active_tab, Tab::Unhook, "Restore");
                ui.selectable_value(&mut self.active_tab, Tab::Etw, "ETW");
                ui.selectable_value(&mut self.active_tab, Tab::Amsi, "AMSI");
                ui.selectable_value(&mut self.active_tab, Tab::Ppid, "PPID");
                ui.selectable_value(&mut self.active_tab, Tab::Sleep, "Sleep");
                ui.selectable_value(&mut self.active_tab, Tab::Spoof, "Stack");
            });
        });

        // Log panel at bottom
        egui::TopBottomPanel::bottom("log_panel")
            .min_height(150.0)
            .resizable(true)
            .show(ctx, |ui| {
                let mut clear = false;
                log_panel::draw(ui, &self.log_entries, &mut clear);
                if clear {
                    self.log_sink.clear();
                    self.log_entries.clear();
                }
            });

        // Status bar
        egui::TopBottomPanel::bottom("status_bar")
            .exact_height(24.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.inject_state.task_running {
                        ui.colored_label(theme::COLOR_WARNING, "Running injection...");
                    } else {
                        ui.colored_label(theme::TEXT_DIM, "Ready");
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.colored_label(theme::TEXT_DIM, "Authorized research only");
                    });
                });
            });

        // Central content panel
        egui::CentralPanel::default().show(ctx, |ui| match self.active_tab {
            Tab::Scan => {
                scan::draw(ui, &mut self.scan_state, &self.log_sink);
            }
            Tab::Analyze => {
                analyze::draw(ui, &mut self.analyze_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Syscall => {
                syscall::draw(ui, &mut self.syscall_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Inject => {
                inject::draw(
                    ui,
                    &mut self.inject_state,
                    &mut self.dry_run,
                    &mut self.confirm,
                    &self.log_sink,
                    ctx,
                );
            }
            Tab::Load => {
                load::draw(ui, &mut self.load_state, &self.log_sink);
            }
            Tab::Unhook => {
                unhook::draw(ui, &mut self.unhook_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Etw => {
                etw::draw(ui, &mut self.etw_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Amsi => {
                amsi::draw(ui, &mut self.amsi_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Ppid => {
                ppid::draw(ui, &mut self.ppid_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Sleep => {
                sleep::draw(ui, &mut self.sleep_state, &mut self.dry_run, &self.log_sink);
            }
            Tab::Spoof => {
                spoof::draw(ui, &mut self.spoof_state, &mut self.dry_run, &self.log_sink);
            }
        });
    }
}
