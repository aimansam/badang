use eframe::egui;

use crate::generate::{self, PayloadType};
use crate::gui::theme;
use crate::log::LogSink;
use crate::payload::{self, PayloadFormat};

#[derive(PartialEq, Clone, Copy)]
enum LoadMode {
    File,
    Convert,
    Generate,
}

pub struct LoadState {
    mode: LoadMode,
    // File mode
    pub path_input: String,
    pub error: String,
    // Convert mode
    input_text: String,
    format_idx: usize,
    auto_detect: bool,
    converted_bytes: Option<Vec<u8>>,
    convert_error: String,
    save_path: String,
    // Generate mode
    generate_type_idx: usize,
    generate_command: String,
    generate_title: String,
    generate_text: String,
    generate_lhost: String,
    generate_lport: String,
    generated_bytes: Option<Vec<u8>>,
    generate_error: String,
}

impl Default for LoadState {
    fn default() -> Self {
        Self {
            mode: LoadMode::File,
            path_input: String::new(),
            error: String::new(),
            input_text: String::new(),
            format_idx: 0,
            auto_detect: true,
            converted_bytes: None,
            convert_error: String::new(),
            save_path: String::from("payload.bin"),
            generate_type_idx: 0,
            generate_command: String::from("calc.exe"),
            generate_title: String::from("Badang"),
            generate_text: String::from("Hello from Badang"),
            generate_lhost: String::from("127.0.0.1"),
            generate_lport: String::from("4444"),
            generated_bytes: None,
            generate_error: String::new(),
        }
    }
}

pub fn draw(ui: &mut egui::Ui, state: &mut LoadState, log: &LogSink) {
    ui.heading("Payload");
    ui.add_space(4.0);

    ui.horizontal(|ui| {
        ui.selectable_value(&mut state.mode, LoadMode::File, "Load File");
        ui.selectable_value(&mut state.mode, LoadMode::Convert, "Convert Bytes");
        ui.selectable_value(&mut state.mode, LoadMode::Generate, "Generate");
    });

    ui.separator();
    ui.add_space(4.0);

    match state.mode {
        LoadMode::File => draw_file_mode(ui, state, log),
        LoadMode::Convert => draw_convert_mode(ui, state, log),
        LoadMode::Generate => draw_generate_mode(ui, state, log),
    }
}

fn draw_file_mode(ui: &mut egui::Ui, state: &mut LoadState, log: &LogSink) {
    ui.horizontal(|ui| {
        ui.label("Payload file:");
        ui.text_edit_singleline(&mut state.path_input);
        if ui.button("Browse...").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Select shellcode payload")
                .pick_file()
            {
                state.path_input = path.display().to_string();
            }
        }
    });

    if !state.error.is_empty() {
        ui.colored_label(theme::COLOR_ERROR, &state.error);
    }

    ui.add_space(4.0);

    if ui.button("Load").clicked() {
        state.error.clear();
        if state.path_input.trim().is_empty() {
            state.error = "Payload path is required".to_string();
        } else {
            match crate::injection::load_payload(state.path_input.trim()) {
                Ok(bytes) => {
                    log.step(format!("[LOAD] Payload file: {}", state.path_input));
                    log.info(format!("       Size: {} bytes", bytes.len()));
                    log.info(format!(
                        "       First bytes: {:02x?}",
                        &bytes[..bytes.len().min(16)]
                    ));
                    log.info("       (payload loaded successfully)");
                    log.detail(format!("\n{}", payload::hex_dump(&bytes)));
                }
                Err(e) => {
                    state.error = e;
                }
            }
        }
    }
}

fn draw_convert_mode(ui: &mut egui::Ui, state: &mut LoadState, log: &LogSink) {
    ui.label("Paste shellcode in any format:");
    ui.add_space(2.0);

    ui.horizontal(|ui| {
        ui.checkbox(&mut state.auto_detect, "Auto-detect format");
        if !state.auto_detect {
            ui.label("Format:");
            let formats = PayloadFormat::all();
            egui::ComboBox::from_id_salt("payload_fmt")
                .selected_text(formats[state.format_idx].name())
                .show_ui(ui, |ui| {
                    for (i, fmt) in formats.iter().enumerate() {
                        ui.selectable_value(&mut state.format_idx, i, fmt.name());
                    }
                });
        }
    });

    ui.add_space(2.0);

    let hint = if state.auto_detect {
        "fc 48 83 e4 f0 ...  or  \\xfc\\x48...  or  b'\\xfc...'  or  {0xfc, 0x48, ...}"
    } else {
        PayloadFormat::all()[state.format_idx].placeholder()
    };

    egui::ScrollArea::vertical()
        .max_height(150.0)
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut state.input_text)
                    .desired_rows(6)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace)
                    .hint_text(hint),
            );
        });

    if !state.convert_error.is_empty() {
        ui.colored_label(theme::COLOR_ERROR, &state.convert_error);
    }

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button("Convert").clicked() {
            state.convert_error.clear();
            state.converted_bytes = None;

            if state.input_text.trim().is_empty() {
                state.convert_error = "Paste shellcode bytes above".to_string();
            } else if state.auto_detect {
                match payload::auto_parse(&state.input_text) {
                    Ok((bytes, fmt)) => {
                        log.step(format!(
                            "[CONVERT] Parsed {} bytes (detected format: {})",
                            bytes.len(),
                            fmt.name()
                        ));
                        log.detail(format!("\n{}", payload::hex_dump(&bytes)));
                        state.converted_bytes = Some(bytes);
                    }
                    Err(e) => {
                        state.convert_error = format!("Parse error: {}", e);
                    }
                }
            } else {
                let fmt = PayloadFormat::all()[state.format_idx];
                match payload::parse(&state.input_text, fmt) {
                    Ok(bytes) => {
                        log.step(format!(
                            "[CONVERT] Parsed {} bytes (format: {})",
                            bytes.len(),
                            fmt.name()
                        ));
                        log.detail(format!("\n{}", payload::hex_dump(&bytes)));
                        state.converted_bytes = Some(bytes);
                    }
                    Err(e) => {
                        state.convert_error = format!("Parse error: {}", e);
                    }
                }
            }
        }

        draw_output_buttons(
            ui,
            &state.converted_bytes,
            &mut state.convert_error,
            &mut state.save_path,
            log,
        );
    });

    if let Some(ref bytes) = state.converted_bytes {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, format!("{} bytes ready", bytes.len()));
    }
}

fn draw_generate_mode(ui: &mut egui::Ui, state: &mut LoadState, log: &LogSink) {
    ui.label("Generate shellcode payload (no msfvenom needed):");
    ui.add_space(2.0);

    let types = PayloadType::all();

    ui.horizontal(|ui| {
        ui.label("Type:");
        egui::ComboBox::from_id_salt("generate_type")
            .selected_text(types[state.generate_type_idx].name())
            .show_ui(ui, |ui| {
                for (i, t) in types.iter().enumerate() {
                    ui.selectable_value(&mut state.generate_type_idx, i, t.name());
                }
            });
    });

    let selected = types[state.generate_type_idx];
    ui.colored_label(theme::TEXT_DIM, selected.description());
    ui.add_space(4.0);

    match selected {
        PayloadType::Exec => {
            ui.horizontal(|ui| {
                ui.label("Command:");
                ui.text_edit_singleline(&mut state.generate_command);
            });
        }
        PayloadType::MessageBox => {
            ui.horizontal(|ui| {
                ui.label("Title:");
                ui.text_edit_singleline(&mut state.generate_title);
            });
            ui.horizontal(|ui| {
                ui.label("Text:");
                ui.text_edit_singleline(&mut state.generate_text);
            });
        }
        PayloadType::ReverseTcp => {
            ui.horizontal(|ui| {
                ui.label("LHOST:");
                ui.text_edit_singleline(&mut state.generate_lhost);
            });
            ui.horizontal(|ui| {
                ui.label("LPORT:");
                ui.add(egui::TextEdit::singleline(&mut state.generate_lport).desired_width(80.0));
            });
        }
        PayloadType::BindTcp => {
            ui.horizontal(|ui| {
                ui.label("LPORT:");
                ui.add(egui::TextEdit::singleline(&mut state.generate_lport).desired_width(80.0));
            });
        }
    }

    if !state.generate_error.is_empty() {
        ui.colored_label(theme::COLOR_ERROR, &state.generate_error);
    }

    ui.add_space(4.0);

    ui.horizontal(|ui| {
        if ui.button("Generate").clicked() {
            state.generate_error.clear();
            state.generated_bytes = None;

            let lport = state.generate_lport.trim().parse::<u16>().unwrap_or(0);
            let config = generate::PayloadConfig {
                payload_type: selected,
                command: state.generate_command.clone(),
                title: state.generate_title.clone(),
                text: state.generate_text.clone(),
                lhost: state.generate_lhost.clone(),
                lport,
            };

            match generate::generate(&config) {
                Ok(bytes) => {
                    log.step(format!(
                        "[GENERATE] {} — {} bytes",
                        selected.name(),
                        bytes.len()
                    ));
                    log.detail(format!("\n{}", payload::hex_dump(&bytes)));
                    state.generated_bytes = Some(bytes);
                }
                Err(e) => {
                    state.generate_error = format!("Generation error: {}", e);
                }
            }
        }

        draw_output_buttons(
            ui,
            &state.generated_bytes,
            &mut state.generate_error,
            &mut state.save_path,
            log,
        );
    });

    if let Some(ref bytes) = state.generated_bytes {
        ui.add_space(4.0);
        ui.colored_label(theme::ACCENT_GREEN, format!("{} bytes ready", bytes.len()));
    }
}

fn draw_output_buttons(
    ui: &mut egui::Ui,
    bytes_opt: &Option<Vec<u8>>,
    error: &mut String,
    save_path: &mut String,
    log: &LogSink,
) {
    if let Some(ref bytes) = bytes_opt {
        if ui.button("Save .bin").clicked() {
            if let Some(path) = rfd::FileDialog::new()
                .set_title("Save raw payload")
                .set_file_name(save_path.as_str())
                .add_filter("Binary", &["bin"])
                .add_filter("All", &["*"])
                .save_file()
            {
                match std::fs::write(&path, bytes) {
                    Ok(()) => {
                        *save_path = path.display().to_string();
                        log.step(format!(
                            "[SAVED] {} bytes -> {}",
                            bytes.len(),
                            path.display()
                        ));
                    }
                    Err(e) => {
                        *error = format!("Save failed: {}", e);
                    }
                }
            }
        }

        if ui.button("Copy as C").clicked() {
            ui.ctx().copy_text(payload::to_c_array(bytes));
            log.info("[COPY] C array copied to clipboard");
        }

        if ui.button("Copy as Python").clicked() {
            ui.ctx().copy_text(payload::to_python_bytes(bytes));
            log.info("[COPY] Python bytes copied to clipboard");
        }

        if ui.button("Copy as Rust").clicked() {
            ui.ctx().copy_text(payload::to_rust_array(bytes));
            log.info("[COPY] Rust array copied to clipboard");
        }
    }
}
