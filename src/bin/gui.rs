// Badang — GUI binary entry point (egui/eframe)
// For authorized security research and red team use only.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(feature = "gui")]
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([900.0, 650.0])
            .with_min_inner_size([700.0, 500.0])
            .with_title("Badang — EDR Evasion Research Toolkit"),
        ..Default::default()
    };
    eframe::run_native(
        "Badang",
        options,
        Box::new(|cc| Ok(Box::new(badang::gui::app::BadangApp::new(cc)))),
    )
}

#[cfg(not(feature = "gui"))]
fn main() {
    eprintln!("This binary requires the 'gui' feature. Build with: cargo build --features gui");
    std::process::exit(1);
}
