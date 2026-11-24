use eframe::egui::{self, Color32, CornerRadius, FontId, Stroke, TextStyle, Visuals};

pub const BG_DARK: Color32 = Color32::from_rgb(0x12, 0x12, 0x1a);
pub const BG_PANEL: Color32 = Color32::from_rgb(0x1a, 0x1a, 0x2e);
pub const BG_WIDGET: Color32 = Color32::from_rgb(0x22, 0x22, 0x3a);
pub const ACCENT_GREEN: Color32 = Color32::from_rgb(0x00, 0xff, 0x41);
pub const ACCENT_CYAN: Color32 = Color32::from_rgb(0x00, 0xd4, 0xff);
pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(0xe0, 0xe0, 0xe0);
pub const TEXT_DIM: Color32 = Color32::from_rgb(0x88, 0x88, 0x99);
pub const COLOR_ERROR: Color32 = Color32::from_rgb(0xff, 0x33, 0x33);
pub const COLOR_WARNING: Color32 = Color32::from_rgb(0xff, 0xaa, 0x00);
pub const COLOR_STEP: Color32 = ACCENT_CYAN;

const CORNER: CornerRadius = CornerRadius::same(4);

pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::dark();

    visuals.panel_fill = BG_DARK;
    visuals.window_fill = BG_PANEL;
    visuals.extreme_bg_color = BG_WIDGET;
    visuals.faint_bg_color = BG_PANEL;

    visuals.widgets.noninteractive.bg_fill = BG_PANEL;
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.noninteractive.corner_radius = CORNER;

    visuals.widgets.inactive.bg_fill = BG_WIDGET;
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, TEXT_PRIMARY);
    visuals.widgets.inactive.corner_radius = CORNER;

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x2a, 0x2a, 0x44);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, ACCENT_CYAN);
    visuals.widgets.hovered.corner_radius = CORNER;

    visuals.widgets.active.bg_fill = Color32::from_rgb(0x2a, 0x2a, 0x44);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, ACCENT_GREEN);
    visuals.widgets.active.corner_radius = CORNER;

    visuals.selection.bg_fill = Color32::from_rgb(0x1e, 0x2e, 0x1e);
    visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT_GREEN);

    ctx.set_visuals(visuals);

    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        TextStyle::Heading,
        FontId::new(18.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Body,
        FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Monospace,
        FontId::new(13.0, egui::FontFamily::Monospace),
    );
    style.text_styles.insert(
        TextStyle::Button,
        FontId::new(14.0, egui::FontFamily::Proportional),
    );
    style.text_styles.insert(
        TextStyle::Small,
        FontId::new(12.0, egui::FontFamily::Proportional),
    );
    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    ctx.set_style(style);
}
