mod app;
mod command;
mod diagnose;
mod model;
mod notify;
mod probe;
mod secrets;
mod session;

use eframe::egui;

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("xrdp-gui")
            .with_app_id("xrdp-gui")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };
    eframe::run_native(
        "xrdp-gui",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}
