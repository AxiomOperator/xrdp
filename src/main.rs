mod app;
mod bus;
mod certs;
mod command;
mod desktop;
mod diagnose;
mod model;
mod notify;
mod probe;
mod secrets;
mod session;
mod single_instance;
mod tray;

use bus::Command;
use eframe::egui;

const USAGE: &str = "\
Usage: xrdp-gui [--connect <target>]

  --connect <target>  Connect to a saved connection (by name, host or id), or to
                      [DOMAIN\\]user@host[:port] without saving it.

If xrdp-gui is already running, the request is passed to it.";

fn parse_args(args: impl Iterator<Item = String>) -> Result<Command, String> {
    // Launchers hand us a token that lets our window take focus; pass it along.
    let token = std::env::var("XDG_ACTIVATION_TOKEN")
        .or_else(|_| std::env::var("DESKTOP_STARTUP_ID"))
        .ok()
        .filter(|t| !t.is_empty());
    let mut args = args.peekable();
    let cmd = match args.next().as_deref() {
        None => Command::Show { token },
        Some("--connect" | "-c") => match args.next() {
            Some(target) if !target.trim().is_empty() => Command::Connect { target, token },
            _ => return Err(format!("--connect needs a target\n\n{USAGE}")),
        },
        Some(a) if a.starts_with("--connect=") => Command::Connect {
            target: a["--connect=".len()..].to_string(),
            token,
        },
        Some("-h" | "--help") => {
            println!("{USAGE}");
            std::process::exit(0);
        }
        Some(other) => return Err(format!("unknown argument: {other}\n\n{USAGE}")),
    };
    match args.next() {
        Some(extra) => Err(format!("unexpected argument: {extra}\n\n{USAGE}")),
        None => Ok(cmd),
    }
}

fn options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("xrdp-gui")
            .with_app_id("xrdp-gui")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([640.0, 420.0]),
        // Return when the window closes, so the app can live on in the tray and open
        // a new window later.
        run_and_return: true,
        ..Default::default()
    }
}

fn main() -> eframe::Result {
    let request = parse_args(std::env::args().skip(1)).unwrap_or_else(|msg| {
        eprintln!("{msg}");
        std::process::exit(2);
    });
    let mut instance = match single_instance::acquire(&request) {
        Ok(Some(primary)) => Some(primary),
        Ok(None) => {
            eprintln!("xrdp-gui is already running; passed the request to it.");
            return Ok(());
        }
        Err(e) => {
            // Better to run unguarded than not at all.
            eprintln!("warning: single-instance check failed: {e:#}");
            None
        }
    };
    // Child processes (FreeRDP) must not reuse our activation token.
    // SAFETY: no other threads exist yet.
    unsafe {
        std::env::remove_var("XDG_ACTIVATION_TOKEN");
        std::env::remove_var("DESKTOP_STARTUP_ID");
    }
    let mut token = match &request {
        Command::Show { token } | Command::Connect { token, .. } => token.clone(),
        Command::Quit => None,
    };

    let mut app: Option<app::App> = None;
    loop {
        if let Some(t) = token.take() {
            // egui-winit hands this to the new window so it may take focus.
            // SAFETY: it's only read on this thread, when the window is created.
            unsafe { std::env::set_var("XDG_ACTIVATION_TOKEN", t) };
        }
        eframe::run_native(
            "xrdp-gui",
            options(),
            Box::new(|cc| {
                match &mut app {
                    Some(a) => a.attach(cc),
                    None => app = Some(app::App::new(cc, instance.take(), request.clone())),
                }
                Ok(Box::new(app::Window(app.as_mut().expect("just set"))))
            }),
        )?;
        let Some(app) = app.as_mut() else {
            return Ok(());
        };
        match app.run_hidden() {
            app::Next::Show(t) => token = t,
            app::Next::Quit => return Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn arguments() {
        assert!(matches!(parse(&[]), Ok(Command::Show { .. })));
        assert!(matches!(
            parse(&["--connect", "Lab"]),
            Ok(Command::Connect { target, .. }) if target == "Lab"
        ));
        assert!(matches!(
            parse(&["--connect=CORP\\bob@pc1:3390"]),
            Ok(Command::Connect { target, .. }) if target == "CORP\\bob@pc1:3390"
        ));
        assert!(parse(&["--connect"]).is_err());
        assert!(parse(&["--bogus"]).is_err());
        assert!(parse(&["--connect", "a", "b"]).is_err());
    }
}
