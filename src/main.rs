mod app;
mod backup;
mod bus;
mod certs;
mod command;
mod desktop;
mod diagnose;
mod embed;
mod model;
mod notify;
mod probe;
mod secrets;
mod session;
mod single_instance;
mod terminal;
mod tray;

use std::sync::{RwLock, RwLockWriteGuard, TryLockError};
use std::time::{Duration, Instant};

use bus::Command;
use eframe::egui;

/// Taken for writing while `main` hands egui-winit an activation token through the
/// environment (egui-winit reads and clears it when it creates the window). Threads that
/// read the environment from C, such as host-name lookups, take it for reading: glibc's
/// `getenv` isn't safe against a concurrent `setenv`. Rust's own `std::env` is already
/// locked internally.
pub static ENV_LOCK: RwLock<()> = RwLock::new(());

/// `ENV_LOCK` for writing, unless a stuck lookup holds it for longer than `patience`: a
/// host-name lookup can take many seconds, which mustn't freeze the app.
fn env_write_lock(patience: Duration) -> Option<RwLockWriteGuard<'static, ()>> {
    let deadline = Instant::now() + patience;
    loop {
        match ENV_LOCK.try_write() {
            Ok(guard) => return Some(guard),
            Err(TryLockError::Poisoned(e)) => return Some(e.into_inner()),
            Err(TryLockError::WouldBlock) if Instant::now() >= deadline => return None,
            Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
}

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

/// A connection manager has no need of a laptop's discrete GPU, and drawing on it costs a
/// copy of every frame across to the GPU that drives the screen, which is slow through
/// XWayland. So prefer an integrated GPU, of those that can actually draw to this window.
/// `WGPU_POWER_PREF` overrides this.
fn low_power_gpu() -> eframe::egui_wgpu::WgpuConfiguration {
    use eframe::egui_wgpu::{WgpuConfiguration, WgpuSetup, wgpu};
    let mut config = WgpuConfiguration::default();
    if wgpu::PowerPreference::from_env().is_none()
        && let WgpuSetup::CreateNew(setup) = &mut config.wgpu_setup
    {
        setup.native_adapter_selector = Some(std::sync::Arc::new(|adapters, surface| {
            adapters
                .iter()
                .filter(|a| surface.is_none_or(|s| a.is_surface_supported(s)))
                .min_by_key(|a| {
                    let info = a.get_info();
                    (
                        gpu_rank(info.device_type),
                        info.backend != wgpu::Backend::Vulkan,
                    )
                })
                .cloned()
                .ok_or_else(|| "no GPU can draw to this window".to_string())
        }));
    }
    config
}

/// Lower is better. Drawing in software comes last, but still beats not starting.
fn gpu_rank(device: eframe::egui_wgpu::wgpu::DeviceType) -> u8 {
    use eframe::egui_wgpu::wgpu::DeviceType;
    match device {
        DeviceType::IntegratedGpu => 0,
        DeviceType::DiscreteGpu => 1,
        DeviceType::VirtualGpu => 2,
        DeviceType::Other => 3,
        DeviceType::Cpu => 4,
    }
}

fn options() -> eframe::NativeOptions {
    eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("xrdp-gui")
            .with_app_id("xrdp-gui")
            .with_inner_size([1000.0, 680.0])
            .with_min_inner_size([860.0, 420.0]),
        // Return when the window closes, so the app can live on in the tray and open
        // a new window later.
        run_and_return: true,
        wgpu_options: low_power_gpu(),
        event_loop_builder: Some(Box::new(|builder| {
            // RDP sessions can only be shown inside an X11 window (see `embed`).
            // `XRDP_GUI_WAYLAND` keeps the window native, and RDP sessions in their own.
            if std::env::var_os("DISPLAY").is_some()
                && std::env::var_os("XRDP_GUI_WAYLAND").is_none()
            {
                use winit::platform::x11::EventLoopBuilderExtX11;
                builder.with_x11();
            }
        })),
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
        let mut env_guard = None;
        // Without the lock the window still opens, it just may not take focus.
        if let Some(t) = token.take()
            && let Some(guard) = env_write_lock(Duration::from_millis(250))
        {
            // egui-winit hands this to the new window so it may take focus.
            // SAFETY: other threads only read the environment through `std::env` (which
            // serialises with this) or while holding ENV_LOCK, which we hold until the
            // window exists and egui-winit has removed the variable again.
            unsafe { std::env::set_var("XDG_ACTIVATION_TOKEN", t) };
            env_guard = Some(guard);
        }
        eframe::run_native(
            "xrdp-gui",
            options(),
            Box::new(|cc| {
                // The window has been created by now.
                drop(env_guard.take());
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
    #[test]
    fn integrated_gpus_come_first_and_software_last() {
        use eframe::egui_wgpu::wgpu::DeviceType::*;
        assert!(super::gpu_rank(IntegratedGpu) < super::gpu_rank(DiscreteGpu));
        assert!(super::gpu_rank(DiscreteGpu) < super::gpu_rank(Cpu));
    }

    use super::*;

    fn parse(args: &[&str]) -> Result<Command, String> {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn stuck_lookup_only_delays_the_window_briefly() {
        let lookup = ENV_LOCK.read().unwrap();
        let start = Instant::now();
        assert!(env_write_lock(Duration::from_millis(50)).is_none());
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(lookup);
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
