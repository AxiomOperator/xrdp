//! The system tray icon (StatusNotifierItem, as used by KDE Plasma): quick access to
//! favourite and recent connections while the window is closed.

use ksni::blocking::TrayMethods;
use ksni::menu::{MenuItem, StandardItem};
use uuid::Uuid;

use crate::bus::{Bus, Command};

/// A connection as listed in the tray menu.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    pub id: Uuid,
    pub name: String,
    pub running: bool,
}

/// What the tray shows; the app pushes a new one whenever it changes.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Menu {
    pub favourites: Vec<Entry>,
    pub recent: Vec<Entry>,
    pub running: usize,
}

struct XrdpTray {
    menu: Menu,
    bus: Bus,
    icon: String,
}

pub struct Tray {
    handle: ksni::blocking::Handle<XrdpTray>,
    shown: Menu,
}

impl Tray {
    /// Starts the tray icon; fails if the desktop has no tray (StatusNotifierWatcher).
    pub fn spawn(bus: Bus) -> anyhow::Result<Self> {
        // Our own icon if installed, a stock one otherwise.
        let installed =
            directories::BaseDirs::new().is_some_and(|d| {
                d.data_dir()
                    .join("icons/hicolor/scalable/apps/xrdp-gui.svg")
                    .exists()
            }) || std::path::Path::new("/usr/share/icons/hicolor/scalable/apps/xrdp-gui.svg")
                .exists();
        let icon = if installed {
            "xrdp-gui"
        } else {
            "preferences-desktop-remote-desktop"
        };
        let handle = XrdpTray {
            menu: Menu::default(),
            bus,
            icon: icon.into(),
        }
        .spawn()
        .map_err(|e| anyhow::anyhow!("tray icon unavailable: {e}"))?;
        Ok(Self {
            handle,
            shown: Menu::default(),
        })
    }

    pub fn set_menu(&mut self, menu: Menu) {
        if menu != self.shown {
            self.shown = menu.clone();
            self.handle.update(move |t| t.menu = menu);
        }
    }

    pub fn is_alive(&self) -> bool {
        !self.handle.is_closed()
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        // Removes the icon right away instead of when the process exits.
        let _ = self.handle.shutdown();
    }
}

fn item(
    label: String,
    icon: &str,
    run: impl Fn(&mut XrdpTray) + Send + Sync + 'static,
) -> MenuItem<XrdpTray> {
    StandardItem {
        label,
        icon_name: icon.into(),
        activate: Box::new(run),
        ..Default::default()
    }
    .into()
}

fn heading(label: &str) -> MenuItem<XrdpTray> {
    StandardItem {
        label: label.into(),
        enabled: false,
        ..Default::default()
    }
    .into()
}

fn connect_items(entries: &[Entry]) -> Vec<MenuItem<XrdpTray>> {
    entries
        .iter()
        .map(|e| {
            let id = e.id;
            // Menu labels treat '_' as a mnemonic marker.
            let mut label = e.name.replace('_', "__");
            if e.running {
                label.push_str("  (connected)");
            }
            item(label, "network-connect", move |t| {
                t.bus.send(Command::Connect {
                    target: id.to_string(),
                    token: ksni::current_xdg_activation_token(),
                })
            })
        })
        .collect()
}

impl ksni::Tray for XrdpTray {
    fn id(&self) -> String {
        "xrdp-gui".into()
    }

    fn title(&self) -> String {
        "xrdp-gui".into()
    }

    fn icon_name(&self) -> String {
        self.icon.clone()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        let description = match self.menu.running {
            0 => "No sessions running".to_string(),
            1 => "1 session running".to_string(),
            n => format!("{n} sessions running"),
        };
        ksni::ToolTip {
            title: "xrdp-gui".into(),
            description,
            ..Default::default()
        }
    }

    /// Left click opens the window.
    fn activate(&mut self, _x: i32, _y: i32) {
        self.bus.send(Command::Show {
            token: ksni::current_xdg_activation_token(),
        });
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let mut items = vec![item("Open xrdp-gui".into(), "window-new", |t| {
            t.bus.send(Command::Show {
                token: ksni::current_xdg_activation_token(),
            })
        })];
        if !self.menu.favourites.is_empty() {
            items.push(MenuItem::Separator);
            items.push(heading("Favourites"));
            items.extend(connect_items(&self.menu.favourites));
        }
        if !self.menu.recent.is_empty() {
            items.push(MenuItem::Separator);
            items.push(heading("Recent"));
            items.extend(connect_items(&self.menu.recent));
        }
        items.push(MenuItem::Separator);
        items.push(item("Quit".into(), "application-exit", |t| {
            t.bus.send(Command::Quit)
        }));
        items
    }
}
