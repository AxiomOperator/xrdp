//! Showing FreeRDP inside the main window. `xfreerdp` can draw into a window it's given
//! (`/parent-window`), which is an X11 feature, so the main window uses X11 too (XWayland on
//! a Wayland desktop). Each session gets a "holder" child window placed over the part of
//! the main window where it should appear.
//!
//! Holders outlive the main window: closing it to the tray destroys it, along with any
//! child windows, which would end the sessions, so holders move to the root window first.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    AtomEnum, ConfigureWindowAux, ConnectionExt, CreateWindowAux, EventMask, InputFocus,
    WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

/// Where a session should appear, in the main window's physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Area {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Area {
    fn contains(self, x: i32, y: i32) -> bool {
        x >= self.x
            && y >= self.y
            && x < self.x + self.width as i32
            && y < self.y + self.height as i32
    }
}

/// The main window's X11 id, if it has one (it doesn't on native Wayland).
pub fn x11_window(window: &impl HasWindowHandle) -> Option<u32> {
    match window.window_handle().ok()?.as_raw() {
        RawWindowHandle::Xlib(h) => u32::try_from(h.window).ok(),
        RawWindowHandle::Xcb(h) => Some(h.window.get()),
        _ => None,
    }
}

/// How often to check where the pointer is, for sending the keyboard to the right place.
const FOCUS_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Copy)]
struct FocusState {
    main: u32,
    /// The session showing, and where.
    shown: Option<(u32, Area)>,
}

pub struct Host {
    conn: RustConnection,
    root: u32,
    main: u32,
    focus: Arc<Mutex<FocusState>>,
}

impl Host {
    pub fn new(main: u32) -> Result<Self> {
        let (conn, screen) = x11rb::connect(None).context("connecting to the X server")?;
        let root = conn.setup().roots[screen].root;
        let focus = Arc::new(Mutex::new(FocusState { main, shown: None }));
        // On its own connection and thread: redrawing a large window just to watch the
        // pointer would slow everything down.
        let (focus_conn, _) = x11rb::connect(None).context("connecting to the X server")?;
        let active_window_atom = focus_conn
            .intern_atom(false, b"_NET_ACTIVE_WINDOW")?
            .reply()
            .context("asking the X server for an atom")?
            .atom;
        let state = Arc::downgrade(&focus);
        thread::spawn(move || {
            let mut focused = None;
            // Ends with the host, or if the connection goes away.
            while let Some(state) = state.upgrade() {
                let current = *state.lock().unwrap();
                drop(state);
                if update_focus(&focus_conn, root, active_window_atom, current, &mut focused)
                    .is_err()
                {
                    return;
                }
                thread::sleep(FOCUS_INTERVAL);
            }
        });
        Ok(Self {
            conn,
            root,
            main,
            focus,
        })
    }

    /// A hidden window for `xfreerdp` to draw into.
    pub fn create_holder(&self, area: Area) -> Result<u32> {
        let id = self.conn.generate_id()?;
        self.conn.create_window(
            x11rb::COPY_DEPTH_FROM_PARENT,
            id,
            self.main,
            area.x as i16,
            area.y as i16,
            area.width.max(1) as u16,
            area.height.max(1) as u16,
            0,
            WindowClass::INPUT_OUTPUT,
            x11rb::COPY_FROM_PARENT,
            // Without the override, the window manager would adopt it while it's on the root.
            &CreateWindowAux::new()
                .override_redirect(1)
                .event_mask(EventMask::NO_EVENT),
        )?;
        self.conn.flush()?;
        Ok(id)
    }

    /// `xfreerdp`'s window inside a holder, once it has made one.
    fn client_window(&self, holder: u32) -> Option<u32> {
        let tree = self.conn.query_tree(holder).ok()?.reply().ok()?;
        tree.children.first().copied()
    }

    /// Whether `xfreerdp` has connected far enough to be worth showing.
    pub fn has_client(&self, holder: u32) -> bool {
        self.client_window(holder).is_some()
    }

    /// Moves and sizes a holder and the session in it.
    pub fn place(&self, holder: u32, area: Area) -> Result<()> {
        let aux = ConfigureWindowAux::new()
            .x(area.x)
            .y(area.y)
            .width(area.width.max(1))
            .height(area.height.max(1));
        self.conn.configure_window(holder, &aux)?;
        if let Some(client) = self.client_window(holder) {
            let size = ConfigureWindowAux::new()
                .width(area.width.max(1))
                .height(area.height.max(1));
            self.conn.configure_window(client, &size)?;
        }
        self.conn.flush()?;
        Ok(())
    }

    pub fn set_visible(&self, holder: u32, visible: bool) -> Result<()> {
        if visible {
            self.conn.map_window(holder)?;
            if let Some(client) = self.client_window(holder) {
                self.conn.map_window(client)?;
            }
        } else {
            self.conn.unmap_window(holder)?;
        }
        self.conn.flush()?;
        Ok(())
    }

    pub fn destroy(&self, holder: u32) {
        let _ = self.conn.destroy_window(holder);
        let _ = self.conn.flush();
    }

    /// Takes a holder off the main window, which is about to close.
    pub fn detach(&self, holder: u32) -> Result<()> {
        self.conn.unmap_window(holder)?;
        self.conn.reparent_window(holder, self.root, 0, 0)?;
        // Before the main window goes, or the session goes with it.
        self.conn.sync()?;
        Ok(())
    }

    /// Hooks up to a new main window, and takes the holders along.
    pub fn attach(&mut self, main: u32, holders: impl Iterator<Item = u32>) -> Result<()> {
        self.main = main;
        *self.focus.lock().unwrap() = FocusState { main, shown: None };
        for holder in holders {
            self.conn.reparent_window(holder, main, 0, 0)?;
        }
        self.conn.flush()?;
        Ok(())
    }

    /// Says which session is showing now, for the keyboard to follow the pointer onto it.
    pub fn set_shown(&self, shown: Option<(u32, Area)>) {
        self.focus.lock().unwrap().shown = shown;
    }
}

/// Sends the keyboard to the session while the pointer is over it, and back to the main
/// window otherwise. A child window can't get focus from the window manager, and
/// `xfreerdp` won't take it when embedded.
fn update_focus(
    conn: &RustConnection,
    root: u32,
    active_window_atom: u32,
    state: FocusState,
    focused: &mut Option<u32>,
) -> Result<()> {
    // Nothing to track, which is the usual case: no X traffic at all.
    if state.shown.is_none() && focused.is_none() {
        return Ok(());
    }
    let pointer = conn.query_pointer(state.main)?.reply()?;
    let over = state.shown.filter(|(_, area)| {
        pointer.same_screen && area.contains(pointer.win_x.into(), pointer.win_y.into())
    });
    let over = match over {
        Some((holder, _)) => {
            let active = conn
                .get_property(false, root, active_window_atom, AtomEnum::WINDOW, 0, 1)?
                .reply()?;
            let is_main = active
                .value32()
                .and_then(|mut v| v.next())
                .is_some_and(|window| window == state.main);
            if is_main {
                conn.query_tree(holder)?.reply()?.children.first().copied()
            } else {
                None
            }
        }
        None => None,
    };
    if over != *focused {
        conn.set_input_focus(
            InputFocus::PARENT,
            over.unwrap_or(state.main),
            x11rb::CURRENT_TIME,
        )?;
        conn.flush()?;
        *focused = over;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn area_edges() {
        let area = Area {
            x: 10,
            y: 20,
            width: 100,
            height: 50,
        };
        assert!(area.contains(10, 20));
        assert!(area.contains(109, 69));
        assert!(!area.contains(110, 69));
        assert!(!area.contains(9, 20));
        assert!(!area.contains(50, 70));
    }
}
