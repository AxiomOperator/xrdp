//! Lets background threads (sessions, host probes, the tray, other launches) wake the
//! app and hand it commands, whether or not its window is currently open.

use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use eframe::egui;

/// A request from outside the window: the tray menu or another `xrdp-gui` launch.
#[derive(Debug, Clone, PartialEq)]
pub enum Command {
    /// Open the window (or bring it to the front). `token` is a Wayland/X11
    /// activation token that lets the window take focus.
    Show {
        token: Option<String>,
    },
    /// Connect to a saved connection (by id, name or host) or, failing that, to the
    /// target as a host name.
    Connect {
        target: String,
        token: Option<String>,
    },
    Quit,
}

#[derive(Default)]
struct State {
    ctx: Option<egui::Context>,
    queue: Vec<Command>,
    woken: bool,
}

#[derive(Clone, Default)]
pub struct Bus {
    inner: Arc<(Mutex<State>, Condvar)>,
}

impl Bus {
    /// The window's context to repaint on wake-ups; `None` while the window is closed.
    pub fn set_ctx(&self, ctx: Option<egui::Context>) {
        self.inner.0.lock().unwrap().ctx = ctx;
    }

    /// Something changed: repaint the window, or wake [`Bus::wait`] if it is closed.
    pub fn wake(&self) {
        let ctx = {
            let mut s = self.inner.0.lock().unwrap();
            s.woken = true;
            s.ctx.clone()
        };
        self.inner.1.notify_all();
        if let Some(ctx) = ctx {
            ctx.request_repaint();
        }
    }

    pub fn send(&self, cmd: Command) {
        self.inner.0.lock().unwrap().queue.push(cmd);
        self.wake();
    }

    pub fn take(&self) -> Vec<Command> {
        std::mem::take(&mut self.inner.0.lock().unwrap().queue)
    }

    /// Blocks until [`Bus::wake`] is called or `timeout` passes.
    pub fn wait(&self, timeout: Duration) {
        let (lock, cvar) = &*self.inner;
        let s = lock.lock().unwrap();
        let (mut s, _) = cvar.wait_timeout_while(s, timeout, |s| !s.woken).unwrap();
        s.woken = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn send_wakes_a_waiter() {
        let bus = Bus::default();
        let sender = bus.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            sender.send(Command::Quit);
        });
        let start = Instant::now();
        bus.wait(Duration::from_secs(5));
        assert!(start.elapsed() < Duration::from_secs(2));
        assert_eq!(bus.take(), [Command::Quit]);
        assert!(bus.take().is_empty());
        t.join().unwrap();
    }
}
