//! Ensures only one copy of the app runs, so two windows can't overwrite each other's
//! config. A second launch asks the running copy to show itself and exits.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use anyhow::{Context, Result};
use eframe::egui;

/// Held by the running copy for its whole lifetime.
pub struct Primary {
    _lock: File,
    listener: UnixListener,
}

fn runtime_dir() -> PathBuf {
    directories::BaseDirs::new()
        .and_then(|d| d.runtime_dir().map(|p| p.to_path_buf()))
        .unwrap_or_else(std::env::temp_dir)
}

/// Returns `Some` if this is the only copy, or `None` after asking the existing copy to
/// come to the front.
pub fn acquire() -> Result<Option<Primary>> {
    let dir = runtime_dir();
    let user = unsafe { libc::getuid() };
    let lock_path = dir.join(format!("xrdp-gui-{user}.lock"));
    let sock_path = dir.join(format!("xrdp-gui-{user}.sock"));

    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("opening {}", lock_path.display()))?;
    // SAFETY: flock on a file descriptor we own; released automatically when it closes.
    let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;

    if !locked {
        if let Ok(mut stream) = UnixStream::connect(&sock_path) {
            let _ = stream.write_all(b"show\n");
        }
        return Ok(None);
    }

    // We hold the lock, so any socket file left behind is stale.
    let _ = std::fs::remove_file(&sock_path);
    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("binding {}", sock_path.display()))?;
    Ok(Some(Primary {
        _lock: lock,
        listener,
    }))
}

impl Primary {
    /// Sets `show` whenever another launch asks this copy to come to the front.
    pub fn listen(&self, ctx: egui::Context) -> Result<Arc<AtomicBool>> {
        let show = Arc::new(AtomicBool::new(false));
        let flag = show.clone();
        let listener = self.listener.try_clone()?;
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut buf = [0u8; 16];
                let _ = stream.read(&mut buf);
                flag.store(true, Ordering::SeqCst);
                ctx.request_repaint();
            }
        });
        Ok(show)
    }
}
