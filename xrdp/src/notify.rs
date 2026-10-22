//! Desktop notifications (freedesktop.org, via D-Bus).

use std::thread;

use notify_rust::{Notification, Urgency};

const ICON: &str = "preferences-desktop-remote-desktop";

/// Shows a notification without blocking the UI thread.
pub fn send(summary: String, body: String, urgent: bool) {
    thread::spawn(move || {
        let _ = Notification::new()
            .appname("xrdp-gui")
            .summary(&summary)
            .body(&body)
            .icon(ICON)
            .urgency(if urgent {
                Urgency::Critical
            } else {
                Urgency::Normal
            })
            .show();
    });
}
