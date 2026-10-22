//! Ensures only one copy of the app runs, so two windows can't overwrite each other's
//! config. A second launch passes its request (show, or `--connect`) to the running copy
//! and exits.

use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;

use anyhow::{Context, Result};

use crate::bus::{Bus, Command};

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

/// Returns `Some` if this is the only copy, or `None` after handing `request` to the
/// existing copy.
pub fn acquire(request: &Command) -> Result<Option<Primary>> {
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
            let _ = stream.write_all(encode(request).as_bytes());
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
    /// Forwards requests from later launches to `bus`.
    pub fn listen(&self, bus: Bus) -> Result<()> {
        let listener = self.listener.try_clone()?;
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut line = String::new();
                let _ = BufReader::new(stream.take(4096)).read_line(&mut line);
                // Anything unreadable still means "someone launched us": show the window.
                bus.send(decode(&line).unwrap_or(Command::Show { token: None }));
            }
        });
        Ok(())
    }
}

/// One line, tab-separated. Tabs and newlines can't occur in tokens, and are replaced
/// in targets.
fn encode(cmd: &Command) -> String {
    let clean = |s: &str| s.replace(['\t', '\n', '\r'], " ");
    let token = |t: &Option<String>| t.as_deref().map(clean).unwrap_or_default();
    match cmd {
        Command::Show { token: t } => format!("show\t{}\n", token(t)),
        Command::Connect { target, token: t } => {
            format!("connect\t{}\t{}\n", clean(target), token(t))
        }
        Command::Quit => "quit\n".into(),
    }
}

fn decode(line: &str) -> Option<Command> {
    let mut parts = line.trim_end_matches(['\n', '\r']).split('\t');
    let token = |t: Option<&str>| t.filter(|t| !t.is_empty()).map(String::from);
    match parts.next()? {
        "show" => Some(Command::Show {
            token: token(parts.next()),
        }),
        "connect" => Some(Command::Connect {
            target: parts.next()?.to_string(),
            token: token(parts.next()),
        }),
        "quit" => Some(Command::Quit),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for cmd in [
            Command::Show { token: None },
            Command::Show {
                token: Some("kwin-123".into()),
            },
            Command::Connect {
                target: "Lab server".into(),
                token: Some("t".into()),
            },
            Command::Connect {
                target: "host".into(),
                token: None,
            },
            Command::Quit,
        ] {
            assert_eq!(decode(&encode(&cmd)), Some(cmd));
        }
        // Old-style "show" from 0.2 and junk.
        assert_eq!(decode("show\n"), Some(Command::Show { token: None }));
        assert_eq!(decode("bogus\n"), None);
    }
}
