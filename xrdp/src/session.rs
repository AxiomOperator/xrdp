//! Running FreeRDP child processes and their captured output.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use uuid::Uuid;

const MAX_LOG_LINES: usize = 5000;

pub enum Status {
    Running,
    Exited(ExitStatus),
}

pub struct Session {
    pub connection_id: Uuid,
    pub name: String,
    pub started: Instant,
    pub status: Status,
    pub log: Arc<Mutex<Vec<String>>>,
    child: Child,
}

impl Session {
    /// Spawns `client`, handing it `args` over stdin so passwords never appear in the
    /// process list.
    pub fn spawn(
        client: &str,
        args: &[String],
        connection_id: Uuid,
        name: String,
        ctx: &eframe::egui::Context,
    ) -> Result<Self> {
        let mut child = Command::new(client)
            .arg("/args-from:stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to start `{client}`"))?;

        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut payload = args.join("\n");
        payload.push('\n');
        // If this fails the client has already exited; its output will say why.
        let _ = stdin.write_all(payload.as_bytes());
        drop(stdin);

        let log = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        pump(stdout, log.clone(), ctx.clone());
        pump(stderr, log.clone(), ctx.clone());

        Ok(Self {
            connection_id,
            name,
            started: Instant::now(),
            status: Status::Running,
            log,
            child,
        })
    }

    /// Updates `status`; returns true if the process exited since the last poll.
    pub fn poll(&mut self) -> bool {
        if let Status::Running = self.status
            && let Ok(Some(st)) = self.child.try_wait() {
                self.status = Status::Exited(st);
                return true;
            }
        false
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status, Status::Running)
    }

    /// Asks the client to shut down gracefully.
    pub fn terminate(&self) {
        if self.is_running() {
            // SAFETY: plain syscall on a pid we own and have not yet reaped.
            unsafe {
                libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Reap the child if it has exited so it does not linger as a zombie.
        let _ = self.child.try_wait();
    }
}

fn pump(stream: impl Read + Send + 'static, log: Arc<Mutex<Vec<String>>>, ctx: eframe::egui::Context) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            let mut log = log.lock().unwrap();
            if log.len() >= MAX_LOG_LINES {
                log.drain(..MAX_LOG_LINES / 10);
            }
            log.push(line);
            drop(log);
            ctx.request_repaint();
        }
    });
}
