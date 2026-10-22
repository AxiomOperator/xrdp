//! Running FreeRDP child processes and their captured output.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use eframe::egui;
use uuid::Uuid;

use crate::diagnose::{self, Diagnosis};

const MAX_LOG_LINES: usize = 5000;
/// With no new attempt for this long, a reconnecting session is assumed to be back.
const RECONNECT_QUIET: Duration = Duration::from_secs(20);

pub enum Status {
    Running,
    Exited(Diagnosis),
}

#[derive(Default)]
pub struct Output {
    pub lines: Vec<String>,
    /// The latest "Attempting reconnect (n of m)" and when it was seen.
    pub reconnect: Option<(u32, u32, Instant)>,
}

pub struct Session {
    pub connection_id: Uuid,
    pub name: String,
    pub started: Instant,
    pub status: Status,
    pub output: Arc<Mutex<Output>>,
    /// Whether the user has been told about the current reconnect episode.
    pub reconnect_notified: bool,
    stopped_by_user: bool,
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
        ctx: &egui::Context,
    ) -> Result<Self> {
        let mut child = Command::new(client)
            .arg("/args-from:stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!(
                    "Couldn't start `{client}`. Is FreeRDP installed? (sudo dnf install freerdp)"
                )
            })?;

        let mut stdin = child.stdin.take().expect("stdin is piped");
        let mut payload = args.join("\n");
        payload.push('\n');
        // If this fails the client has already exited; its output will say why.
        let _ = stdin.write_all(payload.as_bytes());
        drop(stdin);

        let output = Arc::new(Mutex::new(Output::default()));
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        pump(stdout, output.clone(), ctx.clone());
        pump(stderr, output.clone(), ctx.clone());

        Ok(Self {
            connection_id,
            name,
            started: Instant::now(),
            status: Status::Running,
            output,
            reconnect_notified: false,
            stopped_by_user: false,
            child,
        })
    }

    /// Updates `status`; returns true if the process exited since the last poll.
    pub fn poll(&mut self) -> bool {
        if let Status::Running = self.status
            && let Ok(Some(exit)) = self.child.try_wait()
        {
            // Give the reader threads a moment to drain the final lines.
            thread::sleep(Duration::from_millis(50));
            let out = self.output.lock().unwrap();
            let diagnosis = diagnose::diagnose(&out.lines, exit, self.stopped_by_user);
            drop(out);
            self.status = Status::Exited(diagnosis);
            return true;
        }
        false
    }

    pub fn is_running(&self) -> bool {
        matches!(self.status, Status::Running)
    }

    /// The current reconnect attempt, if the session is reconnecting right now.
    pub fn reconnecting(&self) -> Option<(u32, u32)> {
        if !self.is_running() {
            return None;
        }
        let out = self.output.lock().unwrap();
        out.reconnect
            .filter(|(_, _, at)| at.elapsed() < RECONNECT_QUIET)
            .map(|(n, m, _)| (n, m))
    }

    /// Asks the client to shut down gracefully.
    pub fn terminate(&mut self) {
        if self.is_running() {
            self.stopped_by_user = true;
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

fn pump(stream: impl Read + Send + 'static, output: Arc<Mutex<Output>>, ctx: egui::Context) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { break };
            let mut out = output.lock().unwrap();
            if let Some((n, m)) = diagnose::reconnect_attempt(&line) {
                out.reconnect = Some((n, m, Instant::now()));
            }
            if out.lines.len() >= MAX_LOG_LINES {
                out.lines.drain(..MAX_LOG_LINES / 10);
            }
            out.lines.push(line);
            drop(out);
            ctx.request_repaint();
        }
    });
}
