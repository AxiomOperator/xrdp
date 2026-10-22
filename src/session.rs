//! Running FreeRDP child processes and their captured output.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use uuid::Uuid;

use crate::bus::Bus;
use crate::command;
use crate::diagnose::{self, Diagnosis, Severity};

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
    pub started_at: DateTime<Local>,
    pub ended: Option<Instant>,
    /// The command line with passwords masked, for support reports.
    pub command: String,
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
        bus: &Bus,
    ) -> Result<Self> {
        let mut child = Command::new(client)
            .arg("/args-from:stdin")
            // sdl-freerdp's Wayland app id, which picks the window's icon.
            .env("SDL_APP_ID", command::SESSION_APP_ID)
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
        pump(stdout, output.clone(), bus.clone());
        pump(stderr, output.clone(), bus.clone());

        Ok(Self {
            connection_id,
            name,
            started: Instant::now(),
            started_at: Local::now(),
            ended: None,
            command: command::preview(client, args),
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
            self.ended = Some(Instant::now());
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

    /// A self-contained, password-free report of this session for sending to support.
    pub fn report(&self) -> String {
        let result = match &self.status {
            Status::Running => "still running".to_string(),
            Status::Exited(d) => {
                let kind = match d.severity {
                    Severity::Normal => "ended",
                    Severity::Dropped => "dropped",
                    Severity::Failed => "failed",
                };
                let code = d
                    .code
                    .as_deref()
                    .map(|c| format!(" [{c}]"))
                    .unwrap_or_default();
                format!("{kind}: {}{code}", d.title)
            }
        };
        let out = self.output.lock().unwrap();
        let mut report = format!(
            "xrdp-gui {} session log\n\
             Connection: {}\n\
             Started:    {}\n\
             Duration:   {}s\n\
             Result:     {result}\n\
             Command:    {}\n\
             ----------------------------------------\n",
            env!("CARGO_PKG_VERSION"),
            self.name,
            self.started_at.format("%Y-%m-%d %H:%M:%S %z"),
            self.ended
                .unwrap_or_else(Instant::now)
                .duration_since(self.started)
                .as_secs(),
            self.command,
        );
        for line in &out.lines {
            report.push_str(line);
            report.push('\n');
        }
        report
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

fn pump(stream: impl Read + Send + 'static, output: Arc<Mutex<Output>>, bus: Bus) {
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
            bus.wake();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Runs a fake FreeRDP that reads its arguments, logs a logon failure and exits
    /// with FreeRDP's logon-failure code.
    #[test]
    fn fake_client_end_to_end() {
        let dir = std::env::temp_dir().join(format!("xrdp-gui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let client = dir.join("fake-freerdp");
        std::fs::write(
            &client,
            "#!/bin/sh\n\
             [ \"$1\" = /args-from:stdin ] || exit 128\n\
             echo \"got $(wc -l) args\"\n\
             echo '[ERROR][com.freerdp.core] - [nla_client]: ERRCONNECT_LOGON_FAILURE [0x00020014]' >&2\n\
             exit 134\n",
        )
        .unwrap();
        std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();

        let args: Vec<String> = ["/v:host", "/u:alice", "/p:hunter2"]
            .map(String::from)
            .into();
        let bus = Bus::default();
        let mut s = Session::spawn(
            client.to_str().unwrap(),
            &args,
            Uuid::new_v4(),
            "Lab".into(),
            &bus,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !s.poll() {
            assert!(Instant::now() < deadline, "fake client did not exit");
            thread::sleep(Duration::from_millis(20));
        }

        let Status::Exited(d) = &s.status else {
            unreachable!()
        };
        assert_eq!(d.title, "Wrong username or password");
        let report = s.report();
        assert!(report.contains("got 3 args"), "{report}");
        assert!(report.contains("failed: Wrong username or password [ERRCONNECT_LOGON_FAILURE]"));
        assert!(report.contains("/p:***"));
        assert!(
            !report.contains("hunter2"),
            "password leaked into report:\n{report}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
