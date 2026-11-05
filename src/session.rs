//! Running FreeRDP and terminal child processes and their captured output.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use uuid::Uuid;

use crate::bus::Bus;
use crate::certs;
use crate::command;
use crate::diagnose::{self, Diagnosis, Severity};
use crate::embed::Area;
use crate::terminal::Terminal;

const MAX_LOG_LINES: usize = 5000;
/// With no new attempt for this long, a reconnecting session is assumed to be back. FreeRDP
/// doesn't log success. One attempt can outlast several connection timeouts when the network
/// is gone, so this is generous: "Reconnected" comes late rather than wrongly.
const RECONNECT_QUIET: Duration = Duration::from_secs(60);
/// How long to wait after the client exits for its last output lines.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

pub enum Status {
    Running,
    Exited(Diagnosis),
}

pub struct Output {
    pub lines: Vec<String>,
    /// The latest "Attempting reconnect (n of m)" and when it was seen.
    pub reconnect: Option<(u32, u32, Instant)>,
    /// Output streams (stdout, stderr) not yet read to the end.
    open_streams: u8,
}

/// Where a session appears.
pub enum Surface {
    /// In a window of its own.
    OwnWindow,
    /// FreeRDP inside the main window.
    Rdp {
        /// The child window it draws into; gone once the session has ended.
        holder: Option<u32>,
        placed: Option<Area>,
        visible: bool,
    },
    /// A terminal inside the main window.
    Terminal(Box<Terminal>),
}

impl Surface {
    pub fn in_main_window(&self) -> bool {
        !matches!(self, Self::OwnWindow)
    }
}

pub struct Session {
    /// Tells this session apart for as long as the app runs (indexes shift).
    pub uid: u64,
    pub surface: Surface,
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
    /// An SSH session in a terminal window, rather than FreeRDP.
    terminal: bool,
    /// Set once the client has exited (and been reaped), while its last output drains.
    exited: Option<(ExitStatus, Instant)>,
    /// None for a terminal inside the main window, which runs its program by itself.
    child: Option<Child>,
}

fn next_uid() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
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
        Self::spawn_with(client, args, connection_id, name, bus, false)
    }

    /// Like [`Session::spawn`], for a client drawing inside the main window. If the app
    /// dies without closing it, it must go too: it would stay logged in with nothing on
    /// screen to show for it or close it with.
    pub fn spawn_in_holder(
        client: &str,
        args: &[String],
        connection_id: Uuid,
        name: String,
        bus: &Bus,
    ) -> Result<Self> {
        Self::spawn_with(client, args, connection_id, name, bus, true)
    }

    fn spawn_with(
        client: &str,
        args: &[String],
        connection_id: Uuid,
        name: String,
        bus: &Bus,
        die_with_app: bool,
    ) -> Result<Self> {
        let mut command = Command::new(client);
        if die_with_app {
            // SIGKILL because `xfreerdp` hangs in its SIGTERM handler once its window is gone.
            // SAFETY: prctl is async-signal-safe, and nothing else happens between fork and
            // exec here. The signal follows the thread that spawned this, which is the
            // UI's, and that lasts as long as the app does.
            unsafe {
                command.pre_exec(|| {
                    if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command
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

        let command = command::preview(client, args);
        Ok(Self::started(
            child,
            connection_id,
            name,
            command,
            false,
            bus,
        ))
    }

    /// Opens a terminal running `argv`. `command` is what to show for it in reports.
    pub fn spawn_terminal(
        argv: &[String],
        command: String,
        connection_id: Uuid,
        name: String,
        bus: &Bus,
    ) -> Result<Self> {
        let (program, args) = argv.split_first().context("no terminal command")?;
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| {
                format!("Couldn't start the terminal `{program}`. Check the command in Settings.")
            })?;
        Ok(Self::started(
            child,
            connection_id,
            name,
            command,
            true,
            bus,
        ))
    }

    /// Runs `program` in a terminal inside the main window.
    pub fn spawn_in_main_window(
        program: &str,
        args: &[String],
        command: String,
        connection_id: Uuid,
        name: String,
        bus: &Bus,
    ) -> Result<Self> {
        let terminal = Terminal::spawn(program, args, bus)?;
        Ok(Self {
            uid: next_uid(),
            surface: Surface::Terminal(Box::new(terminal)),
            connection_id,
            name,
            started: Instant::now(),
            started_at: Local::now(),
            ended: None,
            command,
            status: Status::Running,
            output: Arc::new(Mutex::new(Output {
                lines: Vec::new(),
                reconnect: None,
                open_streams: 0,
            })),
            reconnect_notified: false,
            stopped_by_user: false,
            terminal: false,
            exited: None,
            child: None,
        })
    }

    fn started(
        mut child: Child,
        connection_id: Uuid,
        name: String,
        command: String,
        terminal: bool,
        bus: &Bus,
    ) -> Self {
        let output = Arc::new(Mutex::new(Output {
            lines: Vec::new(),
            reconnect: None,
            open_streams: 2,
        }));
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");
        pump(stdout, output.clone(), bus.clone());
        pump(stderr, output.clone(), bus.clone());

        Self {
            uid: next_uid(),
            surface: Surface::OwnWindow,
            connection_id,
            name,
            started: Instant::now(),
            started_at: Local::now(),
            ended: None,
            command,
            status: Status::Running,
            output,
            reconnect_notified: false,
            stopped_by_user: false,
            terminal,
            exited: None,
            child: Some(child),
        }
    }

    /// Updates `status`; returns true if the session ended since the last poll.
    pub fn poll(&mut self) -> bool {
        if !self.is_running() {
            return false;
        }
        if let Surface::Terminal(terminal) = &self.surface {
            let ended = terminal.ended();
            if ended.is_none() && !self.stopped_by_user {
                return false;
            }
            self.status =
                Status::Exited(diagnose::ssh_ended(ended.flatten(), self.stopped_by_user));
            self.ended = Some(Instant::now());
            return true;
        }
        if self.exited.is_none()
            && let Some(Ok(Some(exit))) = self.child.as_mut().map(Child::try_wait)
        {
            self.exited = Some((exit, Instant::now()));
        }
        let Some((exit, at)) = self.exited else {
            return false;
        };
        let out = self.output.lock().unwrap();
        // Wait for the reader threads to drain the final lines, unless something else
        // (a process the client started, say) keeps the pipes open.
        if out.open_streams > 0 && at.elapsed() < DRAIN_TIMEOUT {
            return false;
        }
        if self.terminal {
            drop(out);
            self.status = Status::Exited(diagnose::terminal_ended(exit, self.stopped_by_user));
            self.ended = Some(at);
            return true;
        }
        let mut diagnosis = diagnose::diagnose(&out.lines, exit, self.stopped_by_user);
        drop(out);
        // FreeRDP logs the same warnings for a changed certificate and an unknown one.
        if let Some(c) = &diagnosis.cert
            && !certs::path_for(&c.host, c.port).is_ok_and(|p| p.exists())
        {
            diagnosis = diagnose::untrusted_certificate();
        }
        self.status = Status::Exited(diagnosis);
        self.ended = Some(at);
        true
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
        if let Surface::Terminal(terminal) = &self.surface {
            if self.is_running() {
                self.stopped_by_user = true;
                terminal.shutdown();
            }
            return;
        }
        // Once reaped, the pid may already belong to another process.
        if let Some(child) = self.child.as_ref().filter(|_| self.exited.is_none())
            && self.is_running()
        {
            self.stopped_by_user = true;
            // SAFETY: plain syscall on a pid we own and have not yet reaped.
            unsafe {
                libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Reap the child if it has exited so it does not linger as a zombie.
        if let Some(child) = &mut self.child {
            let _ = child.try_wait();
        }
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
        output.lock().unwrap().open_streams -= 1;
        bus.wake();
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
