use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use eframe::egui::{self, Color32, Key as KeyCode, KeyboardShortcut, Modifiers, RichText};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::backup::{Backup, RestoreMode};
use crate::bus::{Bus, Command};
use crate::certs::{self, KnownCert};
use crate::command::{self, Credentials};
use crate::desktop;
use crate::diagnose::{CertIssue, Fix, Severity};
use crate::embed::{self, Area};
use crate::model::{
    self, CertPolicy, CertReview, ClipboardShare, Config, Connection, GatewayMode, Group, Profile,
    Protocol, Resolved, Scaling, Settings,
};
use crate::notify;
use crate::probe::{Prober, Reach, Target};
use crate::secrets::{self, Key};
use crate::session::{Session, Status, Surface};
use crate::single_instance::Primary;
use crate::terminal::Terminal;
use crate::tray::{self, Tray};

/// eframe storage key for the last selected item.
const SELECTION_KEY: &str = "selection";
const SEARCH_ID: &str = "connection_search";
const QUICK_ID: &str = "quick_connect";
/// How many recently used connections the sidebar and tray show.
const RECENT_COUNT: usize = 5;

const SHORTCUT_NEW: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::N);
const SHORTCUT_SAVE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::S);
const SHORTCUT_FIND: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::F);
const SHORTCUT_QUICK: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::L);
const SHORTCUT_QUIT: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::Q);

/// What was selected in the sidebar, restored on the next start.
#[derive(Serialize, Deserialize)]
enum Selection {
    Connection(Uuid),
    Group(String),
}

const RESOLUTIONS: &[(u32, u32)] = &[
    (1280, 720),
    (1366, 768),
    (1600, 900),
    (1920, 1080),
    (2560, 1440),
    (3840, 2160),
];
const LOG_LEVELS: &[&str] = &["OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
const CLIENTS: &[&str] = &[
    "sdl-freerdp",
    "xfreerdp",
    "sdl-freerdp3",
    "xfreerdp3",
    "wlfreerdp",
];
const GREEN: Color32 = Color32::from_rgb(80, 200, 120);
const RED: Color32 = Color32::from_rgb(225, 85, 85);
const AMBER: Color32 = Color32::from_rgb(230, 170, 60);

/// The connection being edited, plus any newly typed passwords (never persisted to disk).
struct Draft {
    conn: Connection,
    /// The connection as it was when editing started.
    pristine: Connection,
    password: String,
    gateway_password: String,
    /// The tags as typed; parsed into `conn.tags` as you type.
    tags_text: String,
    is_new: bool,
}

impl Draft {
    fn new(conn: Connection, is_new: bool) -> Self {
        Self {
            tags_text: conn.tags.join(", "),
            pristine: conn.clone(),
            conn,
            password: String::new(),
            gateway_password: String::new(),
            is_new,
        }
    }
}

/// The group whose defaults are being edited.
struct GroupDraft {
    group: Group,
    /// The group as currently saved (or an empty one if it has no saved defaults).
    original: Group,
    /// For a group not created yet: how it started out, so one left untouched can simply
    /// be dropped.
    new_from: Option<Group>,
    password: String,
    gateway_password: String,
}

impl GroupDraft {
    fn new(config: &Config, name: &str) -> Self {
        let original = config.group(name).cloned().unwrap_or_else(|| Group {
            name: name.to_string(),
            ..Default::default()
        });
        Self {
            group: original.clone(),
            original,
            new_from: None,
            password: String::new(),
            gateway_password: String::new(),
        }
    }
}

/// Asks for whichever passwords a connection needs that aren't in the keyring.
struct PasswordPrompt {
    /// A copy, so quick connections (which aren't saved) work too.
    conn: Connection,
    target: String,
    /// The password from the keyring, when only the gateway password is missing.
    saved_password: Option<String>,
    password: String,
    /// Where "Save in keyring" stores the password and what to call it; `None` for
    /// quick connections.
    save_to: Option<(Key, String)>,
    remember: bool,
    /// Set when a gateway with its own credentials has no saved password.
    gateway: Option<GatewayPrompt>,
    /// The gateway password from the keyring, if it has one.
    saved_gateway_password: Option<String>,
    /// Whether the first field has been given keyboard focus.
    focused: bool,
}

struct GatewayPrompt {
    target: String,
    password: String,
    save_to: Option<(Key, String)>,
    remember: bool,
}

/// A saved certificate about to be forgotten, once the user has compared fingerprints.
struct CertForget {
    host: String,
    port: u16,
    path: PathBuf,
    old_fingerprint: Option<String>,
    /// From FreeRDP's log, when forgetting because the server presented a new one.
    new_fingerprint: Option<String>,
}

/// Passwords read from the keyring for a connection about to be launched.
struct Lookup {
    conn: Connection,
    password: Result<Option<String>>,
    gateway_password: Result<Option<String>>,
}

/// A backup that was opened, waiting for a decision on how to restore it.
struct PendingRestore {
    backup: Backup,
    file: String,
}

/// A change to the keyring, run in the background by [`App::keyring`].
enum KeyringOp {
    Set(Key, String),
    Delete(Key),
    /// Moves a password to a new entry (a group was renamed).
    Move {
        from: Key,
        to: Key,
    },
}

/// Results of keyring work, handed back to the UI thread.
enum KeyringDone {
    Looked(Box<Lookup>),
    /// `key`, if any, ended up without a password even though the config says it has one.
    Failed(Option<Key>, anyhow::Error),
}

/// What happens when the window closes.
#[derive(Debug, Clone, PartialEq)]
pub enum Exit {
    Quit,
    /// Keep running in the tray.
    Hide,
    /// Close and immediately reopen, so the new window can take focus with `token`.
    Reopen(Option<String>),
}

/// What `main` should do after the window has closed.
pub enum Next {
    Show(Option<String>),
    Quit,
}

enum Action {
    NewConnection,
    NewGroup,
    Select(Uuid),
    SelectGroup(String),
    Save,
    Revert,
    Duplicate(Uuid),
    AskDelete(Uuid),
    Delete(Uuid),
    ClearGroup,
    Forget(Key),
    /// Forgets whichever password the connection uses (its own or its group's).
    ForgetPassword(Uuid),
    /// Asks about forgetting the certificate FreeRDP refused, or else the connection's.
    ForgetCertificate(Uuid, Option<CertIssue>),
    ToggleFavorite(Uuid),
    Connect(Uuid),
    /// Starts another session although the connection already has one.
    ConnectAnyway(Uuid),
    QuickConnect,
    OpenCertificates,
    AskForgetKnownCert {
        host: String,
        port: u16,
        path: PathBuf,
        fingerprint: String,
    },
    ForgetCertConfirmed,
    AskQuit,
    Launch,
    Stop(usize),
    Dismiss(usize),
    ClearEnded,
    SaveSettings,
    /// Asks where to save a backup, then writes it.
    Backup,
    /// Asks for a backup to restore, then shows what restoring it would do.
    PickRestore,
    Restore(RestoreMode),
    /// Shows a session in the main area, or the connection form.
    ShowSession(Option<u64>),
    Quit,
}

pub struct App {
    config: Config,
    config_path: std::path::PathBuf,
    /// Set when the config file failed to load; saving is disabled so it is not clobbered.
    load_error: Option<String>,
    draft: Option<Draft>,
    group_draft: Option<GroupDraft>,
    search: String,
    sessions: Vec<Session>,
    log_session: Option<usize>,
    prompt: Option<PasswordPrompt>,
    confirm_delete: Option<Uuid>,
    /// A connection that already has a running session, and was asked to connect again.
    confirm_second: Option<Uuid>,
    confirm_forget_cert: Option<CertForget>,
    settings_draft: Option<Settings>,
    confirm_quit: bool,
    /// Why pending edits couldn't be saved on quit; shown in the quit dialog.
    quit_save_error: Option<String>,
    allow_close: bool,
    notice: Option<(String, bool)>,
    prober: Prober,
    actions: Vec<Action>,
    /// Keeps the single-instance lock for as long as the app runs.
    _instance: Option<Primary>,
    /// Commands from the tray and other launches, and wake-ups from background threads.
    bus: Bus,
    /// Notices from background work (e.g. saving a log file).
    inbox: Arc<Mutex<Vec<(String, bool)>>>,
    /// Runs keyring work off the UI thread, in order.
    keyring: secrets::Queue,
    /// Finished keyring work, waiting to be handled on the UI thread.
    keyring_done: Arc<Mutex<Vec<KeyringDone>>>,
    /// Connections whose passwords are being read from the keyring.
    pending_lookups: Vec<Uuid>,
    /// Set by a request from the tray or another launch: the activation token to bring
    /// the window forward with if that request ends up asking for a password.
    raise_for_prompt: Option<Option<String>>,
    /// Counts errors shown, so the tray can tell whether a request failed.
    errors: u64,
    /// Bumped whenever the config changes (every change goes through `save_config`).
    config_version: std::cell::Cell<u64>,
    /// The config version the host checks were last set up for.
    probed_version: Option<u64>,
    /// Text of the quick-connect box.
    quick: String,
    /// Quick connections made this run; not saved.
    adhoc: Vec<Connection>,
    /// The certificate manager's list, while it is open.
    known_certs: Option<Vec<KnownCert>>,
    backup_open: bool,
    /// The backup being restored, while its window is open.
    restore: Option<PendingRestore>,
    /// A backup file opened in the background (or why it couldn't be).
    restore_inbox: Arc<Mutex<Option<Result<PendingRestore, String>>>>,
    /// The X11 side of the main window, when sessions can be shown inside it.
    x11: Option<embed::Host>,
    /// The session showing in the main area, instead of the connection form.
    active_session: Option<u64>,
    /// The main area, in window pixels, as of the last frame.
    session_area: Option<Area>,
    /// Window pixels per egui point, as of the last frame.
    session_scale: f32,
    /// What SSH connections run; only tests change this.
    ssh_program: String,
    /// Whether to touch the desktop: tray icon and launcher actions (off in tests).
    integrations: bool,
    tray: Option<Tray>,
    /// Favourites last written to the launcher actions.
    launcher_favourites: Option<Vec<(Uuid, String)>>,
    told_about_tray: bool,
    exit: Exit,
}

impl App {
    /// The real app: with the tray icon, launcher actions and `request` from the command
    /// line (e.g. `--connect`).
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        instance: Option<Primary>,
        request: Command,
    ) -> Self {
        let path = Config::path().unwrap_or_else(|_| "xrdp-gui.toml".into());
        let mut app = Self::with_config_path(cc, instance, path);
        app.integrations = true;
        app.x11 = embed::x11_window(cc).and_then(|window| embed::Host::new(window).ok());
        app.sync_tray_setting();
        if let Command::Connect { .. } = request {
            app.bus.send(request);
        }
        app
    }

    fn with_config_path(
        cc: &eframe::CreationContext<'_>,
        instance: Option<Primary>,
        config_path: PathBuf,
    ) -> Self {
        let (config, load_error) = match Config::load(&config_path) {
            Ok(c) => (c, None),
            Err(e) => (Config::default(), Some(format!("{e:#}"))),
        };
        let mut notice = load_error
            .as_ref()
            .map(|e| (format!("Config not loaded, saving disabled: {e}"), true));
        let bus = Bus::default();
        bus.set_ctx(Some(cc.egui_ctx.clone()));
        if let Some(p) = &instance
            && let Err(e) = p.listen(bus.clone())
        {
            notice = Some((format!("{e:#}"), true));
        }
        let mut app = Self {
            config,
            config_path,
            load_error,
            draft: None,
            group_draft: None,
            search: String::new(),
            sessions: Vec::new(),
            log_session: None,
            prompt: None,
            confirm_delete: None,
            confirm_second: None,
            confirm_forget_cert: None,
            settings_draft: None,
            confirm_quit: false,
            quit_save_error: None,
            allow_close: false,
            notice,
            prober: Prober::new(bus.clone()),
            actions: Vec::new(),
            _instance: instance,
            bus,
            inbox: Arc::default(),
            keyring: secrets::Queue::new(),
            keyring_done: Arc::default(),
            pending_lookups: Vec::new(),
            raise_for_prompt: None,
            errors: 0,
            config_version: std::cell::Cell::new(0),
            probed_version: None,
            quick: String::new(),
            adhoc: Vec::new(),
            known_certs: None,
            backup_open: false,
            restore: None,
            restore_inbox: Arc::default(),
            x11: None,
            active_session: None,
            session_area: None,
            session_scale: 1.0,
            ssh_program: "ssh".to_string(),
            integrations: false,
            tray: None,
            launcher_favourites: None,
            told_about_tray: false,
            exit: Exit::Quit,
        };
        match cc.storage.and_then(|s| eframe::get_value(s, SELECTION_KEY)) {
            Some(Selection::Connection(id)) => {
                app.draft = app.find(id).cloned().map(|c| Draft::new(c, false));
            }
            Some(Selection::Group(name)) if app.config.group_names().contains(&name) => {
                app.group_draft = Some(GroupDraft::new(&app.config, &name));
            }
            _ => {}
        }
        app
    }

    /// Hooks the app up to a newly opened window.
    pub fn attach(&mut self, cc: &eframe::CreationContext<'_>) {
        self.bus.set_ctx(Some(cc.egui_ctx.clone()));
        self.exit = Exit::Quit;
        self.allow_close = false;
        self.prober.set_paused(false);
        if let Some(window) = embed::x11_window(cc) {
            let holders: Vec<u32> = self.sessions.iter().filter_map(holder_of).collect();
            let attached = match &mut self.x11 {
                Some(host) => host.attach(window, holders.into_iter()),
                None => embed::Host::new(window).map(|host| self.x11 = Some(host)),
            };
            if let Err(e) = attached {
                self.error(e);
            }
        }
    }

    /// Moves sessions off the main window, which is about to close and would take them along.
    pub fn detach_sessions(&mut self) {
        let Some(host) = &self.x11 else { return };
        for s in &mut self.sessions {
            if let Surface::Rdp {
                holder: Some(holder),
                placed,
                visible,
            } = &mut s.surface
            {
                let _ = host.detach(*holder);
                *placed = None;
                *visible = false;
            }
        }
    }

    /// Whether a request is waiting on an answer that only the window can give.
    fn needs_window(&self) -> bool {
        self.prompt.is_some() || self.confirm_second.is_some()
    }

    /// Closes the window but keeps running in the tray. Questions still open are
    /// cancelled, or they would bring the window straight back.
    fn hide_to_tray(&mut self) {
        self.exit = Exit::Hide;
        self.prompt = None;
        self.confirm_second = None;
        self.confirm_quit = false;
        self.quit_save_error = None;
        self.restore = None;
    }

    /// Runs while the window is closed (in the tray), until it should open again or
    /// the app should quit.
    pub fn run_hidden(&mut self) -> Next {
        self.bus.set_ctx(None);
        match std::mem::replace(&mut self.exit, Exit::Quit) {
            Exit::Quit => return Next::Quit,
            Exit::Reopen(token) => return Next::Show(token),
            Exit::Hide => {}
        }
        // Nothing shows the status dots while the window is closed.
        self.prober.set_paused(true);
        let errors = self.errors;
        loop {
            self.bus.wait(Duration::from_millis(500));
            self.poll_sessions();
            self.sync_integrations();
            let mut show = None;
            for cmd in self.bus.take() {
                match cmd {
                    Command::Show { token } => show = Some(token),
                    Command::Connect { target, token } => {
                        self.raise_for_prompt = Some(token);
                        self.connect_target(&target);
                    }
                    Command::Quit => {
                        // Running sessions or unsaved edits: let the user decide.
                        if self.prepare_quit() {
                            self.confirm_quit = true;
                            return Next::Show(None);
                        }
                        return Next::Quit;
                    }
                }
            }
            if let Some(token) = show {
                return Next::Show(token);
            }
            self.poll_keyring();
            // A question for the user or a failed request needs the window.
            if self.needs_window() || self.errors != errors {
                return Next::Show(self.raise_for_prompt.take().flatten());
            }
            if self.pending_lookups.is_empty() {
                self.raise_for_prompt = None;
            }
        }
    }

    fn terminate_all(&mut self) {
        for s in &mut self.sessions {
            s.terminate();
        }
    }

    /// Starts or stops the tray icon to match the settings.
    fn sync_tray_setting(&mut self) {
        if !self.integrations {
            return;
        }
        match (self.config.settings.tray, self.tray.is_some()) {
            (true, false) => match Tray::spawn(self.bus.clone()) {
                Ok(t) => self.tray = Some(t),
                Err(e) => self.error(e),
            },
            (false, true) => self.tray = None,
            _ => {}
        }
    }

    fn tray_active(&self) -> bool {
        self.tray.as_ref().is_some_and(Tray::is_alive)
    }

    /// Favourites first, then the most recently used connections (excluding favourites).
    fn favourites_and_recent(&self) -> (Vec<&Connection>, Vec<&Connection>) {
        let mut favourites: Vec<&Connection> = self
            .config
            .connections
            .iter()
            .filter(|c| c.favorite)
            .collect();
        favourites.sort_by_key(|c| c.display_name().to_lowercase());
        let mut recent: Vec<&Connection> = self
            .config
            .connections
            .iter()
            .filter(|c| c.last_used.is_some() && !c.favorite)
            .collect();
        recent.sort_by_key(|c| std::cmp::Reverse(c.last_used));
        recent.truncate(RECENT_COUNT);
        (favourites, recent)
    }

    /// Keeps the tray menu and the launcher's favourite actions up to date.
    fn sync_integrations(&mut self) {
        if !self.integrations {
            return;
        }
        let (favourites, recent) = self.favourites_and_recent();
        let entry = |c: &&Connection| tray::Entry {
            id: c.id,
            name: c.display_name().to_string(),
            running: self
                .sessions
                .iter()
                .any(|s| s.connection_id == c.id && s.is_running()),
        };
        let menu = tray::Menu {
            favourites: favourites.iter().map(entry).collect(),
            recent: recent.iter().map(entry).collect(),
            running: self.sessions.iter().filter(|s| s.is_running()).count(),
        };
        let launcher: Vec<(Uuid, String)> = favourites
            .iter()
            .map(|c| (c.id, c.display_name().to_string()))
            .collect();
        if let Some(t) = &mut self.tray {
            t.set_menu(menu);
        }
        if self.launcher_favourites.as_ref() != Some(&launcher) {
            desktop::update_favourites(launcher.clone());
            self.launcher_favourites = Some(launcher);
        }
    }

    /// Handles commands from the tray and other launches while the window is open.
    fn handle_commands(&mut self, ctx: &egui::Context) {
        for cmd in self.bus.take() {
            match cmd {
                Command::Show { token } => self.bring_to_front(ctx, token),
                Command::Connect { target, token } => {
                    self.raise_for_prompt = Some(token);
                    self.connect_target(&target);
                }
                Command::Quit => self.actions.push(Action::AskQuit),
            }
        }
    }

    fn bring_to_front(&mut self, ctx: &egui::Context, token: Option<String>) {
        // Wayland doesn't let a window raise itself, but a new window may take focus
        // with an activation token, so close and reopen.
        // A window using X11 (even on a Wayland desktop) can just ask.
        if token.is_some() && self.x11.is_none() && std::env::var_os("WAYLAND_DISPLAY").is_some() {
            self.exit = Exit::Reopen(token);
            self.allow_close = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Informational,
        ));
    }

    fn selection(&self) -> Option<Selection> {
        match (&self.draft, &self.group_draft) {
            (Some(d), _) if !d.is_new => Some(Selection::Connection(d.conn.id)),
            (_, Some(g)) if !g.original.name.is_empty() => {
                Some(Selection::Group(g.original.name.clone()))
            }
            _ => None,
        }
    }

    /// Whether a window is open on top of the main area.
    fn modal_open(&self) -> bool {
        self.prompt.is_some()
            || self.confirm_delete.is_some()
            || self.confirm_second.is_some()
            || self.confirm_forget_cert.is_some()
            || self.known_certs.is_some()
            || self.backup_open
            || self.restore.is_some()
            || self.settings_draft.is_some()
            || self.confirm_quit
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        // Keys belong to the remote machine while a terminal has them.
        let in_terminal = ctx.memory(|m| m.focused()) == Some(Terminal::focus_id());
        ctx.options_mut(|o| o.zoom_with_keyboard = !in_terminal);
        if self.modal_open() || in_terminal {
            return;
        }
        let (new, save, find, quick, quit) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&SHORTCUT_NEW),
                i.consume_shortcut(&SHORTCUT_SAVE),
                i.consume_shortcut(&SHORTCUT_FIND),
                i.consume_shortcut(&SHORTCUT_QUICK),
                i.consume_shortcut(&SHORTCUT_QUIT),
            )
        });
        if quick {
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique(QUICK_ID)));
        }
        if quit {
            self.actions.push(Action::AskQuit);
        }
        if new {
            self.actions.push(Action::NewConnection);
        }
        let new_group = self
            .group_draft
            .as_ref()
            .is_some_and(|g| g.new_from.is_some());
        if save && (self.conn_dirty() || self.group_dirty() || new_group) {
            self.actions.push(Action::Save);
        }
        if find {
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique(SEARCH_ID)));
        }

        // Plain keys only apply when no text field is being typed into.
        if ctx.egui_wants_keyboard_input() {
            return;
        }
        let Some(d) = self.draft.as_ref().filter(|d| !d.is_new) else {
            return;
        };
        let id = d.conn.id;
        let (enter, delete) = ctx.input_mut(|i| {
            (
                i.consume_key(Modifiers::NONE, KeyCode::Enter),
                i.consume_key(Modifiers::NONE, KeyCode::Delete),
            )
        });
        if enter {
            self.actions.push(Action::Connect(id));
        }
        if delete {
            self.actions.push(Action::AskDelete(id));
        }
    }

    fn save_log(&self, index: usize, ctx: &egui::Context) {
        let Some(s) = self.sessions.get(index) else {
            return;
        };
        let report = s.report();
        let safe_name: String = s
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let file_name = format!(
            "xrdp-gui-{safe_name}-{}.log",
            s.started_at.format("%Y%m%d-%H%M%S")
        );
        let inbox = self.inbox.clone();
        let ctx = ctx.clone();
        // The file dialog blocks, so run it off the UI thread.
        std::thread::spawn(move || {
            let mut dialog = rfd::FileDialog::new()
                .set_title("Save session log")
                .set_file_name(file_name)
                .add_filter("Log file", &["log", "txt"]);
            if let Some(dir) = directories::UserDirs::new().and_then(|u| {
                u.download_dir()
                    .or(u.document_dir())
                    .map(|p| p.to_path_buf())
            }) {
                dialog = dialog.set_directory(dir);
            }
            let Some(path) = dialog.save_file() else {
                return;
            };
            let notice = match std::fs::write(&path, report) {
                Ok(()) => (format!("Saved log to {}", path.display()), false),
                Err(e) => (format!("Couldn't save {}: {e}", path.display()), true),
            };
            inbox.lock().unwrap().push(notice);
            ctx.request_repaint();
        });
    }

    /// Saves the current state to a file the user picks.
    fn save_backup(&mut self, ctx: &egui::Context) {
        self.backup_open = false;
        // Without its config the app holds nothing worth saving, and an empty backup
        // could later replace the real thing.
        if let Err(e) = self.ensure_writable() {
            return self.error(e);
        }
        if !self.commit() {
            return;
        }
        let backup = Backup::of(&self.config);
        let file_name = format!(
            "xrdp-gui-backup-{}.toml",
            chrono::Local::now().format("%Y%m%d")
        );
        let inbox = self.inbox.clone();
        let ctx = ctx.clone();
        // The file dialog blocks, so run it off the UI thread.
        std::thread::spawn(move || {
            let Some(path) = backup_dialog("Save backup")
                .set_file_name(file_name)
                .save_file()
            else {
                return;
            };
            let notice = match backup.write(&path) {
                Ok(()) => (format!("Saved backup to {}", path.display()), false),
                Err(e) => (format!("Couldn't save the backup: {e:#}"), true),
            };
            inbox.lock().unwrap().push(notice);
            ctx.request_repaint();
        });
    }

    /// Opens a file the user picks; its contents then show up through `restore_inbox`.
    fn pick_restore(&mut self, ctx: &egui::Context) {
        self.backup_open = false;
        let inbox = self.restore_inbox.clone();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let Some(path) = backup_dialog("Restore backup").pick_file() else {
                return;
            };
            let opened = Backup::read(&path)
                .map(|backup| PendingRestore {
                    backup,
                    file: path.display().to_string(),
                })
                .map_err(|e| format!("{e:#}"));
            *inbox.lock().unwrap() = Some(opened);
            ctx.request_repaint();
        });
    }

    /// Keeps what's here in a file next to the config before a restore replaces it.
    /// A config that failed to load is kept as it is on disk, for repairing by hand.
    fn keep_before_restore(&self) -> Result<PathBuf> {
        let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
        let dir = self
            .config_path
            .parent()
            .unwrap_or(std::path::Path::new("."));
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        let path = dir.join(format!("before-restore-{stamp}.toml"));
        if self.load_error.is_some() {
            std::fs::copy(&self.config_path, &path)
                .with_context(|| format!("keeping a copy of {}", self.config_path.display()))?;
        } else {
            Backup::of(&self.config).write(&path)?;
        }
        Ok(path)
    }

    fn restore_backup(&mut self, mode: RestoreMode) -> Result<()> {
        let Some(pending) = self.restore.take() else {
            return Ok(());
        };
        // A config that failed to load is replaced, or left alone; there's nothing to add
        // to. Its unsaved edits can't be saved anyway.
        let broken = self.load_error.is_some();
        if broken {
            if mode == RestoreMode::Add {
                self.ensure_writable()?;
            }
            self.draft = None;
            self.group_draft = None;
        } else if !self.commit() {
            return Ok(());
        }
        let kept = match mode {
            RestoreMode::Add => None,
            RestoreMode::Replace => Some(self.keep_before_restore()?),
        };

        let before = self.config.clone();
        let outcome = pending.backup.restore(&mut self.config, mode);
        let load_error = self.load_error.take();
        if let Err(e) = self.save_config() {
            self.config = before;
            self.load_error = load_error;
            return Err(e);
        }
        // Passwords go only once the connections are gone from disk.
        for key in outcome.stale_passwords {
            self.keyring(KeyringOp::Delete(key));
        }

        self.draft = match self.draft.as_ref().map(|d| d.conn.id) {
            Some(id) => self.find(id).cloned().map(|c| Draft::new(c, false)),
            None => None,
        };
        let group = self.group_draft.as_ref().map(|g| g.original.name.clone());
        self.group_draft = group
            .filter(|name| self.config.group_names().contains(name))
            .map(|name| GroupDraft::new(&self.config, &name));
        self.sync_tray_setting();

        let mut message = match mode {
            RestoreMode::Add => format!(
                "Added {} and {}",
                counted(outcome.added_connections, "connection"),
                counted(outcome.added_groups, "group"),
            ),
            RestoreMode::Replace => format!("Restored {}", pending.file),
        };
        if let Some(kept) = kept {
            message.push_str(&format!("; your previous setup is in {}", kept.display()));
        }
        self.info(message);
        Ok(())
    }

    // ---- state helpers -------------------------------------------------------------

    fn find(&self, id: Uuid) -> Option<&Connection> {
        self.config.find(id)
    }

    /// A saved connection or a quick connection from this run.
    fn find_any(&self, id: Uuid) -> Option<&Connection> {
        self.find(id)
            .or_else(|| self.adhoc.iter().find(|c| c.id == id))
    }

    fn conn_dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(|d| {
            d.is_new
                || !d.password.is_empty()
                || !d.gateway_password.is_empty()
                || self.find(d.conn.id) != Some(&d.conn)
        })
    }

    fn group_dirty(&self) -> bool {
        self.group_draft.as_ref().is_some_and(|g| {
            g.group != *g.new_from.as_ref().unwrap_or(&g.original)
                || !g.password.is_empty()
                || !g.gateway_password.is_empty()
        })
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), false));
    }

    fn error(&mut self, e: anyhow::Error) {
        self.notice = Some((format!("{e:#}"), true));
        self.errors += 1;
    }

    fn notify(&self, summary: String, body: String, urgent: bool) {
        if self.config.settings.notifications {
            notify::send(summary, body, urgent);
        }
    }

    /// Fails if the config can't be saved, so changes that also touch the keyring can
    /// check before they start.
    fn ensure_writable(&self) -> Result<()> {
        if let Some(e) = &self.load_error {
            bail!("not saving: config failed to load ({e})");
        }
        Ok(())
    }

    fn save_config(&self) -> Result<()> {
        // The in-memory config changed even if it can't be written.
        self.config_version.set(self.config_version.get() + 1);
        self.ensure_writable()?;
        self.config.save(&self.config_path)
    }

    fn save_draft(&mut self) -> Result<()> {
        self.ensure_writable()?;
        let Some(d) = self.draft.as_mut() else {
            return Ok(());
        };
        if d.conn.host.trim().is_empty() {
            bail!("host is required");
        }
        d.conn.group = d.conn.group.trim().to_string();
        let mut ops = Vec::new();
        if !d.password.is_empty() {
            ops.push(KeyringOp::Set(
                Key::Rdp(d.conn.id),
                std::mem::take(&mut d.password),
            ));
            d.conn.has_saved_password = true;
        }
        if !d.gateway_password.is_empty() {
            ops.push(KeyringOp::Set(
                Key::Gateway(d.conn.id),
                std::mem::take(&mut d.gateway_password),
            ));
            d.conn.has_saved_gateway_password = true;
        }
        match self
            .config
            .connections
            .iter_mut()
            .find(|c| c.id == d.conn.id)
        {
            Some(c) => *c = d.conn.clone(),
            None => self.config.connections.push(d.conn.clone()),
        }
        d.is_new = false;
        for op in ops {
            self.keyring(op);
        }
        self.save_config()
    }

    fn save_group(&mut self) -> Result<()> {
        self.ensure_writable()?;
        let Some(g) = self.group_draft.as_mut() else {
            return Ok(());
        };
        let new_name = g.group.name.trim().to_string();
        let old_name = g.original.name.clone();
        if new_name.is_empty() {
            bail!("group name is required");
        }
        if new_name != old_name && self.config.group_names().contains(&new_name) {
            bail!("a group named “{new_name}” already exists");
        }
        // Would share a keyring entry with the gateway password of the group without it.
        if new_name != old_name && new_name.ends_with(":gateway") {
            bail!("a group's name can't end in “:gateway”");
        }
        g.group.name = new_name.clone();

        // Keyring changes for the old name, made once the config is saved.
        let mut after_save = Vec::new();
        // A brand-new group has no old name; don't sweep ungrouped connections into it.
        if new_name != old_name && !old_name.is_empty() {
            // Saved passwords are keyed by group name; copy them along unless a new one
            // was typed.
            let moves = [
                (
                    g.original.has_saved_password,
                    g.password.is_empty(),
                    Key::GroupRdp(old_name.clone()),
                    Key::GroupRdp(new_name.clone()),
                ),
                (
                    g.original.has_saved_gateway_password,
                    g.gateway_password.is_empty(),
                    Key::GroupGateway(old_name.clone()),
                    Key::GroupGateway(new_name.clone()),
                ),
            ];
            for (saved, keep, old_key, new_key) in moves {
                after_save.push(match (saved, keep) {
                    (false, _) => continue,
                    (true, true) => KeyringOp::Move {
                        from: old_key,
                        to: new_key,
                    },
                    (true, false) => KeyringOp::Delete(old_key),
                });
            }
            for c in self
                .config
                .connections
                .iter_mut()
                .filter(|c| c.group.trim() == old_name)
            {
                c.group = new_name.clone();
            }
            if let Some(d) = self
                .draft
                .as_mut()
                .filter(|d| d.conn.group.trim() == old_name)
            {
                d.conn.group = new_name.clone();
            }
        }
        let mut ops = Vec::new();
        if !g.password.is_empty() {
            ops.push(KeyringOp::Set(
                Key::GroupRdp(new_name.clone()),
                std::mem::take(&mut g.password),
            ));
            g.group.has_saved_password = true;
        }
        if !g.gateway_password.is_empty() {
            ops.push(KeyringOp::Set(
                Key::GroupGateway(new_name.clone()),
                std::mem::take(&mut g.gateway_password),
            ));
            g.group.has_saved_gateway_password = true;
        }

        self.config
            .groups
            .retain(|x| x.name != old_name && x.name != new_name);
        self.config.groups.push(g.group.clone());
        self.config.groups.sort_by_key(|x| x.name.to_lowercase());
        g.original = g.group.clone();
        g.new_from = None;
        for op in ops {
            self.keyring(op);
        }
        self.save_config()?;
        for op in after_save {
            self.keyring(op);
        }
        Ok(())
    }

    /// Saves the connection or group being edited, if it has changes. A new connection
    /// that has no host yet can't be saved, so it is dropped rather than blocking whatever
    /// the user wants to do next.
    fn save_pending(&mut self) -> Result<()> {
        if let Some(d) = self
            .draft
            .as_ref()
            .filter(|d| d.is_new && d.conn.host.trim().is_empty())
        {
            let edited =
                d.conn != d.pristine || !d.password.is_empty() || !d.gateway_password.is_empty();
            self.draft = None;
            if edited {
                self.info("Discarded the new connection: it had no host");
            }
            return Ok(());
        }
        if self.conn_dirty() {
            self.save_draft()
        } else if self.group_dirty() {
            self.save_group()
        } else {
            Ok(())
        }
    }

    /// Saves pending edits before navigating away; returns false if that failed.
    fn commit(&mut self) -> bool {
        match self.save_pending() {
            Ok(()) => true,
            Err(e) => {
                self.error(e.context("unsaved changes"));
                false
            }
        }
    }

    /// Saves pending edits; returns whether quitting needs confirming because sessions
    /// are running or the edits couldn't be saved.
    fn prepare_quit(&mut self) -> bool {
        self.quit_save_error = self.save_pending().err().map(|e| format!("{e:#}"));
        self.quit_save_error.is_some() || self.sessions.iter().any(Session::is_running)
    }

    fn current_group(&self) -> String {
        match (&self.draft, &self.group_draft) {
            (Some(d), _) => d.conn.group.trim().to_string(),
            (_, Some(g)) => g.original.name.clone(),
            _ => String::new(),
        }
    }

    // ---- actions -------------------------------------------------------------------

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        // Going to a connection or group leaves any session for the form.
        if matches!(
            action,
            Action::NewConnection
                | Action::NewGroup
                | Action::Select(_)
                | Action::SelectGroup(_)
                | Action::Duplicate(_)
        ) {
            self.active_session = None;
        }
        match action {
            Action::ShowSession(uid) => self.active_session = uid,
            Action::NewConnection => {
                let group = self.current_group();
                if self.commit() {
                    let conn = Connection {
                        name: "New connection".into(),
                        group,
                        ..Default::default()
                    };
                    self.group_draft = None;
                    self.draft = Some(Draft::new(conn, true));
                }
            }
            Action::NewGroup => {
                if self.commit() {
                    let names = self.config.group_names();
                    let name = (1..)
                        .map(|n| {
                            if n == 1 {
                                "New group".to_string()
                            } else {
                                format!("New group {n}")
                            }
                        })
                        .find(|n| !names.contains(n))
                        .unwrap();
                    let mut g = GroupDraft::new(&self.config, &name);
                    // Unsaved until the user hits Save.
                    g.original.name = String::new();
                    g.new_from = Some(g.group.clone());
                    self.draft = None;
                    self.group_draft = Some(g);
                }
            }
            Action::Select(id) => {
                if self.draft.as_ref().is_some_and(|d| d.conn.id == id) || !self.commit() {
                    return;
                }
                self.group_draft = None;
                self.draft = self.find(id).cloned().map(|c| Draft::new(c, false));
            }
            Action::SelectGroup(name) => {
                if self
                    .group_draft
                    .as_ref()
                    .is_some_and(|g| g.original.name == name)
                    || !self.commit()
                {
                    return;
                }
                self.draft = None;
                self.group_draft = Some(GroupDraft::new(&self.config, &name));
            }
            Action::Save => {
                let result = if self.draft.is_some() {
                    self.save_draft()
                } else {
                    self.save_group()
                };
                match result {
                    Ok(()) => self.info("Saved"),
                    Err(e) => self.error(e),
                }
            }
            Action::Revert => {
                if let Some(d) = &self.draft {
                    self.draft = self.find(d.conn.id).cloned().map(|c| Draft::new(c, false));
                }
                if self
                    .group_draft
                    .as_ref()
                    .is_some_and(|g| g.new_from.is_some())
                {
                    self.group_draft = None;
                } else if let Some(g) = &mut self.group_draft {
                    g.group = g.original.clone();
                    g.password.clear();
                    g.gateway_password.clear();
                }
            }
            Action::Duplicate(id) => {
                if !self.commit() {
                    return;
                }
                if let Some(src) = self.find(id) {
                    let conn = Connection {
                        id: Uuid::new_v4(),
                        name: format!("{} (copy)", src.display_name()),
                        has_saved_password: false,
                        has_saved_gateway_password: false,
                        favorite: false,
                        last_used: None,
                        ..src.clone()
                    };
                    self.group_draft = None;
                    self.draft = Some(Draft::new(conn, true));
                }
            }
            Action::AskDelete(id) => self.confirm_delete = Some(id),
            Action::Delete(id) => {
                self.confirm_delete = None;
                if let Err(e) = self.ensure_writable() {
                    return self.error(e);
                }
                self.config.connections.retain(|c| c.id != id);
                if self.draft.as_ref().is_some_and(|d| d.conn.id == id) {
                    self.draft = None;
                }
                // Passwords go only once the connection is gone from disk.
                match self.save_config() {
                    Ok(()) => {
                        self.keyring(KeyringOp::Delete(Key::Rdp(id)));
                        self.keyring(KeyringOp::Delete(Key::Gateway(id)));
                    }
                    Err(e) => self.error(e),
                }
            }
            Action::ClearGroup => {
                let Some(name) = self.group_draft.as_ref().map(|g| g.original.name.clone()) else {
                    return;
                };
                if let Err(e) = self.ensure_writable() {
                    return self.error(e);
                }
                self.config.groups.retain(|x| x.name != name);
                self.group_draft = Some(GroupDraft::new(&self.config, &name));
                match self.save_config() {
                    Ok(()) => {
                        self.keyring(KeyringOp::Delete(Key::GroupGateway(name.clone())));
                        self.keyring(KeyringOp::Delete(Key::GroupRdp(name.clone())));
                        self.info(format!("Cleared the defaults of “{name}”"));
                    }
                    Err(e) => self.error(e),
                }
            }
            Action::Forget(key) => match self.forget(&key) {
                Ok(()) => self.info("Password removed from keyring"),
                Err(e) => self.error(e),
            },
            Action::ForgetPassword(id) => {
                let key = self
                    .find(id)
                    .map(|c| self.config.resolve(c))
                    .and_then(|r| r.password_key);
                if let Some(key) = key {
                    self.actions.push(Action::Forget(key));
                }
            }
            Action::ForgetCertificate(id, issue) => self.ask_forget_certificate(id, issue),
            Action::ToggleFavorite(id) => {
                let drafts = self
                    .draft
                    .as_mut()
                    .map(|d| &mut d.conn)
                    .filter(|c| c.id == id);
                for c in self
                    .config
                    .connections
                    .iter_mut()
                    .filter(|c| c.id == id)
                    .chain(drafts)
                {
                    c.favorite = !c.favorite;
                }
                if let Err(e) = self.save_config() {
                    self.error(e);
                }
            }
            Action::Connect(id) => self.connect(id),
            Action::ConnectAnyway(id) => {
                self.confirm_second = None;
                self.connect_anyway(id);
            }
            Action::QuickConnect => {
                let target = std::mem::take(&mut self.quick);
                self.connect_target(&target);
            }
            Action::Launch => self.launch_from_prompt(),
            Action::OpenCertificates => self.known_certs = Some(self.load_certs()),
            Action::AskForgetKnownCert {
                host,
                port,
                path,
                fingerprint,
            } => {
                self.confirm_forget_cert = Some(CertForget {
                    host,
                    port,
                    path,
                    old_fingerprint: Some(fingerprint).filter(|f| !f.is_empty()),
                    new_fingerprint: None,
                });
            }
            Action::ForgetCertConfirmed => {
                if let Some(forget) = self.confirm_forget_cert.take() {
                    match self.forget_cert(&forget) {
                        Ok(()) => self.info(format!(
                            "Forgot the certificate of {}:{}. The next connection will ask you \
                             to check the new one.",
                            forget.host, forget.port
                        )),
                        Err(e) => self.error(e),
                    }
                }
                if self.known_certs.is_some() {
                    self.known_certs = Some(self.load_certs());
                }
            }
            Action::AskQuit => {
                if self.prepare_quit() {
                    self.confirm_quit = true;
                    self.bring_to_front(ctx, None);
                } else {
                    self.actions.push(Action::Quit);
                }
            }
            Action::Stop(i) => {
                if let Some(s) = self.sessions.get_mut(i) {
                    s.terminate();
                }
            }
            Action::Dismiss(i) => {
                if i < self.sessions.len() {
                    self.sessions.remove(i);
                    self.log_session = match self.log_session {
                        Some(l) if l == i => None,
                        Some(l) if l > i => Some(l - 1),
                        other => other,
                    };
                }
            }
            Action::ClearEnded => {
                // The shown log stays open if its session is kept, at its new index:
                // the number of running sessions before it.
                self.log_session = self
                    .log_session
                    .filter(|&i| self.sessions.get(i).is_some_and(Session::is_running))
                    .map(|i| self.sessions[..i].iter().filter(|s| s.is_running()).count());
                self.sessions.retain(Session::is_running);
            }
            Action::SaveSettings => {
                if let Some(s) = self.settings_draft.take() {
                    self.config.settings = s;
                    if let Err(e) = self.save_config() {
                        self.error(e);
                    }
                    self.sync_tray_setting();
                }
            }
            Action::Backup => self.save_backup(ctx),
            Action::PickRestore => self.pick_restore(ctx),
            Action::Restore(mode) => {
                if let Err(e) = self.restore_backup(mode) {
                    self.error(e);
                }
            }
            Action::Quit => {
                self.terminate_all();
                self.exit = Exit::Quit;
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn forget(&mut self, key: &Key) -> Result<()> {
        self.ensure_writable()?;
        self.set_saved_flag(key, false);
        self.save_config()?;
        self.keyring(KeyringOp::Delete(key.clone()));
        Ok(())
    }

    /// Queues a keyring change; failures come back through [`App::poll_keyring`].
    fn keyring(&self, op: KeyringOp) {
        let (done, bus) = (self.keyring_done.clone(), self.bus.clone());
        self.keyring.run(move || {
            let failed = match op {
                KeyringOp::Set(key, password) => secrets::set(&key, &password).err().map(|e| {
                    // A password that was already saved stays usable if replacing it failed.
                    let lost = !matches!(secrets::get(&key), Ok(Some(_)));
                    (lost.then_some(key), e)
                }),
                KeyringOp::Delete(key) => secrets::delete(&key).err().map(|e| (None, e)),
                KeyringOp::Move { from, to } => {
                    let copied = secrets::get(&from).and_then(|pw| match pw {
                        Some(pw) => secrets::set(&to, &pw),
                        None => Ok(()),
                    });
                    match copied {
                        // Keep the old entry if the copy failed; nothing is lost.
                        Err(e) => Some((Some(to), e)),
                        Ok(()) => secrets::delete(&from).err().map(|e| (None, e)),
                    }
                }
            };
            if let Some((key, e)) = failed {
                done.lock().unwrap().push(KeyringDone::Failed(key, e));
                bus.wake();
            }
        });
    }

    /// Asks whether to forget the certificate FreeRDP refused. That names the host itself,
    /// which behind a gateway may not be the connection's own.
    fn ask_forget_certificate(&mut self, id: Uuid, issue: Option<CertIssue>) {
        let (host, port, new_fingerprint) = match issue {
            Some(i) => (i.host, i.port, i.new_fingerprint),
            None => match self.find_any(id) {
                Some(c) => (c.host.trim().to_string(), c.port, None),
                None => return self.error(anyhow::anyhow!("connection no longer exists")),
            },
        };
        let path = match certs::path_for(&host, port) {
            Ok(p) => p,
            Err(e) => return self.error(e),
        };
        if !path.exists() {
            return self.info(format!("No saved certificate found at {}", path.display()));
        }
        self.confirm_forget_cert = Some(CertForget {
            host,
            port,
            old_fingerprint: Some(certs::read(&path).fingerprint).filter(|f| !f.is_empty()),
            new_fingerprint,
            path,
        });
    }

    /// Removes FreeRDP's record of a certificate, and remembers that the next one needs
    /// checking: under trust on first use it would otherwise be accepted unseen. Checks
    /// first that this can be remembered.
    fn forget_cert(&mut self, forget: &CertForget) -> Result<()> {
        self.ensure_writable()?;
        certs::forget(&forget.path)?;
        let review = CertReview {
            host: certs::store_host(&forget.host),
            port: forget.port,
        };
        if !self.config.cert_review.contains(&review) {
            self.config.cert_review.push(review);
        }
        self.save_config()
    }

    /// Stops asking about servers whose new certificate FreeRDP has saved by now.
    fn prune_cert_reviews(&mut self) {
        let before = self.config.cert_review.len();
        self.config
            .cert_review
            .retain(|r| !certs::path_for(&r.host, r.port).is_ok_and(|p| p.exists()));
        if self.config.cert_review.len() != before
            && let Err(e) = self.save_config()
        {
            self.error(e);
        }
    }

    fn load_certs(&mut self) -> Vec<KnownCert> {
        certs::list().unwrap_or_else(|e| {
            self.error(e);
            Vec::new()
        })
    }

    /// Connects to a saved connection given by id, name or host; anything else is
    /// treated as a quick connection to that host.
    fn connect_target(&mut self, target: &str) {
        let t = target.trim();
        let found = self
            .config
            .connections
            .iter()
            .find(|c| c.id.to_string() == t)
            .or_else(|| {
                let lower = t.to_lowercase();
                let by = |f: fn(&Connection) -> &str| {
                    self.config
                        .connections
                        .iter()
                        .find(|c| f(c).trim().to_lowercase() == lower)
                };
                by(|c| c.display_name()).or_else(|| by(|c| &c.host))
            })
            .map(|c| c.id);
        match found {
            Some(id) => self.connect(id),
            None => self.quick_connect(t),
        }
    }

    /// Connects to `[DOMAIN\]user@host[:port]` without saving a connection.
    fn quick_connect(&mut self, target: &str) {
        let Some(conn) = parse_quick(target) else {
            self.error(anyhow::anyhow!("enter a host name to connect to"));
            return;
        };
        // Reuse an earlier quick connection to the same place so reconnecting matches.
        let id = match self.adhoc.iter().find(|c| {
            (
                c.host.as_str(),
                c.port,
                c.username.as_str(),
                c.domain.as_str(),
            ) == (
                conn.host.as_str(),
                conn.port,
                conn.username.as_str(),
                conn.domain.as_str(),
            )
        }) {
            Some(c) => c.id,
            None => {
                let id = conn.id;
                self.adhoc.push(conn);
                id
            }
        };
        self.connect(id);
    }

    /// Connects, first asking if the connection already has a session: a second sign-in
    /// usually disconnects the first.
    fn connect(&mut self, id: Uuid) {
        let ssh = self
            .find_any(id)
            .is_some_and(|c| c.protocol == Protocol::Ssh);
        // Unlike RDP, any number of SSH sessions get along.
        if !ssh
            && self
                .sessions
                .iter()
                .any(|s| s.connection_id == id && s.is_running())
        {
            self.confirm_second = Some(id);
        } else {
            self.connect_anyway(id);
        }
    }

    fn connect_anyway(&mut self, id: Uuid) {
        // Clicking again while the keyring is being read isn't another connection.
        if self.pending_lookups.contains(&id) {
            return;
        }
        self.prune_cert_reviews();
        if self.draft.as_ref().is_some_and(|d| d.conn.id == id) && !self.commit() {
            return;
        }
        let Some(conn) = self.find_any(id).cloned() else {
            return;
        };
        if conn.protocol == Protocol::Ssh {
            return self.launch(&conn, None, None);
        }
        let resolved = self.config.resolve(&conn);
        let password_key = resolved.password_key;
        let gateway_key = resolved
            .gateway
            .filter(|gw| !gw.same_credentials)
            .and_then(|gw| gw.saved_password);
        if password_key.is_none() && gateway_key.is_none() {
            return self.got_passwords(conn, Ok(None), Ok(None));
        }
        let (done, bus) = (self.keyring_done.clone(), self.bus.clone());
        self.pending_lookups.push(id);
        self.keyring.run(move || {
            let get = |key: Option<Key>| key.map_or(Ok(None), |k| secrets::get(&k));
            let lookup = Lookup {
                password: get(password_key),
                gateway_password: get(gateway_key),
                conn,
            };
            done.lock()
                .unwrap()
                .push(KeyringDone::Looked(Box::new(lookup)));
            bus.wake();
        });
    }

    /// Handles finished keyring work: continues connections whose passwords were looked
    /// up, and reports failed changes.
    fn poll_keyring(&mut self) {
        let done = std::mem::take(&mut *self.keyring_done.lock().unwrap());
        for d in done {
            match d {
                KeyringDone::Looked(l) => {
                    self.pending_lookups.retain(|id| *id != l.conn.id);
                    self.got_passwords(l.conn, l.password, l.gateway_password);
                }
                KeyringDone::Failed(key, e) => {
                    if let Some(key) = key {
                        self.set_saved_flag(&key, false);
                        if let Err(e) = self.save_config() {
                            self.error(e);
                        }
                    }
                    self.error(e);
                }
            }
        }
    }

    fn keyring_result(&mut self, result: Result<Option<String>>) -> Option<String> {
        result.unwrap_or_else(|e| {
            self.error(e);
            None
        })
    }

    /// Launches `conn` with the passwords from the keyring, or asks for missing ones.
    fn got_passwords(
        &mut self,
        conn: Connection,
        password: Result<Option<String>>,
        gateway_password: Result<Option<String>>,
    ) {
        let password = self.keyring_result(password);
        let gateway_password = self.keyring_result(gateway_password);
        let saved_conn = self.find(conn.id).is_some();
        let resolved = self.config.resolve(&conn);
        let user_at = |domain: &str, user: &str| match (domain, user) {
            (_, "") => String::new(),
            ("", u) => format!("{u}@"),
            (d, u) => format!("{d}\\{u}@"),
        };
        // A gateway with its own credentials needs its own password.
        let gateway = resolved
            .gateway
            .as_ref()
            .filter(|gw| !gw.same_credentials && !gw.host.is_empty())
            .filter(|_| gateway_password.is_none())
            .map(|gw| GatewayPrompt {
                target: format!("{}{}", user_at(&gw.domain, &gw.username), gw.host),
                password: String::new(),
                save_to: match &gw.from_group {
                    Some(g) => Some((
                        Key::GroupGateway(g.clone()),
                        format!("Save in keyring for group “{g}”"),
                    )),
                    None if saved_conn => {
                        Some((Key::Gateway(conn.id), "Save in keyring".to_string()))
                    }
                    None => None,
                },
                remember: false,
            });
        if password.is_some() && gateway.is_none() {
            return self.launch(&conn, password, gateway_password);
        }
        let save_to = match &resolved.creds_from_group {
            Some(g) => Some((
                Key::GroupRdp(g.clone()),
                format!("Save in keyring for group “{g}”"),
            )),
            None if saved_conn => Some((Key::Rdp(conn.id), "Save in keyring".to_string())),
            None => None,
        };
        self.prompt = Some(PasswordPrompt {
            target: format!(
                "{}{}",
                user_at(&resolved.domain, &resolved.username),
                conn.host.trim()
            ),
            conn,
            saved_password: password,
            password: String::new(),
            save_to,
            remember: false,
            gateway,
            saved_gateway_password: gateway_password,
            focused: false,
        });
    }

    fn launch_from_prompt(&mut self) {
        let Some(p) = self.prompt.take() else { return };
        let typed = |pw: String| Some(pw).filter(|p| !p.is_empty());
        if p.remember
            && let Some((key, _)) = &p.save_to
            && !p.password.is_empty()
        {
            self.remember(key, &p.password);
        }
        let mut gateway_password = p.saved_gateway_password;
        if let Some(g) = p.gateway {
            if g.remember
                && let Some((key, _)) = &g.save_to
                && !g.password.is_empty()
            {
                self.remember(key, &g.password);
            }
            gateway_password = typed(g.password);
        }
        // An empty password lets FreeRDP prompt (or use Kerberos/smartcard) itself.
        let password = p.saved_password.or_else(|| typed(p.password));
        let conn = self.find_any(p.conn.id).cloned().unwrap_or(p.conn);
        self.launch(&conn, password, gateway_password);
    }

    /// Saves a password typed into the prompt in the keyring.
    fn remember(&mut self, key: &Key, password: &str) {
        if let Err(e) = self.ensure_writable() {
            return self.error(e);
        }
        self.keyring(KeyringOp::Set(key.clone(), password.to_string()));
        self.set_saved_flag(key, true);
        if let Err(e) = self.save_config() {
            self.error(e);
        }
    }

    /// Records whether a password is in the keyring under `key`, in the config and in
    /// whatever is being edited.
    fn set_saved_flag(&mut self, key: &Key, saved: bool) {
        match key {
            Key::Rdp(id) | Key::Gateway(id) => {
                let rdp = matches!(key, Key::Rdp(_));
                let drafts = self
                    .draft
                    .as_mut()
                    .map(|d| &mut d.conn)
                    .filter(|c| c.id == *id);
                for c in self
                    .config
                    .connections
                    .iter_mut()
                    .filter(|c| c.id == *id)
                    .chain(drafts)
                {
                    if rdp {
                        c.has_saved_password = saved;
                    } else {
                        c.has_saved_gateway_password = saved;
                    }
                }
            }
            Key::GroupRdp(name) | Key::GroupGateway(name) => {
                let rdp = matches!(key, Key::GroupRdp(_));
                let set = |g: &mut Group| {
                    if rdp {
                        g.has_saved_password = saved;
                    } else {
                        g.has_saved_gateway_password = saved;
                    }
                };
                for g in self.config.groups.iter_mut().filter(|g| g.name == *name) {
                    set(g);
                }
                if let Some(g) = self
                    .group_draft
                    .as_mut()
                    .filter(|g| g.original.name == *name)
                {
                    set(&mut g.group);
                    set(&mut g.original);
                }
            }
        }
    }

    fn launch(
        &mut self,
        conn: &Connection,
        password: Option<String>,
        gateway_password: Option<String>,
    ) {
        let resolved = self.config.resolve(conn);
        let creds = Credentials {
            password: password.as_deref(),
            gateway_password: gateway_password.as_deref(),
        };
        let settings = &self.config.settings;
        let name = conn.display_name().to_string();
        // Why an RDP session that should open in the main window can't.
        let mut own_window_because = None;
        let result = if conn.protocol == Protocol::Ssh {
            command::ssh_args(&resolved).and_then(|args| {
                let shown = command::preview("ssh", &args);
                if conn.new_window {
                    let argv = command::terminal_command(settings, &args)?;
                    Session::spawn_terminal(&argv, shown, conn.id, name, &self.bus)
                } else {
                    Session::spawn_in_main_window(
                        &self.ssh_program,
                        &args,
                        shown,
                        conn.id,
                        name,
                        &self.bus,
                    )
                }
            })
        } else {
            match self.main_window_client(conn, &resolved, password.is_some()) {
                Ok(client) => self.spawn_rdp_in_main_window(conn, &client, &creds),
                Err(reason) => {
                    own_window_because = reason;
                    command::build_args(&resolved, settings, &creds).and_then(|args| {
                        Session::spawn(&settings.client, &args, conn.id, name, &self.bus)
                    })
                }
            }
        };
        match result {
            Ok(session) => {
                if session.surface.in_main_window() {
                    self.active_session = Some(session.uid);
                }
                self.sessions.push(session);
                self.info(match own_window_because.filter(|_| self.integrations) {
                    Some(reason) => format!(
                        "Connecting to {} in a new window: {reason}",
                        conn.display_name()
                    ),
                    None => format!("Connecting to {}…", conn.display_name()),
                });
                self.touch(conn.id);
            }
            Err(e) => self.error(e),
        }
    }

    /// The client to show an RDP session in the main window with. Otherwise it gets its own
    /// window, and the reason says why, if the connection didn't ask for that.
    fn main_window_client(
        &self,
        conn: &Connection,
        resolved: &Resolved,
        has_password: bool,
    ) -> Result<String, Option<&'static str>> {
        if conn.new_window {
            return Err(None);
        }
        if self.x11.is_none() {
            return Err(Some("the main window isn't using X11"));
        }
        // `xfreerdp` can only ask questions on a terminal, and sessions don't have one.
        if resolved.cert == CertPolicy::Ask {
            return Err(Some(
                "its certificate needs checking, which FreeRDP asks about there",
            ));
        }
        if !has_password {
            return Err(Some("no password is set, so FreeRDP asks for it there"));
        }
        command::embeddable_client(&self.config.settings).ok_or(Some("xfreerdp isn't installed"))
    }

    fn spawn_rdp_in_main_window(
        &self,
        conn: &Connection,
        client: &str,
        creds: &Credentials,
    ) -> Result<Session> {
        let host = self
            .x11
            .as_ref()
            .context("the main window isn't using X11")?;
        let area = self.session_area.unwrap_or(Area {
            x: 0,
            y: 0,
            width: 1024,
            height: 768,
        });
        // On a scaled screen, asking the server for every physical pixel of the main area
        // can mean 4-5 times the work, for `xfreerdp` to draw in software: far too slow.
        // So ask for the size in points, and let the X server stretch that to fit.
        let scale = self.session_scale.max(1.0);
        let scaled = scale > 1.01;
        let fitted = Connection {
            fullscreen: false,
            multimon: false,
            dynamic_resolution: !scaled,
            width: ((area.width as f32 / scale).round() as u32).max(200),
            height: ((area.height as f32 / scale).round() as u32).max(200),
            ..conn.clone()
        };
        let resolved = self.config.resolve(&fitted);
        let mut args = command::build_args(&resolved, &self.config.settings, creds)?;
        if scaled {
            args.push("/smart-sizing".to_string());
        }
        let holder = host.create_holder(area)?;
        args.extend([
            format!("/parent-window:{holder}"),
            // Grabbing would keep the keyboard and pointer from the rest of the desktop.
            "-grab-keyboard".to_string(),
            "-grab-mouse".to_string(),
        ]);
        let spawned = Session::spawn_in_holder(
            client,
            &args,
            conn.id,
            conn.display_name().to_string(),
            &self.bus,
        );
        match spawned {
            Ok(mut session) => {
                session.surface = Surface::Rdp {
                    holder: Some(holder),
                    placed: None,
                    visible: false,
                };
                Ok(session)
            }
            Err(e) => {
                host.destroy(holder);
                Err(e)
            }
        }
    }

    /// Keeps session windows over the main area while they should show, and out of the way
    /// of anything drawn on top. They're separate X11 windows, so they cover egui's drawing.
    fn sync_session_windows(&mut self, ctx: &egui::Context) {
        if let Some(uid) = self.active_session
            && !self.sessions.iter().any(|s| s.uid == uid)
        {
            self.active_session = None;
        }
        let modal = self.modal_open();
        let (active, area) = (self.active_session, self.session_area);
        let Some(host) = &mut self.x11 else { return };
        let mut shown = None;
        let mut failure = None;
        let mut connecting = false;
        for s in &mut self.sessions {
            let running = s.is_running();
            let is_active = active == Some(s.uid);
            let Surface::Rdp {
                holder,
                placed,
                visible,
            } = &mut s.surface
            else {
                continue;
            };
            let Some(id) = *holder else { continue };
            if !running {
                host.destroy(id);
                *holder = None;
                continue;
            }
            // Asking the X server takes a round trip, so only until the session has shown.
            let wanted = area.filter(|_| is_active && !modal && (*visible || host.has_client(id)));
            if is_active && !modal && wanted.is_none() {
                connecting = true;
            }
            let mut sync = || -> Result<()> {
                if let Some(area) = wanted {
                    if *placed != Some(area) {
                        host.place(id, area)?;
                        *placed = Some(area);
                    }
                    shown = Some((id, area));
                }
                if wanted.is_some() != *visible {
                    host.set_visible(id, wanted.is_some())?;
                    *visible = wanted.is_some();
                }
                Ok(())
            };
            if let Err(e) = sync() {
                failure = Some(e);
            }
        }
        host.set_shown(shown);
        if connecting {
            // Nothing else says when the session's window has appeared.
            ctx.request_repaint_after(Duration::from_millis(200));
        }
        if let Some(e) = failure {
            self.error(e);
        }
    }

    /// The tabs above the main area, when any session is showing there.
    fn session_tabs(&mut self, ui: &mut egui::Ui) {
        let tabs: Vec<(usize, u64, String, bool)> = self
            .sessions
            .iter()
            .enumerate()
            .filter(|(_, s)| s.surface.in_main_window())
            .map(|(i, s)| (i, s.uid, s.name.clone(), s.is_running()))
            .collect();
        if tabs.is_empty() {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .selectable_label(self.active_session.is_none(), "Connection")
                .clicked()
            {
                self.actions.push(Action::ShowSession(None));
            }
            for (index, uid, name, running) in tabs {
                ui.separator();
                let text = if running {
                    name.clone()
                } else {
                    format!("{name} (ended)")
                };
                if ui
                    .selectable_label(self.active_session == Some(uid), text)
                    .clicked()
                {
                    self.actions.push(Action::ShowSession(Some(uid)));
                }
                let close = ui
                    .small_button("✕")
                    .on_hover_text(if running { "Disconnect" } else { "Close" })
                    .accessible_name(format!("Close {name}"))
                    .clicked();
                if close {
                    self.actions.push(if running {
                        Action::Stop(index)
                    } else {
                        Action::Dismiss(index)
                    });
                }
            }
        });
        ui.separator();
    }

    /// The main area: a session if one is chosen, otherwise the connection form.
    fn main_area(&mut self, ui: &mut egui::Ui) {
        self.session_tabs(ui);
        // Kept up to date even with no session showing, so a new one starts at the right size.
        let rect = ui.available_rect_before_wrap();
        let ppp = ui.ctx().pixels_per_point();
        self.session_scale = ppp;
        self.session_area = Some(Area {
            x: (rect.left() * ppp).round() as i32,
            y: (rect.top() * ppp).round() as i32,
            width: (rect.width() * ppp).round().max(1.0) as u32,
            height: (rect.height() * ppp).round().max(1.0) as u32,
        });
        let interactive = !self.modal_open();
        let active = self.active_session;
        let Some(session) = self.sessions.iter_mut().find(|s| Some(s.uid) == active) else {
            return self.editor(ui);
        };
        let ended = match &session.status {
            Status::Exited(d) => Some((d.title.clone(), d.hint.clone())),
            Status::Running => None,
        };
        let (id, name) = (session.connection_id, session.name.clone());
        let mut again = false;
        let mut ended_bar = |ui: &mut egui::Ui| {
            if let Some((title, hint)) = &ended {
                ui.horizontal_wrapped(|ui| {
                    ui.strong(title);
                    if !hint.is_empty() {
                        ui.weak(hint);
                    }
                    again = ui.button("▶ Connect again").clicked();
                });
                ui.add_space(4.0);
            }
        };
        match &mut session.surface {
            Surface::Terminal(terminal) => {
                ended_bar(ui);
                terminal.show(ui, interactive);
            }
            Surface::Rdp { .. } => {
                ended_bar(ui);
                // Shows until the session's own window covers it.
                if ended.is_none() {
                    ui.centered_and_justified(|ui| {
                        ui.weak(format!("Connecting to {name}…"));
                    });
                }
            }
            Surface::OwnWindow => {}
        }
        if again {
            self.actions.push(Action::Connect(id));
        }
    }

    /// Marks a saved connection as just used.
    fn touch(&mut self, id: Uuid) {
        let now = chrono::Local::now().timestamp();
        let drafts = self
            .draft
            .as_mut()
            .map(|d| &mut d.conn)
            .filter(|c| c.id == id);
        let mut found = false;
        for c in self
            .config
            .connections
            .iter_mut()
            .filter(|c| c.id == id)
            .chain(drafts)
        {
            c.last_used = Some(now);
            found = true;
        }
        if found && let Err(e) = self.save_config() {
            self.error(e);
        }
    }

    fn poll_sessions(&mut self) {
        let mut notes = Vec::new();
        let mut notice = None;
        for s in &mut self.sessions {
            if s.poll()
                && let Status::Exited(d) = &s.status
            {
                match d.severity {
                    Severity::Normal => notice = Some((format!("{}: {}", s.name, d.title), false)),
                    Severity::Dropped | Severity::Failed => {
                        notice = Some((format!("{}: {}", s.name, d.title), true));
                        let summary = match d.severity {
                            Severity::Dropped => format!("{} disconnected", s.name),
                            _ => format!("Couldn't connect to {}", s.name),
                        };
                        notes.push((
                            summary,
                            format!("{}\n{}", d.title, d.hint),
                            d.severity == Severity::Dropped,
                        ));
                    }
                }
                continue;
            }
            match s.reconnecting() {
                Some((n, m)) if !s.reconnect_notified => {
                    s.reconnect_notified = true;
                    let of = if m == 0 {
                        String::new()
                    } else {
                        format!(" of {m}")
                    };
                    notes.push((
                        format!("Connection to {} lost", s.name),
                        format!("Reconnecting automatically (attempt {n}{of})…"),
                        false,
                    ));
                }
                None if s.reconnect_notified && s.is_running() => {
                    s.reconnect_notified = false;
                    notes.push((
                        format!("Reconnected to {}", s.name),
                        "The session is back.".into(),
                        false,
                    ));
                }
                _ => {}
            }
        }
        if notice.is_some() {
            self.notice = notice;
        }
        for (summary, body, urgent) in notes {
            self.notify(summary, body, urgent);
        }
    }

    fn update_probe_targets(&mut self) {
        let version = self.config_version.get();
        if self.probed_version == Some(version) {
            return;
        }
        self.probed_version = Some(version);
        let targets = if self.config.settings.probe_hosts {
            self.config
                .connections
                .iter()
                .filter(|c| !c.host.trim().is_empty())
                .map(|c| {
                    // Behind a gateway the host itself is usually not reachable; check the gateway.
                    let (host, port) = match self.config.gateway(c) {
                        Some(gw) if !gw.host.is_empty() => model::split_host_port(&gw.host, 443),
                        _ => (c.host.trim().trim_matches(['[', ']']).to_string(), c.port),
                    };
                    Target {
                        id: c.id,
                        host,
                        port,
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        self.prober.set_targets(targets);
    }

    // ---- UI ------------------------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("xrdp-gui");
            ui.separator();
            if ui.button("➕ Connection").on_hover_text("Ctrl+N").clicked() {
                self.actions.push(Action::NewConnection);
            }
            if ui
                .button("➕ Group")
                .on_hover_text("Shared defaults for a set of connections")
                .clicked()
            {
                self.actions.push(Action::NewGroup);
            }
            ui.separator();
            let quick = ui
                .add(
                    egui::TextEdit::singleline(&mut self.quick)
                        .id(egui::Id::unique(QUICK_ID))
                        .hint_text("Quick connect: [user@]host[:port]")
                        .desired_width(230.0),
                )
                .accessible_name("Quick connect")
                .on_hover_text(
                    "Connect without saving a connection (Ctrl+L). \
                     Also accepts the name of a saved connection.",
                );
            if quick.lost_focus()
                && ui.input(|i| i.key_pressed(egui::Key::Enter))
                && !self.quick.trim().is_empty()
            {
                self.actions.push(Action::QuickConnect);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⚙ Settings").clicked() {
                    self.settings_draft = Some(self.config.settings.clone());
                }
                if ui
                    .button("💾 Backup")
                    .on_hover_text("Save your connections to a file, or restore them from one")
                    .clicked()
                {
                    self.backup_open = true;
                }
                if ui
                    .button("🔒 Certificates")
                    .on_hover_text("Server certificates FreeRDP trusts")
                    .clicked()
                {
                    self.actions.push(Action::OpenCertificates);
                }
                if let Some((msg, is_err)) = &self.notice {
                    let color = if *is_err {
                        ui.visuals().error_fg_color
                    } else {
                        ui.visuals().weak_text_color()
                    };
                    if ui.small_button("✕").clicked() {
                        self.notice = None;
                    } else {
                        ui.add(egui::Label::new(RichText::new(msg).color(color)).truncate());
                    }
                }
            });
        });
    }

    fn connection_list(&mut self, ui: &mut egui::Ui) {
        ui.add(
            egui::TextEdit::singleline(&mut self.search)
                .id(egui::Id::unique(SEARCH_ID))
                .hint_text("🔍 Search (Ctrl+F), #tag")
                .desired_width(f32::INFINITY),
        )
        .accessible_name("Search connections");
        ui.add_space(4.0);

        let query = self.search.trim().to_lowercase();
        let searching = !query.is_empty();
        let mut groups: BTreeMap<String, Vec<Uuid>> = BTreeMap::new();
        if !searching {
            // Show groups that only have defaults so they can be edited.
            for g in &self.config.groups {
                groups.entry(g.name.clone()).or_default();
            }
        }
        let mut sorted: Vec<&Connection> = self.config.connections.iter().collect();
        sorted.sort_by_key(|c| c.display_name().to_lowercase());
        for c in sorted.into_iter().filter(|c| c.matches(&query)) {
            groups
                .entry(c.group.trim().to_string())
                .or_default()
                .push(c.id);
        }
        let ids = |list: Vec<&Connection>| list.iter().map(|c| c.id).collect::<Vec<_>>();
        let (favourites, recent) = self.favourites_and_recent();
        let (favourites, recent) = (ids(favourites), ids(recent));

        let selected = self.draft.as_ref().map(|d| d.conn.id);
        let selected_group = self.group_draft.as_ref().map(|g| g.original.name.clone());
        let accordion = self.config.settings.accordion && !searching;
        let config = &self.config;
        let sessions = &self.sessions;
        let prober = &self.prober;
        let actions = &mut self.actions;
        let rows = |ui: &mut egui::Ui, list: &[Uuid], actions: &mut Vec<Action>| {
            for c in list.iter().filter_map(|id| config.find(*id)) {
                connection_row(
                    ui,
                    c,
                    selected == Some(c.id),
                    config,
                    sessions,
                    prober,
                    actions,
                );
            }
        };

        egui::ScrollArea::vertical().show(ui, |ui| {
            if config.connections.is_empty() {
                ui.weak("No connections yet.");
            }
            if !searching {
                for (key, title, list) in [
                    ("favourites", "★ Favourites", &favourites),
                    ("recent", "🕘 Recent", &recent),
                ] {
                    if list.is_empty() {
                        continue;
                    }
                    let id = ui.make_persistent_id(("sidebar", key));
                    egui::collapsing_header::CollapsingState::load_with_default_open(
                        ui.ctx(),
                        id,
                        true,
                    )
                    .show_header(ui, |ui| ui.label(RichText::new(title).small().strong()))
                    .body(|ui| rows(ui, list, actions));
                }
            }

            let show_headers = groups.len() > 1 || groups.keys().any(|g| !g.is_empty());
            if !show_headers {
                if let Some(list) = groups.values().next() {
                    rows(ui, list, actions);
                }
                return;
            }
            let mut header_ids = Vec::new();
            let mut opened = None;
            for (group, list) in &groups {
                ui.add_space(2.0);
                // Searching shows every match without touching the saved open/closed state.
                let salt = if searching {
                    "sidebar_search"
                } else {
                    "sidebar_group"
                };
                let id = ui.make_persistent_id((salt, group));
                header_ids.push(id);
                let mut state = egui::collapsing_header::CollapsingState::load_with_default_open(
                    ui.ctx(),
                    id,
                    true,
                );
                if searching {
                    state.set_open(true);
                }
                let was_open = state.is_open();
                let (mut toggle, mut edit) = (false, false);
                let name = if group.is_empty() {
                    "Ungrouped"
                } else {
                    group.as_str()
                };
                let mut header = state.show_header(ui, |ui| {
                    let label = RichText::new(format!("{name} ({})", list.len())).strong();
                    let is_selected = selected_group.as_deref() == Some(group.as_str());
                    toggle = ui
                        .add(egui::Button::selectable(is_selected, label).frame(false))
                        .on_hover_text("Click to expand or collapse")
                        .clicked();
                    if !group.is_empty() {
                        edit = ui
                            .small_button("⚙")
                            .on_hover_text("Edit this group's shared defaults and credentials")
                            .accessible_name(format!("Edit group {group}"))
                            .clicked();
                    }
                });
                if toggle {
                    header.toggle();
                }
                if !was_open && header.is_open() {
                    opened = Some(id);
                }
                if edit {
                    actions.push(Action::SelectGroup(group.clone()));
                }
                header.body(|ui| {
                    if list.is_empty() {
                        ui.weak("(empty)");
                    }
                    rows(ui, list, actions);
                });
            }
            // Accordion: opening one group closes the others.
            if accordion && let Some(open) = opened {
                for id in header_ids.into_iter().filter(|id| *id != open) {
                    let mut state =
                        egui::collapsing_header::CollapsingState::load_with_default_open(
                            ui.ctx(),
                            id,
                            true,
                        );
                    state.set_open(false);
                    state.store(ui.ctx());
                }
            }
        });
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        if self.group_draft.is_some() {
            return self.group_editor(ui);
        }
        let dirty = self.conn_dirty();
        let settings = self.config.settings.clone();
        let group_names = self.config.group_names();
        let Some(d) = self.draft.as_mut() else {
            ui.centered_and_justified(|ui| {
                ui.weak(
                    "Select a connection, or create one with ➕ Connection.\n\
                     Double-click a connection to connect. Click ⚙ next to a group to edit its defaults.",
                );
            });
            return;
        };
        let config = &self.config;
        let actions = &mut self.actions;
        let id = d.conn.id;
        let group = config.group(&d.conn.group).cloned();
        let group_label = || match &group {
            Some(g) => format!("from group “{}”", g.name),
            None => "default".to_string(),
        };

        ui.horizontal(|ui| {
            if !d.is_new {
                let (star, hover) = if d.conn.favorite {
                    ("★", "Remove from favourites")
                } else {
                    (
                        "☆",
                        "Add to favourites (shown at the top, in the tray and launcher)",
                    )
                };
                if ui
                    .add(
                        egui::Button::new(RichText::new(star).color(AMBER).size(18.0)).frame(false),
                    )
                    .on_hover_text(hover)
                    .accessible_name("Favourite")
                    .clicked()
                {
                    actions.push(Action::ToggleFavorite(id));
                }
            }
            ui.heading(d.conn.display_name().to_owned());
            if dirty {
                ui.weak("(unsaved)");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let connect = egui::Button::new(RichText::new("▶ Connect").strong());
                if ui
                    .add_enabled(!d.conn.host.trim().is_empty(), connect)
                    .on_hover_text("Enter")
                    .clicked()
                {
                    actions.push(Action::Connect(id));
                }
                if ui
                    .add_enabled(dirty, egui::Button::new("💾 Save"))
                    .on_hover_text("Ctrl+S")
                    .on_disabled_hover_text("No unsaved changes (Ctrl+S)")
                    .clicked()
                {
                    actions.push(Action::Save);
                }
                let revert = if d.is_new {
                    "✕ Discard"
                } else {
                    "↺ Revert"
                };
                if ui.add_enabled(dirty, egui::Button::new(revert)).clicked() {
                    actions.push(Action::Revert);
                }
                if ui
                    .add_enabled(!d.is_new, egui::Button::new("Duplicate"))
                    .clicked()
                {
                    actions.push(Action::Duplicate(id));
                }
                if ui
                    .add_enabled(!d.is_new, egui::Button::new("🗑 Delete"))
                    .on_hover_text("Delete")
                    .clicked()
                {
                    actions.push(Action::AskDelete(id));
                }
            });
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                let c = &mut d.conn;

                section(ui, "General", true, |ui| {
                    row(ui, "Name", |ui| ui.text_edit_singleline(&mut c.name));
                    row(ui, "Group", |ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut c.group).hint_text("none"))
                                .accessible_name("Group");
                            egui::ComboBox::from_id_salt("group_pick")
                                .selected_text("")
                                .width(20.0)
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut c.group, String::new(), "(none)");
                                    for g in &group_names {
                                        ui.selectable_value(&mut c.group, g.clone(), g);
                                    }
                                })
                                .response
                                .accessible_name("Choose an existing group");
                        })
                        .response
                    });
                    row(ui, "Type", |ui| {
                        ui.horizontal(|ui| {
                            let was = c.protocol;
                            ui.radio_value(&mut c.protocol, Protocol::Rdp, "RDP");
                            ui.radio_value(&mut c.protocol, Protocol::Ssh, "SSH");
                            if c.protocol != was && c.port == was.default_port() {
                                c.port = c.protocol.default_port();
                            }
                        })
                        .response
                    });
                    row(ui, "Open in", |ui| {
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut c.new_window, false, "This window");
                            ui.radio_value(&mut c.new_window, true, "New window");
                        })
                        .response
                    });
                    row(ui, "Host", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut c.host).hint_text("hostname or IP"))
                    });
                    row(ui, "Port", |ui| {
                        ui.add(egui::DragValue::new(&mut c.port).range(1..=65535))
                    });
                    let group_creds = group
                        .as_ref()
                        .filter(|g| !g.username.trim().is_empty() || g.has_saved_password);
                    row(ui, "Username", |ui| {
                        let hint = match group_creds {
                            Some(g) if g.username.trim().is_empty() => "(from group)".to_string(),
                            Some(g) => format!("{} (from group)", g.username.trim()),
                            None => String::new(),
                        };
                        ui.add(egui::TextEdit::singleline(&mut c.username).hint_text(hint))
                    });
                    if c.protocol == Protocol::Ssh {
                        row(ui, "Sign-in", |ui| {
                            ui.weak("Uses your SSH keys, or asks for the password in the terminal.")
                        });
                        return;
                    }
                    row(ui, "Domain", |ui| {
                        let hint = match group
                            .as_ref()
                            .map(|g| g.domain.trim())
                            .filter(|d| !d.is_empty())
                        {
                            Some(gd) => format!("{gd} (from group)"),
                            None => String::new(),
                        };
                        ui.add(egui::TextEdit::singleline(&mut c.domain).hint_text(hint))
                    });
                    match group_creds.filter(|_| c.username.trim().is_empty()) {
                        Some(g) => row(ui, "Password", |ui| {
                            let text = if g.has_saved_password {
                                format!("Uses the password saved for group “{}”", g.name)
                            } else {
                                format!("Asks when connecting (group “{}”)", g.name)
                            };
                            ui.weak(text).on_hover_text(
                                "Enter a username to use this connection's own credentials",
                            )
                        }),
                        None => row(ui, "Password", |ui| {
                            password_field(
                                ui,
                                "Password",
                                &mut d.password,
                                c.has_saved_password,
                                || actions.push(Action::Forget(Key::Rdp(id))),
                            )
                        }),
                    }
                });

                if c.protocol == Protocol::Rdp {
                    section(ui, "Display", true, |ui| {
                        if !c.new_window {
                            row(ui, "Size", |ui| {
                                ui.weak("Fits the window, and resizes with it")
                            });
                        } else {
                            row(ui, "Mode", |ui| {
                                ui.horizontal(|ui| {
                                    ui.radio_value(&mut c.fullscreen, false, "Window");
                                    ui.radio_value(&mut c.fullscreen, true, "Fullscreen");
                                })
                                .response
                            });
                            if c.fullscreen {
                                row(ui, "", |ui| {
                                    ui.checkbox(&mut c.multimon, "Span all monitors")
                                });
                            } else {
                                row(ui, "Size", |ui| {
                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::DragValue::new(&mut c.width).range(640..=8192),
                                        )
                                        .accessible_name("Width");
                                        ui.label("×");
                                        ui.add(
                                            egui::DragValue::new(&mut c.height).range(480..=8192),
                                        )
                                        .accessible_name("Height");
                                        egui::ComboBox::from_id_salt("res_presets")
                                            .selected_text("Presets")
                                            .show_ui(ui, |ui| {
                                                for &(w, h) in RESOLUTIONS {
                                                    if ui.button(format!("{w} × {h}")).clicked() {
                                                        (c.width, c.height) = (w, h);
                                                    }
                                                }
                                            })
                                            .response
                                            .accessible_name("Resolution presets");
                                    })
                                    .response
                                });
                            }
                            row(ui, "", |ui| {
                                ui.checkbox(
                                    &mut c.dynamic_resolution,
                                    "Resize remote desktop with the window",
                                )
                            });
                        }
                        row(ui, "Scaling", |ui| {
                            let options = [Scaling::Off, Scaling::Auto]
                                .into_iter()
                                .chain(Scaling::PRESETS.into_iter().skip(1).map(Scaling::Percent));
                            egui::ComboBox::from_id_salt("scaling")
                                .selected_text(c.scaling.label())
                                .width(260.0)
                                .show_ui(ui, |ui| {
                                    for o in options {
                                        ui.selectable_value(&mut c.scaling, o, o.label());
                                    }
                                })
                                .response
                                .on_hover_text(
                                    "Makes text and icons in the remote desktop larger on \
                                 high-DPI screens (/scale-desktop)",
                                )
                        });
                    });

                    section(ui, "Performance", true, |ui| {
                        let inherited = group
                            .as_ref()
                            .and_then(|g| g.profile)
                            .unwrap_or(Profile::DEFAULT);
                        row(ui, "Profile", |ui| {
                            inherit_combo(
                                ui,
                                "profile",
                                &mut c.profile,
                                &Profile::ALL,
                                Profile::label,
                                || format!("{} ({})", inherited.label(), group_label()),
                            )
                        });
                        row(ui, "", |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(
                                    &mut c.auto_reconnect,
                                    "Reconnect automatically if the network drops",
                                );
                            })
                            .response
                        });
                        if c.auto_reconnect {
                            row(ui, "Retries", |ui| {
                                ui.horizontal(|ui| {
                                    ui.add(
                                        egui::DragValue::new(&mut c.reconnect_retries)
                                            .range(0..=1000),
                                    )
                                    .accessible_name("Reconnect retries");
                                    ui.weak(if c.reconnect_retries == 0 {
                                        "unlimited"
                                    } else {
                                        "attempts"
                                    });
                                })
                                .response
                            });
                        }
                    });

                    section(ui, "Redirection", true, |ui| {
                        row(ui, "Clipboard", |ui| {
                            share_combo(ui, "clipboard_text", &mut c.clipboard_text).on_hover_text(
                                "Copy and paste text and images between this computer and the \
                             remote one",
                            )
                        });
                        row(ui, "Files", |ui| {
                            share_combo(ui, "clipboard_files", &mut c.clipboard_files)
                                .on_hover_text(
                                    "Copy and paste files between the computers. Pasting remote \
                             files here needs FUSE.",
                                )
                        });
                        row(ui, "", |ui| {
                            ui.checkbox(&mut c.home_drive, "Home folder as a drive")
                        });
                        row(ui, "", |ui| {
                            ui.checkbox(&mut c.sound, "Play remote audio locally")
                        });
                        row(ui, "", |ui| ui.checkbox(&mut c.microphone, "Microphone"));
                    });

                    section(ui, "Gateway", c.gateway != GatewayMode::Inherit, |ui| {
                        row(ui, "Gateway", |ui| {
                            ui.horizontal(|ui| {
                                ui.radio_value(&mut c.gateway, GatewayMode::Inherit, "From group");
                                ui.radio_value(&mut c.gateway, GatewayMode::Off, "None");
                                ui.radio_value(&mut c.gateway, GatewayMode::On, "Custom");
                            })
                            .response
                        });
                        match c.gateway {
                            GatewayMode::Inherit => {
                                let text = match &group {
                                    Some(g) if g.gateway_enabled => {
                                        format!(
                                            "Uses {} from group “{}”",
                                            g.gateway_host.trim(),
                                            g.name
                                        )
                                    }
                                    Some(g) => format!("Group “{}” has no gateway", g.name),
                                    None => "No group gateway; connects directly".into(),
                                };
                                row(ui, "", |ui| ui.weak(text));
                            }
                            GatewayMode::Off => {}
                            GatewayMode::On => {
                                row(ui, "Host", |ui| {
                                    ui.add(
                                        egui::TextEdit::singleline(&mut c.gateway_host)
                                            .hint_text("gateway[:port]"),
                                    )
                                });
                                row(ui, "", |ui| {
                                    ui.checkbox(
                                        &mut c.gateway_same_credentials,
                                        "Use the same credentials",
                                    )
                                });
                                if !c.gateway_same_credentials {
                                    row(ui, "Username", |ui| {
                                        ui.text_edit_singleline(&mut c.gateway_username)
                                    });
                                    row(ui, "Domain", |ui| {
                                        ui.text_edit_singleline(&mut c.gateway_domain)
                                    });
                                    row(ui, "Password", |ui| {
                                        password_field(
                                            ui,
                                            "Gateway password",
                                            &mut d.gateway_password,
                                            c.has_saved_gateway_password,
                                            || actions.push(Action::Forget(Key::Gateway(id))),
                                        )
                                    });
                                }
                            }
                        }
                    });

                    section(
                        ui,
                        "Notes",
                        !c.notes.is_empty() || !c.tags.is_empty(),
                        |ui| {
                            row(ui, "Tags", |ui| {
                                let resp = ui.add(
                                    egui::TextEdit::singleline(&mut d.tags_text)
                                        .hint_text("comma separated, e.g. prod, sql")
                                        .desired_width(f32::INFINITY),
                                );
                                if resp.changed() {
                                    c.tags = model::parse_tags(&d.tags_text);
                                }
                                resp
                            });
                            row(ui, "Notes", |ui| {
                                ui.add(
                                    egui::TextEdit::multiline(&mut c.notes)
                                        .hint_text("Who owns it, what it's for… (searchable)")
                                        .desired_rows(3)
                                        .desired_width(f32::INFINITY),
                                )
                            });
                        },
                    );
                }

                section(ui, "Advanced", false, |ui| {
                    if c.protocol == Protocol::Rdp {
                        let inherited = group
                            .as_ref()
                            .and_then(|g| g.cert)
                            .unwrap_or(CertPolicy::DEFAULT);
                        row(ui, "Certificate", |ui| {
                            inherit_combo(
                                ui,
                                "cert",
                                &mut c.cert,
                                &CertPolicy::ALL,
                                CertPolicy::label,
                                || format!("{} ({})", inherited.label(), group_label()),
                            )
                        });
                        row(ui, "", |ui| {
                            ui.checkbox(&mut c.admin, "Admin / console session")
                        });
                    }
                    let example = match c.protocol {
                        Protocol::Rdp => "e.g. /kbd:layout:0x409",
                        Protocol::Ssh => "e.g. -i ~/.ssh/work_key",
                    };
                    row(ui, "Extra args", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut c.extra_args)
                                .hint_text(example)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        )
                    });
                });

                ui.add_space(8.0);
                ui.label(RichText::new("Command").strong());
                let resolved = config.resolve(c);
                let gateway_password = resolved.gateway.as_ref().is_some_and(|gw| {
                    gw.saved_password.is_some() || !d.gateway_password.is_empty()
                });
                let creds = Credentials {
                    password: (resolved.password_key.is_some() || !d.password.is_empty())
                        .then_some("x"),
                    gateway_password: gateway_password.then_some("x"),
                };
                command_preview(ui, &resolved, &settings, &creds);
            });
    }

    fn group_editor(&mut self, ui: &mut egui::Ui) {
        let dirty = self.group_dirty();
        let Some(g) = self.group_draft.as_mut() else {
            return;
        };
        let is_new = g.new_from.is_some();
        let actions = &mut self.actions;
        let saved = !g.original.name.is_empty() && self.config.group(&g.original.name).is_some();
        let members: Vec<&Connection> = self
            .config
            .connections
            .iter()
            .filter(|c| !g.original.name.is_empty() && c.group.trim() == g.original.name)
            .collect();

        ui.horizontal(|ui| {
            ui.heading(format!("Group: {}", g.group.name));
            if dirty {
                ui.weak("(unsaved)");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .add_enabled(dirty || is_new, egui::Button::new("💾 Save"))
                    .on_hover_text("Ctrl+S")
                    .on_disabled_hover_text("No unsaved changes (Ctrl+S)")
                    .clicked()
                {
                    actions.push(Action::Save);
                }
                let revert = if is_new { "✕ Discard" } else { "↺ Revert" };
                if ui
                    .add_enabled(dirty || is_new, egui::Button::new(revert))
                    .clicked()
                {
                    actions.push(Action::Revert);
                }
                if ui
                    .add_enabled(saved, egui::Button::new("Clear defaults"))
                    .on_hover_text("Remove this group's shared settings")
                    .clicked()
                {
                    actions.push(Action::ClearGroup);
                }
            });
        });
        ui.weak(match members.len() {
            0 => "No connections use this group yet. Set a connection's Group field to join it."
                .to_string(),
            1 => "1 connection inherits these defaults unless it sets its own value.".to_string(),
            n => format!("{n} connections inherit these defaults unless they set their own value."),
        });
        ui.separator();

        egui::ScrollArea::vertical()
            .auto_shrink(false)
            .show(ui, |ui| {
                let gr = &mut g.group;
                section(ui, "Defaults", true, |ui| {
                    row(ui, "Name", |ui| ui.text_edit_singleline(&mut gr.name));
                    row(ui, "Profile", |ui| {
                        inherit_combo(
                            ui,
                            "group_profile",
                            &mut gr.profile,
                            &Profile::ALL,
                            Profile::label,
                            || format!("Not set ({})", Profile::DEFAULT.label()),
                        )
                    });
                    row(ui, "Certificate", |ui| {
                        inherit_combo(
                            ui,
                            "group_cert",
                            &mut gr.cert,
                            &CertPolicy::ALL,
                            CertPolicy::label,
                            || format!("Not set ({})", CertPolicy::DEFAULT.label()),
                        )
                    });
                });

                section(ui, "Credentials", true, |ui| {
                    row(ui, "Username", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut gr.username)
                                .hint_text("used by members without their own"),
                        )
                    });
                    row(ui, "Domain", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut gr.domain)
                                .hint_text("e.g. CORP (members without their own)"),
                        )
                    });
                    let key = Key::GroupRdp(g.original.name.clone());
                    row(ui, "Password", |ui| {
                        password_field(
                            ui,
                            "Group password",
                            &mut g.password,
                            gr.has_saved_password,
                            || actions.push(Action::Forget(key)),
                        )
                    });
                    row(ui, "", |ui| {
                        ui.weak(
                            "Members that leave Username empty use this username and password; \
                             members that leave Domain empty use this domain.",
                        )
                    });
                });

                section(ui, "Gateway", true, |ui| {
                    row(ui, "", |ui| {
                        ui.checkbox(&mut gr.gateway_enabled, "Connect through an RD Gateway")
                    });
                    ui.add_enabled_ui(gr.gateway_enabled, |ui| {
                        row(ui, "Host", |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut gr.gateway_host)
                                    .hint_text("gateway[:port]"),
                            )
                        });
                        row(ui, "", |ui| {
                            ui.checkbox(
                                &mut gr.gateway_same_credentials,
                                "Use each connection's credentials",
                            )
                        });
                        if !gr.gateway_same_credentials {
                            row(ui, "Username", |ui| {
                                ui.text_edit_singleline(&mut gr.gateway_username)
                            });
                            row(ui, "Domain", |ui| {
                                ui.text_edit_singleline(&mut gr.gateway_domain)
                            });
                            let key = Key::GroupGateway(g.original.name.clone());
                            row(ui, "Password", |ui| {
                                password_field(
                                    ui,
                                    "Gateway password",
                                    &mut g.gateway_password,
                                    gr.has_saved_gateway_password,
                                    || actions.push(Action::Forget(key)),
                                )
                            });
                        }
                    });
                });

                if !members.is_empty() {
                    section(ui, "Members", false, |ui| {
                        for c in &members {
                            row(ui, "", |ui| {
                                let resp = ui.link(c.display_name());
                                if resp.clicked() {
                                    actions.push(Action::Select(c.id));
                                }
                                resp
                            });
                        }
                    });
                }
            });
    }

    fn sessions_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Sessions").strong());
            let running = self.sessions.iter().filter(|s| s.is_running()).count();
            ui.weak(format!("{running} running"));
            if self.sessions.iter().any(|s| !s.is_running())
                && ui.small_button("Clear ended").clicked()
            {
                self.actions.push(Action::ClearEnded);
            }
        });
        egui::ScrollArea::vertical()
            .id_salt("session_list")
            .max_height(150.0)
            .show(ui, |ui| {
                for (i, s) in self.sessions.iter().enumerate() {
                    let secs = s.started.elapsed().as_secs();
                    let diagnosis = match &s.status {
                        Status::Exited(d) => Some(d),
                        Status::Running => None,
                    };
                    let (color, state) = match (&s.status, s.reconnecting()) {
                        (Status::Running, Some((n, m))) => {
                            let of = if m == 0 {
                                String::new()
                            } else {
                                format!(" of {m}")
                            };
                            (AMBER, format!("reconnecting (attempt {n}{of})…"))
                        }
                        (Status::Running, None) => (
                            GREEN,
                            format!(
                                "running {:02}:{:02}:{:02}",
                                secs / 3600,
                                secs / 60 % 60,
                                secs % 60
                            ),
                        ),
                        (Status::Exited(d), _) => match d.severity {
                            Severity::Normal => (ui.visuals().weak_text_color(), d.title.clone()),
                            Severity::Dropped => (AMBER, d.title.clone()),
                            Severity::Failed => (RED, d.title.clone()),
                        },
                    };
                    ui.horizontal(|ui| {
                        ui.colored_label(color, "●");
                        ui.label(&s.name);
                        ui.label(RichText::new(state).color(color));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if s.is_running() {
                                if ui.small_button("⏹ Disconnect").clicked() {
                                    self.actions.push(Action::Stop(i));
                                }
                            } else {
                                if ui.small_button("✕").on_hover_text("Dismiss").clicked() {
                                    self.actions.push(Action::Dismiss(i));
                                }
                                if ui.small_button("↻ Reconnect").clicked() {
                                    self.actions.push(Action::Connect(s.connection_id));
                                }
                            }
                            let showing = self.log_session == Some(i);
                            if ui.selectable_label(showing, "Log").clicked() {
                                self.log_session = if showing { None } else { Some(i) };
                            }
                        });
                    });
                    if let Some(d) = diagnosis.filter(|d| d.severity != Severity::Normal) {
                        ui.indent(("diag", i), |ui| {
                            ui.add(egui::Label::new(RichText::new(&d.hint).small()).wrap());
                            ui.horizontal(|ui| {
                                let fix = match d.fix {
                                    Some(Fix::ForgetPassword) => Some((
                                        "Forget saved password",
                                        "You'll be asked for the password on the next connect",
                                        Action::ForgetPassword(s.connection_id),
                                    )),
                                    Some(Fix::ForgetCertificate) => Some((
                                        "Forget saved certificate…",
                                        "Only if you expected the certificate to change",
                                        Action::ForgetCertificate(s.connection_id, d.cert.clone()),
                                    )),
                                    None => None,
                                };
                                if let Some((label, hover, action)) = fix
                                    && ui.small_button(label).on_hover_text(hover).clicked()
                                {
                                    self.actions.push(action);
                                }
                                if let Some(code) = &d.code {
                                    ui.weak(RichText::new(code).small().monospace());
                                }
                            });
                        });
                    }
                }
            });

        if let Some(i) = self.log_session.filter(|&i| i < self.sessions.len()) {
            ui.separator();
            let (mut copy, mut save) = (false, false);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Log: {}", self.sessions[i].name)).strong());
                copy = ui
                    .small_button("📋 Copy log")
                    .on_hover_text("Copy the log with connection details (passwords masked)")
                    .clicked();
                save = ui
                    .small_button("💾 Save log…")
                    .on_hover_text("Save the log with connection details (passwords masked)")
                    .clicked();
            });
            if copy {
                ui.ctx().copy_text(self.sessions[i].report());
                self.notice = Some(("Log copied to the clipboard".into(), false));
            }
            if save {
                self.save_log(i, ui.ctx());
            }
            let s = &self.sessions[i];
            let out = s.output.lock().unwrap();
            if out.lines.is_empty() {
                ui.weak("(no output)");
            }
            // Only the visible lines are laid out; a log can run to thousands of them.
            let row_height = ui.text_style_height(&egui::TextStyle::Small);
            egui::ScrollArea::both()
                .id_salt("session_log")
                .stick_to_bottom(true)
                .auto_shrink(false)
                .show_rows(ui, row_height, out.lines.len(), |ui, rows| {
                    for line in &out.lines[rows] {
                        ui.add(egui::Label::new(RichText::new(line).monospace().small()).extend());
                    }
                });
        }
    }

    fn modals(&mut self, ctx: &egui::Context) {
        if let Some(p) = &mut self.prompt {
            let mut cancel = false;
            let resp = egui::Modal::new(egui::Id::unique("password_prompt")).show(ctx, |ui| {
                ui.set_width(340.0);
                let mut first_field = None;
                if p.saved_password.is_none() {
                    ui.heading("Password");
                    ui.label(format!("Connecting to {}", p.target));
                    ui.add_space(6.0);
                    let field = ui
                        .add(
                            egui::TextEdit::singleline(&mut p.password)
                                .password(true)
                                .hint_text("Leave empty to let FreeRDP ask")
                                .desired_width(f32::INFINITY),
                        )
                        .accessible_name("Password");
                    first_field = Some(field);
                    if let Some((_, label)) = &p.save_to {
                        ui.checkbox(&mut p.remember, label.as_str());
                    }
                }
                if let Some(g) = &mut p.gateway {
                    ui.add_space(6.0);
                    ui.heading("Gateway password");
                    ui.label(format!("Gateway {}", g.target));
                    ui.add_space(6.0);
                    let field = ui
                        .add(
                            egui::TextEdit::singleline(&mut g.password)
                                .password(true)
                                .hint_text("Leave empty to let FreeRDP ask")
                                .desired_width(f32::INFINITY),
                        )
                        .accessible_name("Gateway password");
                    first_field.get_or_insert(field);
                    if let Some((_, label)) = &g.save_to {
                        ui.checkbox(&mut g.remember, label.as_str());
                    }
                }
                if let Some(field) = first_field.filter(|_| !p.focused) {
                    field.request_focus();
                    p.focused = true;
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    // Enter in a field ends editing it; treat Enter anywhere in this dialog
                    // as "Connect".
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if ui.button("Connect").clicked() || enter {
                        self.actions.push(Action::Launch);
                    }
                    if ui.button("Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
            if cancel || resp.should_close() {
                self.prompt = None;
            }
        }

        if let Some(id) = self.confirm_delete {
            let name = self
                .find(id)
                .map(|c| c.display_name().to_owned())
                .unwrap_or_default();
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("confirm_delete")).show(ctx, |ui| {
                ui.heading("Delete connection?");
                ui.label(format!("“{name}” and its saved passwords will be removed."));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new("Delete").color(ui.visuals().error_fg_color))
                        .clicked()
                    {
                        self.actions.push(Action::Delete(id));
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.confirm_delete = None;
            }
        }

        if let Some(s) = &mut self.settings_draft {
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("settings")).show(ctx, |ui| {
                ui.set_width(400.0);
                ui.heading("Settings");
                ui.add_space(6.0);
                egui::Grid::new("settings_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label("FreeRDP client");
                        ui.horizontal(|ui| {
                            ui.text_edit_singleline(&mut s.client)
                                .accessible_name("FreeRDP client");
                            egui::ComboBox::from_id_salt("client_presets")
                                .selected_text("")
                                .width(20.0)
                                .show_ui(ui, |ui| {
                                    for c in CLIENTS {
                                        ui.selectable_value(&mut s.client, c.to_string(), *c);
                                    }
                                })
                                .response
                                .accessible_name("Client presets");
                        });
                        ui.end_row();
                        ui.label("Terminal");
                        ui.add(
                            egui::TextEdit::singleline(&mut s.terminal)
                                .hint_text("automatic (for SSH in a new window)"),
                        )
                        .accessible_name("Terminal")
                        .on_hover_text(
                            "The name of a terminal, or a full command such as \
                             “konsole --nofork -e”; ssh is added to its end. It should keep \
                             running until the session ends, or the session list shows the \
                             session as ended.",
                        );
                        ui.end_row();
                        ui.label("Log level");
                        egui::ComboBox::from_id_salt("log_level")
                            .selected_text(s.log_level.as_str())
                            .show_ui(ui, |ui| {
                                for l in LOG_LEVELS {
                                    ui.selectable_value(&mut s.log_level, l.to_string(), *l);
                                }
                            })
                            .response
                            .accessible_name("Log level");
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(&mut s.probe_hosts, "Check whether hosts are reachable");
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(
                            &mut s.tray,
                            "Tray icon (closing the window keeps xrdp-gui running)",
                        );
                        ui.end_row();
                        ui.label("");
                        ui.checkbox(
                            &mut s.accordion,
                            "Opening a group in the sidebar closes the others",
                        );
                        ui.end_row();
                        ui.label("");
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut s.notifications, "Desktop notifications");
                            if ui.small_button("Test").clicked() {
                                notify::send(
                                    "xrdp-gui".into(),
                                    "Notifications are working.".into(),
                                    false,
                                );
                            }
                        });
                        ui.end_row();
                    });
                ui.add_space(4.0);
                ui.weak(
                    "sdl-freerdp is recommended on Wayland. Sessions inside the main window use \
                     xfreerdp, the only client that can draw there.",
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Save").clicked() {
                        self.actions.push(Action::SaveSettings);
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.settings_draft = None;
            }
        }

        if let Some(list) = &self.known_certs {
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("certificates")).show(ctx, |ui| {
                ui.set_width(720.0);
                ui.heading("Trusted server certificates");
                ui.label(
                    "FreeRDP remembers each server's certificate the first time you accept it, and \
                     refuses to connect if it changes. Forget one when a server's certificate was \
                     replaced on purpose; the next connection then asks you to check the new one.",
                );
                ui.add_space(6.0);
                if list.is_empty() {
                    ui.weak("No certificates saved yet.");
                }
                egui::ScrollArea::vertical()
                    .max_height(380.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        // A grid is only as wide as its contents, so the columns are given
                        // widths that add up to the window's; the details get what's left.
                        const HOST: f32 = 200.0;
                        const FINGERPRINT: f32 = 125.0;
                        const FORGET: f32 = 60.0;
                        const GAP: f32 = 12.0;
                        let details =
                            (ui.available_width() - HOST - FINGERPRINT - FORGET - 3.0 * GAP)
                                .max(120.0);
                        let column =
                            |ui: &mut egui::Ui, width: f32, add: &mut dyn FnMut(&mut egui::Ui)| {
                                ui.vertical(|ui| {
                                    ui.set_width(width);
                                    add(ui);
                                });
                            };
                        egui::Grid::new("cert_grid")
                            .num_columns(4)
                            .striped(true)
                            .spacing([GAP, 6.0])
                            .show(ui, |ui| {
                                for cert in list {
                                    let used_by: Vec<&str> = self
                                        .config
                                        .connections
                                        .iter()
                                        .filter(|c| {
                                            c.port == cert.port
                                                && certs::store_host(&c.host) == cert.host
                                        })
                                        .map(|c| c.display_name())
                                        .collect();
                                    column(ui, HOST, &mut |ui| {
                                        ui.label(
                                            RichText::new(format!("{}:{}", cert.host, cert.port))
                                                .strong(),
                                        );
                                        if !used_by.is_empty() {
                                            ui.weak(used_by.join(", "));
                                        }
                                    });
                                    column(ui, details, &mut |ui| match &cert.error {
                                        Some(e) => {
                                            ui.colored_label(ui.visuals().warn_fg_color, e);
                                        }
                                        None => {
                                            ui.label(format!(
                                                "{} (issued by {})",
                                                cert.subject, cert.issuer
                                            ));
                                            if let Some(t) = cert.expires {
                                                let text =
                                                    format!("Expires {}", t.format("%Y-%m-%d"));
                                                if cert.expired() {
                                                    ui.colored_label(
                                                        RED,
                                                        format!("{text} (expired)"),
                                                    );
                                                } else {
                                                    ui.weak(text);
                                                }
                                            }
                                        }
                                    });
                                    column(ui, FINGERPRINT, &mut |ui| {
                                        let short: String =
                                            cert.fingerprint.chars().take(23).collect();
                                        if ui
                                            .add(
                                                egui::Label::new(
                                                    RichText::new(format!("{short}…"))
                                                        .monospace()
                                                        .small(),
                                                )
                                                .sense(egui::Sense::click()),
                                            )
                                            .on_hover_text(format!(
                                                "SHA-256 {}\nClick to copy",
                                                cert.fingerprint
                                            ))
                                            .clicked()
                                        {
                                            ui.ctx().copy_text(cert.fingerprint.clone());
                                        }
                                    });
                                    if ui
                                        .add(
                                            egui::Button::new("Forget")
                                                .min_size(egui::vec2(FORGET, 0.0)),
                                        )
                                        .on_hover_text(
                                            "The next connection will ask you to check the new one",
                                        )
                                        .accessible_name(format!(
                                            "Forget certificate for {}",
                                            cert.host
                                        ))
                                        .clicked()
                                    {
                                        self.actions.push(Action::AskForgetKnownCert {
                                            host: cert.host.clone(),
                                            port: cert.port,
                                            path: cert.path.clone(),
                                            fingerprint: cert.fingerprint.clone(),
                                        });
                                    }
                                    ui.end_row();
                                }
                            });
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Refresh").clicked() {
                        self.actions.push(Action::OpenCertificates);
                    }
                    if ui.button("Open folder").clicked()
                        && let Ok(dir) = certs::dir()
                    {
                        let _ = std::process::Command::new("xdg-open").arg(dir).spawn();
                    }
                    close = ui.button("Close").clicked();
                });
            });
            if close || resp.should_close() {
                self.known_certs = None;
            }
        }

        if self.backup_open {
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("backup")).show(ctx, |ui| {
                ui.set_width(520.0);
                ui.heading("Backup and restore");
                ui.label(
                    "A backup holds your connections, groups and settings, to move to another \
                     computer or to keep safe.",
                );
                ui.add_space(4.0);
                ui.label(
                    "Passwords and trusted certificates are not included: you'll be asked for \
                     passwords again, and to accept certificates as if connecting for the first \
                     time.",
                );
                ui.add_space(4.0);
                ui.label(
                    "Extra arguments and notes are saved as you typed them, so keep the file \
                     private if they hold anything sensitive.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Back up…").clicked() {
                        self.actions.push(Action::Backup);
                    }
                    if ui.button("Restore…").clicked() {
                        self.actions.push(Action::PickRestore);
                    }
                    close = ui.button("Close").clicked();
                });
            });
            if close || resp.should_close() {
                self.backup_open = false;
            }
        }

        if let Some(pending) = &self.restore {
            let backup = &pending.backup;
            let broken = self.load_error.is_some();
            let add = backup.preview(&self.config, RestoreMode::Add);
            let replace = backup.preview(&self.config, RestoreMode::Replace);
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("restore")).show(ctx, |ui| {
                ui.set_width(560.0);
                ui.heading("Restore this backup?");
                ui.label(RichText::new(&pending.file).small());
                ui.add_space(4.0);
                let created = match backup.created.as_str() {
                    "" => String::new(),
                    when => format!("Made {when}: "),
                };
                ui.label(format!(
                    "{created}{} and {}.",
                    counted(backup.connections.len(), "connection"),
                    counted(backup.groups.len(), "group"),
                ));
                if backup.risky_entries() > 0 {
                    ui.add_space(4.0);
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        format!(
                            "{} extra FreeRDP arguments or skipped certificate checks. Only \
                             restore this if you trust where the file came from.",
                            match backup.risky_entries() {
                                1 => "1 entry uses".to_string(),
                                n => format!("{n} entries use"),
                            },
                        ),
                    );
                }
                ui.add_space(8.0);
                if !broken {
                    ui.label(RichText::new("Add what's missing").strong());
                    ui.label(format!(
                        "Adds {} and {}. Nothing you have now changes.",
                        counted(add.added_connections, "connection"),
                        counted(add.added_groups, "group"),
                    ));
                    ui.add_space(6.0);
                }
                if !backup.is_empty() {
                    ui.label(RichText::new("Replace everything").strong());
                    let mut text = "Connections, groups and settings become what's in the \
                                    backup, and a copy of your current setup is kept first."
                        .to_string();
                    if replace.removed_connections + replace.removed_groups > 0 {
                        text.push_str(&format!(
                            " This removes {} and {} that the backup doesn't have.",
                            counted(replace.removed_connections, "connection"),
                            counted(replace.removed_groups, "group"),
                        ));
                    }
                    if backup.changes_programs(&self.config) {
                        text.push_str(
                            " It also changes the FreeRDP client or terminal program this \
                             computer runs; check them in Settings afterwards.",
                        );
                    }
                    if !replace.stale_passwords.is_empty() {
                        text.push_str(&format!(
                            " {} saved with those can't be brought back, even from that copy.",
                            counted(replace.stale_passwords.len(), "password"),
                        ));
                    }
                    ui.label(text);
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let nothing_to_add = add.added_connections + add.added_groups == 0;
                    if !broken
                        && ui
                            .add_enabled(!nothing_to_add, egui::Button::new("Add what's missing"))
                            .on_disabled_hover_text("You already have everything in this backup")
                            .clicked()
                    {
                        self.actions.push(Action::Restore(RestoreMode::Add));
                    }
                    if !backup.is_empty() && ui.button("Replace everything").clicked() {
                        self.actions.push(Action::Restore(RestoreMode::Replace));
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.restore = None;
            }
        }

        if let Some(forget) = &self.confirm_forget_cert {
            let mut close = false;
            let asks = self.config.settings.client.contains("sdl");
            let resp = egui::Modal::new(egui::Id::unique("confirm_forget_cert")).show(ctx, |ui| {
                ui.set_width(640.0);
                ui.heading("Forget this certificate?");
                ui.label(format!("{}:{}", forget.host, forget.port));
                ui.add_space(4.0);
                ui.label(
                    "Only do this if you expected the certificate to change, for example after \
                     a renewal or reinstall. A change can also mean someone is intercepting the \
                     connection.",
                );
                ui.add_space(6.0);
                let fingerprint = |ui: &mut egui::Ui, label: &str, value: Option<&String>| {
                    ui.label(label);
                    match value {
                        Some(v) => ui.label(RichText::new(v).monospace().small()),
                        None => ui.weak("not known yet"),
                    };
                };
                fingerprint(
                    ui,
                    "Saved certificate (SHA-256):",
                    forget.old_fingerprint.as_ref(),
                );
                if forget.new_fingerprint.is_some() {
                    fingerprint(
                        ui,
                        "Certificate the server presented (SHA-256):",
                        forget.new_fingerprint.as_ref(),
                    );
                }
                ui.add_space(6.0);
                ui.label(
                    "The next connection will show you the new certificate and ask whether to \
                     trust it.",
                );
                if !asks {
                    ui.colored_label(
                        ui.visuals().warn_fg_color,
                        "Only sdl-freerdp can show that question when started from xrdp-gui. \
                         Other clients may refuse the connection instead; you can change the \
                         client in Settings.",
                    );
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new("Forget").color(ui.visuals().error_fg_color))
                        .clicked()
                    {
                        self.actions.push(Action::ForgetCertConfirmed);
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.confirm_forget_cert = None;
            }
        }

        if let Some(id) = self.confirm_second {
            let name = self
                .find_any(id)
                .map(|c| c.display_name().to_owned())
                .unwrap_or_default();
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("confirm_second")).show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.heading("Already running");
                ui.label(format!(
                    "“{name}” already has a session running. Connecting again with the same \
                     account usually disconnects it."
                ));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Connect anyway").clicked() {
                        self.actions.push(Action::ConnectAnyway(id));
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.confirm_second = None;
            }
        }

        if self.confirm_quit {
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("confirm_quit")).show(ctx, |ui| {
                ui.set_max_width(420.0);
                ui.heading("Quit?");
                let n = self.sessions.iter().filter(|s| s.is_running()).count();
                if n > 0 {
                    ui.label(format!(
                        "{n} session(s) are still running and will be disconnected."
                    ));
                }
                if let Some(e) = &self.quit_save_error {
                    ui.colored_label(
                        ui.visuals().error_fg_color,
                        format!("Your unsaved changes couldn't be saved: {e}"),
                    );
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let label = match (n > 0, self.quit_save_error.is_some()) {
                        (true, true) => "Disconnect and quit without saving",
                        (false, true) => "Quit without saving",
                        _ => "Disconnect and quit",
                    };
                    if ui.button(label).clicked() {
                        self.actions.push(Action::Quit);
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.confirm_quit = false;
                self.quit_save_error = None;
            }
        }
    }
}

impl eframe::App for App {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        match self.selection() {
            Some(sel) => eframe::set_value(storage, SELECTION_KEY, &sel),
            None => storage.set_string(SELECTION_KEY, String::new()),
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.frame(ui);
    }
}

/// A window onto the app. The app outlives its window, so it can keep running in the
/// tray and open a new one later.
pub struct Window<'a>(pub &'a mut App);

impl eframe::App for Window<'_> {
    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::App::save(self.0, storage);
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        eframe::App::ui(self.0, ui, frame);
    }

    fn on_exit(&mut self) {
        self.0.detach_sessions();
    }
}

impl App {
    fn frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        if let Some(ppp) = ctx.input(|i| i.viewport().native_pixels_per_point) {
            model::set_screen_scale(ppp);
        }
        self.poll_sessions();
        self.update_probe_targets();
        self.handle_shortcuts(&ctx);
        self.handle_commands(&ctx);
        self.poll_keyring();
        // A request from the tray or another launch that needs an answer brings the window
        // forward.
        if self.needs_window()
            && let Some(token) = self.raise_for_prompt.take()
        {
            self.bring_to_front(&ctx, token);
        } else if self.pending_lookups.is_empty() {
            self.raise_for_prompt = None;
        }
        self.sync_integrations();
        if let Some(n) = self.inbox.lock().unwrap().pop() {
            self.notice = Some(n);
        }
        let opened = self.restore_inbox.lock().unwrap().take();
        match opened {
            Some(Ok(pending)) => self.restore = Some(pending),
            Some(Err(e)) => self.error(anyhow::anyhow!(e)),
            None => {}
        }

        let any_running = self.sessions.iter().any(Session::is_running);
        if any_running {
            // Keep the elapsed-time display, reconnect state and exit detection ticking.
            // Not more often: on a large window, a frame isn't free.
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            if self.tray_active() {
                self.hide_to_tray();
                if !self.told_about_tray {
                    self.told_about_tray = true;
                    self.notify(
                        "xrdp-gui is still running".into(),
                        "Open it again from the tray icon. Quit from the tray menu or with Ctrl+Q."
                            .into(),
                        false,
                    );
                }
            } else if self.prepare_quit() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.confirm_quit = true;
            } else {
                self.exit = Exit::Quit;
            }
        }

        egui::Panel::top("top").show(ui, |ui| {
            ui.add_space(4.0);
            self.top_bar(ui);
            ui.add_space(2.0);
        });
        if !self.sessions.is_empty() {
            let size = if self.log_session.is_some() {
                300.0
            } else {
                120.0
            };
            egui::Panel::bottom("sessions")
                .resizable(true)
                .default_size(size)
                .show(ui, |ui| self.sessions_panel(ui));
        }
        egui::Panel::left("connections")
            .resizable(true)
            .default_size(250.0)
            .size_range(180.0..=420.0)
            .show(ui, |ui| self.connection_list(ui));
        egui::CentralPanel::default_margins().show(ui, |ui| self.main_area(ui));

        self.modals(&ctx);
        self.sync_session_windows(&ctx);

        for action in std::mem::take(&mut self.actions) {
            self.apply(action, &ctx);
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        self.terminate_all();
    }
}

/// Parses `[DOMAIN\]user@host[:port]` (or `rdp://…`) for quick connect.
fn parse_quick(text: &str) -> Option<Connection> {
    let text = text.trim();
    let text = text.strip_prefix("rdp://").unwrap_or(text);
    let (user, host) = match text.rsplit_once('@') {
        Some((u, h)) => (u.trim(), h),
        None => ("", text),
    };
    let (domain, user) = user.split_once('\\').unwrap_or(("", user));
    let (host, port) = model::split_host_port(host, 3389);
    if host.is_empty() || host.contains(char::is_whitespace) {
        return None;
    }
    Some(Connection {
        name: host.clone(),
        host,
        port,
        username: user.to_string(),
        domain: domain.to_string(),
        ..Default::default()
    })
}

fn connection_row(
    ui: &mut egui::Ui,
    c: &Connection,
    selected: bool,
    config: &Config,
    sessions: &[Session],
    prober: &Prober,
    actions: &mut Vec<Action>,
) {
    let session = sessions
        .iter()
        .rev()
        .find(|s| s.connection_id == c.id && s.is_running());
    let reach = prober.get(c.id);
    let (dot, reach_text) = match (&reach, config.settings.probe_hosts) {
        (_, false) => (
            ui.visuals().weak_text_color(),
            "Host checks are off".to_string(),
        ),
        (None, _) => (ui.visuals().weak_text_color(), "Checking…".to_string()),
        (Some(Reach::Up(t)), _) => (GREEN, format!("Reachable ({} ms)", t.as_millis())),
        (Some(Reach::Down(why)), _) => (RED, format!("Not reachable: {why}")),
    };

    let fmt = |color| egui::TextFormat {
        color,
        ..Default::default()
    };
    let mut text = egui::text::LayoutJob::default();
    text.append("● ", 0.0, fmt(dot));
    text.append(c.display_name(), 0.0, fmt(ui.visuals().text_color()));
    if c.favorite {
        text.append(" ★", 0.0, fmt(AMBER));
    }
    if c.protocol == Protocol::Ssh {
        text.append(
            "  SSH",
            0.0,
            egui::TextFormat {
                color: ui.visuals().weak_text_color(),
                font_id: egui::FontId::proportional(11.0),
                ..Default::default()
            },
        );
    }
    if !c.tags.is_empty() {
        let tags: Vec<String> = c.tags.iter().map(|t| format!("#{t}")).collect();
        text.append(
            &format!("  {}", tags.join(" ")),
            0.0,
            egui::TextFormat {
                color: ui.visuals().weak_text_color(),
                font_id: egui::FontId::proportional(11.0),
                ..Default::default()
            },
        );
    }
    match session.map(|s| s.reconnecting()) {
        Some(Some(_)) => text.append("  ⟳", 0.0, fmt(AMBER)),
        Some(None) => text.append("  ▶", 0.0, fmt(GREEN)),
        None => {}
    }

    let target = match config.gateway(c) {
        Some(gw) => format!("{}:{} via gateway {}", c.host, c.port, gw.host),
        None => format!("{}:{}", c.host, c.port),
    };
    let mut hover = format!("{target}\n{reach_text}");
    if let Some(t) = c
        .last_used
        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
    {
        let t = t.with_timezone(&chrono::Local);
        hover.push_str(&format!("\nLast used {}", t.format("%Y-%m-%d %H:%M")));
    }
    if let Some(first) = c.notes.lines().find(|l| !l.trim().is_empty()) {
        hover.push_str(&format!("\n📝 {}", first.trim()));
    }
    // A justified layout stretches the row to full width with its text on the left.
    let resp = ui
        .with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
            ui.add(egui::Button::selectable(selected, text).min_size(egui::vec2(0.0, 22.0)))
        })
        .inner
        .on_hover_text(hover);
    if resp.double_clicked() {
        actions.push(Action::Connect(c.id));
    } else if resp.clicked() {
        actions.push(Action::Select(c.id));
    }
    resp.context_menu(|ui| {
        if ui.button("Connect").clicked() {
            actions.push(Action::Connect(c.id));
        }
        let star = if c.favorite {
            "Remove from favourites"
        } else {
            "Add to favourites"
        };
        if ui.button(star).clicked() {
            actions.push(Action::ToggleFavorite(c.id));
        }
        if ui.button("Duplicate").clicked() {
            actions.push(Action::Duplicate(c.id));
        }
        if ui.button("Delete…").clicked() {
            actions.push(Action::AskDelete(c.id));
        }
    });
}

/// A combo box choosing which way the shared clipboard copies.
fn share_combo(ui: &mut egui::Ui, id: &str, value: &mut ClipboardShare) -> egui::Response {
    egui::ComboBox::from_id_salt(id)
        .selected_text(value.label())
        .width(260.0)
        .show_ui(ui, |ui| {
            for s in ClipboardShare::ALL {
                ui.selectable_value(value, s, s.label());
            }
        })
        .response
}

fn section(ui: &mut egui::Ui, title: &str, open: bool, body: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).strong())
        .default_open(open)
        .show(ui, |ui| {
            egui::Grid::new(title)
                .num_columns(2)
                .spacing([12.0, 6.0])
                .show(ui, body);
        });
}

fn row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> egui::Response) {
    let label_id = ui.label(label).id;
    let field = add(ui);
    if !label.is_empty() {
        // Lets screen readers announce the field by its label.
        field.labelled_by(label_id);
    }
    ui.end_row();
}

fn password_field(
    ui: &mut egui::Ui,
    name: &str,
    value: &mut String,
    saved: bool,
    forget: impl FnOnce(),
) -> egui::Response {
    ui.horizontal(|ui| {
        let hint = if saved {
            "•••••••• (saved; type to replace)"
        } else {
            "ask when connecting"
        };
        ui.add(
            egui::TextEdit::singleline(value)
                .password(true)
                .hint_text(hint),
        )
        .accessible_name(name);
        if saved
            && ui
                .small_button("Forget")
                .on_hover_text("Remove from keyring")
                .clicked()
        {
            forget();
        }
    })
    .response
}

/// A combo box whose first entry ("inherit") stores `None`.
fn inherit_combo<T: Copy + PartialEq>(
    ui: &mut egui::Ui,
    id: &str,
    value: &mut Option<T>,
    all: &[T],
    label: fn(T) -> &'static str,
    inherited: impl FnOnce() -> String,
) -> egui::Response {
    let inherited = inherited();
    let selected = match *value {
        Some(v) => label(v).to_string(),
        None => inherited.clone(),
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(selected)
        .width(260.0)
        .show_ui(ui, |ui| {
            ui.selectable_value(value, None, inherited);
            ui.separator();
            for &v in all {
                ui.selectable_value(value, Some(v), label(v));
            }
        })
        .response
}

fn command_preview(
    ui: &mut egui::Ui,
    resolved: &Resolved,
    settings: &Settings,
    creds: &Credentials,
) {
    let preview_row = |ui: &mut egui::Ui, preview: String| {
        ui.horizontal_wrapped(|ui| {
            ui.add(egui::Label::new(RichText::new(&preview).monospace().weak()).wrap());
            if ui
                .small_button("📋")
                .on_hover_text("Copy (passwords masked)")
                .clicked()
            {
                ui.ctx().copy_text(preview.clone());
            }
        });
    };
    if resolved.conn.protocol == Protocol::Ssh {
        match command::ssh_args(resolved) {
            Ok(args) => preview_row(ui, command::preview("ssh", &args)),
            Err(e) => {
                ui.colored_label(ui.visuals().warn_fg_color, format!("{e:#}"));
            }
        }
        return;
    }
    match command::build_args(resolved, settings, creds) {
        Ok(args) => {
            preview_row(ui, command::preview(&settings.client, &args));
            ui.weak("Arguments are passed via /args-from:stdin, so passwords never appear in the process list.");
        }
        Err(e) => {
            ui.colored_label(ui.visuals().warn_fg_color, format!("{e:#}"));
        }
    }
}

fn holder_of(session: &Session) -> Option<u32> {
    match session.surface {
        Surface::Rdp { holder, .. } => holder,
        _ => None,
    }
}

/// "1 connection", "2 connections".
fn counted(n: usize, what: &str) -> String {
    if n == 1 {
        format!("1 {what}")
    } else {
        format!("{n} {what}s")
    }
}

/// A file dialog for backups, starting in the documents folder.
fn backup_dialog(title: &str) -> rfd::FileDialog {
    let dialog = rfd::FileDialog::new()
        .set_title(title)
        .add_filter("Backup", &["toml"]);
    match directories::UserDirs::new().and_then(|u| u.document_dir().map(|p| p.to_path_buf())) {
        Some(dir) => dialog.set_directory(dir),
        None => dialog,
    }
}

#[cfg(test)]
mod ui_tests {
    //! Drives the real UI headlessly: key presses and clicks go through egui exactly as
    //! they would from the keyboard and mouse.

    use super::*;
    use egui::accesskit::Role;
    use egui_kittest::Harness;
    use egui_kittest::kittest::Queryable;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct TestEnv {
        dir: PathBuf,
    }

    impl TestEnv {
        /// A throwaway config with one connection whose client is a fake FreeRDP that
        /// fails with a logon error.
        fn new(name: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("xrdp-gui-ui-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let client = dir.join("fake-freerdp");
            std::fs::write(
                &client,
                "#!/bin/sh\ncat >/dev/null\n\
                 echo '[ERROR][com.freerdp.core] - [nla]: ERRCONNECT_LOGON_FAILURE [0x00020014]' >&2\n\
                 exit 134\n",
            )
            .unwrap();
            std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o755)).unwrap();
            let config = Config {
                settings: Settings {
                    client: client.to_string_lossy().into(),
                    probe_hosts: false,
                    notifications: false,
                    ..Default::default()
                },
                cert_review: Vec::new(),
                groups: vec![Group {
                    name: "Work".into(),
                    domain: "CORP".into(),
                    username: "svc".into(),
                    ..Default::default()
                }],
                connections: vec![
                    Connection {
                        name: "Alpha".into(),
                        host: "127.0.0.1".into(),
                        username: "alice".into(),
                        ..Default::default()
                    },
                    Connection {
                        name: "Beta".into(),
                        group: "Work".into(),
                        host: "127.0.0.2".into(),
                        ..Default::default()
                    },
                ],
            };
            let env = Self { dir };
            config.save(&env.config_path()).unwrap();
            env
        }

        fn config_path(&self) -> PathBuf {
            self.dir.join("config.toml")
        }

        fn harness(&self) -> Harness<'static, App> {
            self.harness_with_storage(None)
        }

        /// Starts the app as eframe would on launch, optionally with previously saved state.
        fn harness_with_storage(
            &self,
            storage: Option<&'static MemStorage>,
        ) -> Harness<'static, App> {
            let path = self.config_path();
            let mut h = Harness::builder()
                .with_size([1100.0, 760.0])
                // The harness has no system fonts; draw boxes for icons instead of panicking.
                .allow_missing_glyphs()
                .build_eframe(move |cc| {
                    cc.storage = storage.map(|s| s as &dyn eframe::Storage);
                    App::with_config_path(cc, None, path)
                });
            h.run_steps(2);
            h
        }
    }

    /// Stands in for eframe's on-disk app state (`~/.local/share/xrdp-gui/app.ron`).
    #[derive(Default)]
    struct MemStorage(std::collections::HashMap<String, String>);

    impl eframe::Storage for MemStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.to_string(), value);
        }
        fn remove_string(&mut self, key: &str) {
            self.0.remove(key);
        }
        fn flush(&mut self) {}
    }

    /// Saves the app's state the way eframe does on exit or autosave.
    fn saved_state(h: &mut Harness<'static, App>) -> &'static MemStorage {
        let mut storage = MemStorage::default();
        eframe::App::save(h.state_mut(), &mut storage);
        Box::leak(Box::new(storage))
    }

    #[test]
    fn restores_last_selection() {
        let env = TestEnv::new("restore");

        // Select a connection, save state, and start a fresh app from it.
        let mut h = env.harness();
        h.get_by_label_contains("Beta").click();
        h.run_steps(3);
        let beta = h
            .state()
            .draft
            .as_ref()
            .map(|d| d.conn.id)
            .expect("Beta selected");
        let storage = saved_state(&mut h);
        drop(h);
        let h = env.harness_with_storage(Some(storage));
        let restored = h.state().draft.as_ref().map(|d| d.conn.id);
        assert_eq!(
            restored,
            Some(beta),
            "last selected connection should be restored"
        );
        // …and shown in the editor.
        assert!(
            h.query_by(|n| n.role() == Role::TextInput && n.value().as_deref() == Some("Beta"))
                .is_some(),
            "the restored connection should be open in the editor"
        );

        // Same for a group whose defaults were being edited.
        let mut h = env.harness();
        h.get_by_label("Edit group Work").click();
        h.run_steps(3);
        assert!(
            h.state().group_draft.is_some(),
            "clicking the group header should open it"
        );
        let storage = saved_state(&mut h);
        drop(h);
        let h = env.harness_with_storage(Some(storage));
        let restored = h
            .state()
            .group_draft
            .as_ref()
            .map(|g| g.original.name.clone());
        assert_eq!(
            restored.as_deref(),
            Some("Work"),
            "last selected group should be restored"
        );

        // A selection that no longer exists is ignored rather than crashing.
        let mut stale = MemStorage::default();
        eframe::set_value(
            &mut stale,
            SELECTION_KEY,
            &Selection::Connection(Uuid::new_v4()),
        );
        let h = env.harness_with_storage(Some(Box::leak(Box::new(stale))));
        assert!(h.state().draft.is_none() && h.state().group_draft.is_none());

        // Nothing selected: nothing restored.
        let mut h = env.harness();
        let storage = saved_state(&mut h);
        drop(h);
        let h = env.harness_with_storage(Some(storage));
        assert!(h.state().draft.is_none() && h.state().group_draft.is_none());
    }

    impl Drop for TestEnv {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn select_alpha(h: &mut Harness<'static, App>) {
        h.get_by_label_contains("Alpha").click();
        h.run_steps(3);
        assert!(
            h.state()
                .draft
                .as_ref()
                .is_some_and(|d| d.conn.name == "Alpha")
        );
    }

    #[test]
    fn keyboard_shortcuts() {
        let env = TestEnv::new("shortcuts");
        let mut h = env.harness();
        select_alpha(&mut h);

        // Enter connects; with no saved password that starts with the password prompt.
        h.key_press(KeyCode::Enter);
        h.run_steps(3);
        assert!(h.state().prompt.is_some(), "Enter should start connecting");
        h.get_by_label("Cancel").click();
        h.run_steps(3);
        assert!(h.state().prompt.is_none());

        // Delete asks for confirmation.
        h.key_press(KeyCode::Delete);
        h.run_steps(3);
        assert!(
            h.state().confirm_delete.is_some(),
            "Delete should ask to delete"
        );
        h.get_by_label("Cancel").click();
        h.run_steps(3);
        assert!(h.state().confirm_delete.is_none());
        assert_eq!(
            h.state().config.connections.len(),
            2,
            "Cancel must not delete"
        );

        // Ctrl+S saves, even while typing in a field.
        h.get_by(|n| n.role() == Role::TextInput && n.value().as_deref() == Some("Alpha"))
            .focus();
        h.run_steps(2);
        h.input_mut().events.push(egui::Event::Text(" Two".into()));
        h.run_steps(2);
        assert!(
            h.state().conn_dirty(),
            "typing should make the connection dirty"
        );
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::S);
        h.run_steps(3);
        assert!(!h.state().conn_dirty(), "Ctrl+S should save");
        let saved = std::fs::read_to_string(env.config_path()).unwrap();
        assert!(
            saved.contains("Two"),
            "saved config should contain the edit:\n{saved}"
        );

        // Ctrl+F jumps to search.
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::F);
        h.run_steps(3);
        h.input_mut().events.push(egui::Event::Text("zzz".into()));
        h.run_steps(3);
        assert_eq!(
            h.state().search,
            "zzz",
            "Ctrl+F should focus the search box"
        );

        // Ctrl+N starts a new connection.
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::N);
        h.run_steps(3);
        assert!(
            h.state().draft.as_ref().is_some_and(|d| d.is_new),
            "Ctrl+N should create a connection"
        );
    }

    #[test]
    fn copy_log_button() {
        let env = TestEnv::new("copylog");
        let mut h = env.harness();
        select_alpha(&mut h);

        // Connect via Enter, then Enter again in the password prompt (empty password).
        h.key_press(KeyCode::Enter);
        h.run_steps(3);
        assert!(h.state().prompt.is_some());
        h.key_press(KeyCode::Enter);
        h.run_steps(3);
        assert!(
            h.state().prompt.is_none(),
            "Enter in the password prompt should connect"
        );
        assert_eq!(h.state().sessions.len(), 1, "a session should have started");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while h.state().sessions[0].is_running() {
            assert!(
                std::time::Instant::now() < deadline,
                "fake client did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
            h.step();
        }
        h.run_steps(2);

        h.get_by_label("Log").click();
        h.run_steps(3);
        h.get_by_label("📋 Copy log").click();
        let mut copied = None;
        for _ in 0..4 {
            h.step();
            copied = copied.or_else(|| {
                h.output()
                    .platform_output
                    .commands
                    .iter()
                    .find_map(|c| match c {
                        egui::OutputCommand::CopyText(t) => Some(t.clone()),
                        _ => None,
                    })
            });
        }
        let copied = copied.expect("Copy log should put text on the clipboard");
        assert!(copied.contains("Connection: Alpha"), "{copied}");
        assert!(
            copied.contains("failed: Wrong username or password [ERRCONNECT_LOGON_FAILURE]"),
            "{copied}"
        );
        assert!(
            copied.contains("ERRCONNECT_LOGON_FAILURE [0x00020014]"),
            "log lines missing:\n{copied}"
        );
    }

    fn has_label(h: &Harness<'static, App>, text: &str) -> bool {
        h.query_by_label_contains(text).is_some()
    }

    fn wait_for_sessions(h: &mut Harness<'static, App>) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while h.state().sessions.iter().any(Session::is_running) {
            assert!(
                std::time::Instant::now() < deadline,
                "fake client did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
            h.step();
        }
        h.run_steps(2);
    }

    #[test]
    fn groups_are_an_accordion() {
        let env = TestEnv::new("accordion");
        let mut h = env.harness();
        assert!(has_label(&h, "Alpha") && has_label(&h, "Beta"));

        // Clicking a group's name collapses it…
        h.get_by_label("Ungrouped (1)").click();
        h.run_steps(10);
        assert!(!has_label(&h, "Alpha"), "Ungrouped should collapse");
        assert!(has_label(&h, "Beta"));

        // …and opening it again closes the other groups.
        h.get_by_label("Ungrouped (1)").click();
        h.run_steps(10);
        assert!(has_label(&h, "Alpha"));
        assert!(
            !has_label(&h, "Beta"),
            "opening a group should close the others"
        );

        // With the accordion off, groups open and close independently.
        h.state_mut().config.settings.accordion = false;
        h.get_by_label("Work (1)").click();
        h.run_steps(10);
        assert!(has_label(&h, "Alpha") && has_label(&h, "Beta"));

        // Searching shows every match, even in collapsed groups.
        h.get_by_label("Work (1)").click();
        h.run_steps(10);
        assert!(!has_label(&h, "Beta"));
        h.state_mut().search = "beta".into();
        h.run_steps(10);
        assert!(
            has_label(&h, "Beta"),
            "search should reveal collapsed matches"
        );
        h.state_mut().search.clear();
        h.run_steps(10);
        assert!(
            !has_label(&h, "Beta"),
            "search must not change what was collapsed"
        );
    }

    #[test]
    fn favourites_and_recent() {
        let env = TestEnv::new("favourites");
        let mut h = env.harness();
        assert!(!has_label(&h, "★ Favourites") && !has_label(&h, "🕘 Recent"));

        select_alpha(&mut h);
        h.get_by_label("Favourite").click();
        h.run_steps(3);
        assert!(h.state().config.connections[0].favorite);
        assert!(!h.state().conn_dirty(), "starring saves immediately");
        let saved = Config::load(&env.config_path()).unwrap();
        assert!(
            saved
                .connections
                .iter()
                .any(|c| c.name == "Alpha" && c.favorite)
        );
        assert!(has_label(&h, "★ Favourites"));
        let menu = {
            let (f, r) = h.state().favourites_and_recent();
            (ids(&f), ids(&r))
        };
        assert_eq!(menu.0, [h.state().config.connections[0].id]);

        // Connecting makes Beta "recent" (Alpha is a favourite, so not listed twice).
        h.state_mut().connect_target("Beta");
        h.run_steps(2);
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(3);
        wait_for_sessions(&mut h);
        assert!(has_label(&h, "🕘 Recent"));
        let (_, recent) = h.state().favourites_and_recent();
        assert_eq!(names(&recent), ["Beta"]);
        let saved = Config::load(&env.config_path()).unwrap();
        assert!(
            saved
                .connections
                .iter()
                .any(|c| c.name == "Beta" && c.last_used.is_some())
        );
    }

    fn ids(list: &[&Connection]) -> Vec<Uuid> {
        list.iter().map(|c| c.id).collect()
    }

    fn names<'a>(list: &[&'a Connection]) -> Vec<&'a str> {
        list.iter().map(|c| c.name.as_str()).collect()
    }

    #[test]
    fn quick_connect() {
        let env = TestEnv::new("quick");
        let mut h = env.harness();
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::L);
        h.run_steps(2);
        h.input_mut()
            .events
            .push(egui::Event::Text("CORP\\bob@10.0.0.9:3390".into()));
        h.run_steps(2);
        assert_eq!(
            h.state().quick,
            "CORP\\bob@10.0.0.9:3390",
            "Ctrl+L focuses quick connect"
        );
        h.key_press(KeyCode::Enter);
        h.run_steps(3);

        let p = h.state().prompt.as_ref().expect("asks for the password");
        assert_eq!(p.target, "CORP\\bob@10.0.0.9");
        assert!(
            p.save_to.is_none(),
            "quick connections can't save passwords"
        );
        assert!(!has_label(&h, "Save in keyring"));
        h.key_press(KeyCode::Enter);
        h.run_steps(3);
        assert_eq!(h.state().sessions.len(), 1);
        let cmd = &h.state().sessions[0].command;
        assert!(
            cmd.contains("/v:10.0.0.9") && cmd.contains("/port:3390"),
            "{cmd}"
        );
        assert!(cmd.contains("/u:bob") && cmd.contains("/d:CORP"), "{cmd}");
        assert_eq!(h.state().config.connections.len(), 2, "nothing is saved");
        wait_for_sessions(&mut h);

        // A saved connection's name works too.
        h.state_mut().quick = "alpha".into();
        h.state_mut().actions.push(Action::QuickConnect);
        h.run_steps(3);
        assert_eq!(h.state().prompt.as_ref().unwrap().conn.name, "Alpha");
    }

    #[test]
    fn group_credentials_in_prompt() {
        let env = TestEnv::new("groupcreds");
        let mut h = env.harness();
        // Beta has no username, so it uses group Work's (svc, domain CORP).
        h.state_mut().connect_target("Beta");
        h.run_steps(3);
        let p = h
            .state()
            .prompt
            .as_ref()
            .expect("asks for the group password");
        assert_eq!(p.target, "CORP\\svc@127.0.0.2");
        assert!(matches!(&p.save_to, Some((Key::GroupRdp(g), _)) if g == "Work"));
        assert!(has_label(&h, "Save in keyring for group “Work”"));
        h.state_mut().prompt = None;

        // The group editor shows username, domain and password together.
        h.get_by_label("Edit group Work").click();
        h.run_steps(5);
        for (label, value) in [("Username", "svc"), ("Domain", "CORP")] {
            assert!(
                h.query_by(|n| n.role() == Role::TextInput
                    && n.label().as_deref() == Some(label)
                    && n.value().as_deref() == Some(value))
                    .is_some(),
                "group editor should show {label} = {value}"
            );
        }
        assert!(
            h.query_by(|n| n.label().as_deref() == Some("Group password"))
                .is_some()
        );
    }

    #[test]
    fn tags_and_notes() {
        let env = TestEnv::new("tags");
        let mut h = env.harness();
        select_alpha(&mut h);
        h.get_by_label("Notes").click(); // expand the section
        h.run_steps(3);
        h.get_by(|n| n.role() == Role::TextInput && n.label().as_deref() == Some("Tags"))
            .focus();
        h.run_steps(2);
        h.input_mut()
            .events
            .push(egui::Event::Text("prod, #SQL, prod".into()));
        h.run_steps(2);
        assert_eq!(h.state().draft.as_ref().unwrap().conn.tags, ["prod", "SQL"]);
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::S);
        h.run_steps(3);
        let saved = Config::load(&env.config_path()).unwrap();
        assert_eq!(saved.connections[0].tags, ["prod", "SQL"]);

        h.state_mut().search = "#sql".into();
        h.run_steps(5);
        assert!(has_label(&h, "#prod #SQL"), "tags are shown in the list");
        assert!(!has_label(&h, "Beta"), "#tag search matches tags only");
    }

    #[test]
    fn commands_from_tray_and_other_launches() {
        let env = TestEnv::new("commands");
        let mut h = env.harness();
        // `xrdp-gui --connect Alpha` while running.
        h.state().bus.send(Command::Connect {
            target: "Alpha".into(),
            token: None,
        });
        h.run_steps(3);
        assert_eq!(h.state().prompt.as_ref().unwrap().conn.name, "Alpha");
        h.state_mut().prompt = None;

        // While the window is closed to the tray: show, connect (needs the window for
        // the password prompt) and quit.
        let app = h.state_mut();
        app.exit = Exit::Hide;
        app.bus.send(Command::Show {
            token: Some("t1".into()),
        });
        assert!(matches!(app.run_hidden(), Next::Show(Some(t)) if t == "t1"));

        app.exit = Exit::Hide;
        app.bus.send(Command::Connect {
            target: "Beta".into(),
            token: None,
        });
        assert!(matches!(app.run_hidden(), Next::Show(None)));
        assert_eq!(app.prompt.as_ref().unwrap().conn.name, "Beta");

        app.exit = Exit::Hide;
        app.bus.send(Command::Quit);
        assert!(matches!(app.run_hidden(), Next::Quit));

        app.exit = Exit::Quit;
        assert!(matches!(app.run_hidden(), Next::Quit));
    }

    #[test]
    fn clear_ended_keeps_the_shown_log() {
        let env = TestEnv::new("clearended");
        let slow = env.dir.join("slow-freerdp");
        std::fs::write(&slow, "#!/bin/sh\ncat >/dev/null\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut h = env.harness();
        let fake = h.state().config.settings.client.clone();
        // Three sessions; the middle one keeps running.
        let alpha = h.state().config.connections[0].id;
        for client in [&fake, &slow.to_string_lossy().into_owned(), &fake] {
            h.state_mut().config.settings.client = client.clone();
            h.state_mut().connect_anyway(alpha);
            h.state_mut().actions.push(Action::Launch);
            h.run_steps(2);
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while h.state().sessions.iter().filter(|s| s.is_running()).count() > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "fake clients did not exit"
            );
            std::thread::sleep(Duration::from_millis(20));
            h.step();
        }
        let app = h.state_mut();
        let running = app.sessions[1].started;
        app.log_session = Some(1);
        app.actions.push(Action::ClearEnded);
        h.run_steps(2);
        let app = h.state();
        assert_eq!(app.sessions.len(), 1);
        assert_eq!(
            app.log_session,
            Some(0),
            "the running session's log stays open"
        );
        assert_eq!(app.sessions[0].started, running);
        h.state_mut().actions.push(Action::Stop(0));
        wait_for_sessions(&mut h);

        // The log of a cleared session closes rather than showing another one.
        let app = h.state_mut();
        app.log_session = Some(0);
        app.actions.push(Action::ClearEnded);
        h.run_steps(2);
        assert!(h.state().sessions.is_empty() && h.state().log_session.is_none());
    }

    #[test]
    fn quitting_saves_pending_edits() {
        let env = TestEnv::new("quitsave");
        let mut h = env.harness();
        select_alpha(&mut h);
        h.state_mut().draft.as_mut().unwrap().conn.name = "Alpha edited".into();
        h.state_mut().actions.push(Action::AskQuit);
        h.run_steps(2);
        assert!(!h.state().confirm_quit, "saved, so nothing to confirm");
        let saved = Config::load(&env.config_path()).unwrap();
        assert!(saved.connections.iter().any(|c| c.name == "Alpha edited"));

        // If the edits can't be saved, quitting asks first.
        let env = TestEnv::new("quitfail");
        let mut h = env.harness();
        select_alpha(&mut h);
        let app = h.state_mut();
        app.load_error = Some("broken".into());
        app.draft.as_mut().unwrap().conn.name = "Lost".into();
        app.actions.push(Action::AskQuit);
        h.run_steps(3);
        assert!(h.state().confirm_quit);
        assert!(has_label(&h, "Quit without saving"));
        assert!(has_label(&h, "couldn't be saved"));
    }

    #[test]
    fn asks_for_a_gateway_password() {
        let env = TestEnv::new("gateway");
        let mut h = env.harness();
        let alpha = h.state().config.connections[0].id;
        let conn = &mut h.state_mut().config.connections[0];
        conn.gateway = GatewayMode::On;
        conn.gateway_host = "gw.example".into();
        conn.gateway_same_credentials = false;
        conn.gateway_username = "gwuser".into();
        h.state_mut().connect(alpha);
        h.run_steps(3);
        let p = h.state().prompt.as_ref().expect("asks for passwords");
        let g = p.gateway.as_ref().expect("asks for the gateway password");
        assert_eq!(g.target, "gwuser@gw.example");
        assert!(matches!(&g.save_to, Some((Key::Gateway(id), _)) if *id == alpha));
        assert!(has_label(&h, "Gateway gwuser@gw.example"));

        let p = h.state_mut().prompt.as_mut().unwrap();
        p.password = "pw".into();
        p.gateway.as_mut().unwrap().password = "gwpw".into();
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(2);
        let cmd = &h.state().sessions[0].command;
        assert!(
            cmd.contains("/gateway:g:gw.example,u:gwuser,p:***") && cmd.contains("/p:***"),
            "{cmd}"
        );
        wait_for_sessions(&mut h);
    }

    #[test]
    fn failed_keyring_save_is_reported() {
        let env = TestEnv::new("keyringfail");
        let mut h = env.harness();
        select_alpha(&mut h);
        let alpha = h.state().config.connections[0].id;
        // As if saving Alpha's password had succeeded here but failed in the keyring.
        h.state_mut().config.connections[0].has_saved_password = true;
        h.state_mut()
            .draft
            .as_mut()
            .unwrap()
            .conn
            .has_saved_password = true;
        h.state()
            .keyring_done
            .lock()
            .unwrap()
            .push(KeyringDone::Failed(
                Some(Key::Rdp(alpha)),
                anyhow::anyhow!("keyring is locked"),
            ));
        h.run_steps(2);
        let app = h.state();
        assert!(!app.config.connections[0].has_saved_password);
        assert!(!app.draft.as_ref().unwrap().conn.has_saved_password);
        assert!(
            app.notice
                .as_ref()
                .is_some_and(|(m, err)| *err && m.contains("locked"))
        );
        let saved = Config::load(&env.config_path()).unwrap();
        assert!(!saved.connections[0].has_saved_password);
    }

    #[test]
    fn host_checks_follow_config_changes() {
        let env = TestEnv::new("probeversion");
        let mut h = env.harness();
        let seen = h.state().probed_version;
        assert!(seen.is_some());
        h.run_steps(3);
        assert_eq!(
            h.state().probed_version,
            seen,
            "unchanged config: no rebuild"
        );
        let id = h.state().config.connections[0].id;
        h.state_mut().actions.push(Action::ToggleFavorite(id));
        h.run_steps(2);
        assert_ne!(h.state().probed_version, seen);
    }

    #[test]
    fn certificate_manager_opens() {
        let env = TestEnv::new("certs");
        let mut h = env.harness();
        h.get_by_label("🔒 Certificates").click();
        h.run_steps(3);
        assert!(h.state().known_certs.is_some());
        assert!(has_label(&h, "Trusted server certificates"));
        // The grid takes a couple of frames to settle its layout.
        h.run_steps(5);
        h.get_by_label("Close").click();
        h.run_steps(3);
        assert!(h.state().known_certs.is_none());
    }

    /// A certificate as the window would list it, with made-up names of the given length.
    fn sample_cert(host: &str, subject: &str) -> KnownCert {
        KnownCert {
            path: PathBuf::from(format!("/nonexistent/{host}_3389.pem")),
            host: host.into(),
            port: 3389,
            subject: subject.into(),
            issuer: subject.into(),
            expires: None,
            fingerprint: vec!["AB"; 32].join(":"),
            error: None,
        }
    }

    #[test]
    fn certificate_list_fills_the_window() {
        let env = TestEnv::new("certwidth");
        let mut h = env.harness();
        let long = "a-very-long-name-for-a-server.with.several.parts.example.org.".repeat(2);
        h.state_mut().known_certs =
            Some(vec![sample_cert("pc1", "PC1"), sample_cert(&long, &long)]);
        h.run_steps(5);

        let window_left = h.get_by_label("Trusted server certificates").rect().min.x;
        let window_right = window_left + 720.0;
        for host in ["pc1", long.as_str()] {
            let forget = h
                .get_by_label(&format!("Forget certificate for {host}"))
                .rect();
            assert!(
                forget.max.x > window_right - 30.0 && forget.max.x <= window_right + 1.0,
                "the {host} row should reach the right edge of the window: {forget:?}, \
                 window {window_left}..{window_right}"
            );
        }
    }

    fn pending_restore(backup: Backup) -> PendingRestore {
        PendingRestore {
            backup,
            file: "/nonexistent/backup.toml".into(),
        }
    }

    fn files_before_restore(env: &TestEnv) -> Vec<PathBuf> {
        std::fs::read_dir(&env.dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.to_string_lossy().contains("before-restore-"))
            .collect()
    }

    #[test]
    fn backup_window_opens_from_the_top_bar_and_closes() {
        let env = TestEnv::new("backupwindow");
        let mut h = env.harness();
        h.get_by_label("💾 Backup").click();
        h.run_steps(3);
        assert!(h.state().backup_open);
        assert!(has_label(&h, "Passwords and trusted certificates are not"));
        h.get_by_label("Close").click();
        h.run_steps(3);
        assert!(!h.state().backup_open);
    }

    #[test]
    fn adding_from_a_backup_keeps_what_is_here_and_is_saved() {
        let env = TestEnv::new("restoreadd");
        let mut h = env.harness();
        let mut backup = Backup::of(&h.state().config);
        backup.connections[0].notes = "from the backup".into();
        backup.connections.push(Connection {
            name: "Gamma".into(),
            host: "gamma.example.org".into(),
            ..Default::default()
        });
        h.state_mut().restore = Some(pending_restore(backup));
        h.run_steps(3);
        assert!(has_label(&h, "Adds 1 connection and 0 groups"));

        h.get_by_role_and_label(Role::Button, "Add what's missing")
            .click();
        h.run_steps(3);

        assert!(h.state().restore.is_none());
        let saved = Config::load(&env.config_path()).unwrap();
        assert_eq!(saved.connections.len(), 3);
        assert_ne!(saved.connections[0].notes, "from the backup");
        assert!(saved.connections.iter().any(|c| c.name == "Gamma"));
        assert!(files_before_restore(&env).is_empty(), "nothing was at risk");
    }

    #[test]
    fn replacing_keeps_a_restorable_copy_and_drops_a_removed_selection() {
        let env = TestEnv::new("restorereplace");
        let mut h = env.harness();
        let original = h.state().config.connections.clone();
        let (alpha, beta) = (original[0].id, original[1].id);
        let mut backup = Backup::of(&h.state().config);
        backup.connections.retain(|c| c.id == alpha);
        backup.settings.accordion = !h.state().config.settings.accordion;
        h.state_mut().actions.push(Action::Select(beta));
        h.run_steps(2);
        h.state_mut().restore = Some(pending_restore(backup));
        h.run_steps(3);
        assert!(has_label(&h, "This removes 1 connection and 0 groups"));

        h.get_by_role_and_label(Role::Button, "Replace everything")
            .click();
        h.run_steps(3);

        let saved = Config::load(&env.config_path()).unwrap();
        assert_eq!(saved.connections.len(), 1);
        assert_eq!(saved.connections[0].id, alpha);
        assert!(h.state().draft.is_none(), "the selected connection is gone");
        assert_eq!(
            saved.settings.accordion,
            h.state().config.settings.accordion
        );

        let kept = files_before_restore(&env);
        assert_eq!(kept.len(), 1);
        let kept = Backup::read(&kept[0]).unwrap();
        assert_eq!(kept.connections.len(), 2, "the copy holds the old setup");
        assert!(kept.connections.iter().any(|c| c.id == beta));
    }

    #[test]
    fn pending_edits_are_saved_before_a_restore_uses_them() {
        let env = TestEnv::new("restoreedits");
        let mut h = env.harness();
        let backup = Backup::of(&h.state().config);
        let alpha = h.state().config.connections[0].id;
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        h.state_mut().draft.as_mut().unwrap().conn.notes = "typed just now".into();
        h.state_mut().restore = Some(pending_restore(backup));
        h.run_steps(3);
        h.state_mut()
            .actions
            .push(Action::Restore(RestoreMode::Replace));
        h.run_steps(3);

        // The backup wins, but the edit is in the copy kept first.
        assert_ne!(h.state().find(alpha).unwrap().notes, "typed just now");
        assert_ne!(
            h.state().draft.as_ref().unwrap().conn.notes,
            "typed just now"
        );
        let kept = Backup::read(&files_before_restore(&env)[0]).unwrap();
        assert_eq!(kept.connections[0].notes, "typed just now");
    }

    #[test]
    fn a_config_that_failed_to_load_can_be_replaced_but_not_backed_up() {
        let env = TestEnv::new("restorebroken");
        let backup = Backup::of(&Config::load(&env.config_path()).unwrap());
        std::fs::write(env.config_path(), "this is = = broken").unwrap();
        let mut h = env.harness();
        assert!(h.state().load_error.is_some());

        h.state_mut().actions.push(Action::Backup);
        h.run_steps(2);
        assert!(h.state().notice.as_ref().is_some_and(|(_, err)| *err));
        assert_eq!(
            std::fs::read_to_string(env.config_path()).unwrap(),
            "this is = = broken"
        );

        h.state_mut().restore = Some(pending_restore(backup.clone()));
        h.run_steps(3);
        assert!(
            h.query_by_role_and_label(Role::Button, "Add what's missing")
                .is_none()
        );
        h.get_by_role_and_label(Role::Button, "Replace everything")
            .click();
        h.run_steps(3);

        assert!(h.state().load_error.is_none());
        let saved = Config::load(&env.config_path()).unwrap();
        assert_eq!(saved.connections.len(), backup.connections.len());
        let kept = &files_before_restore(&env)[0];
        assert_eq!(
            std::fs::read_to_string(kept).unwrap(),
            "this is = = broken",
            "the broken file is kept for repairing by hand"
        );
    }

    #[test]
    fn a_warning_shows_for_a_backup_that_changes_safety_settings() {
        let env = TestEnv::new("restorerisky");
        let mut h = env.harness();
        let mut backup = Backup::of(&h.state().config);
        h.state_mut().restore = Some(pending_restore(backup.clone()));
        h.run_steps(3);
        assert!(!has_label(&h, "trust where the file came from"));

        backup.connections[0].extra_args = "/drive:all,/".into();
        h.state_mut().restore = Some(pending_restore(backup));
        h.run_steps(3);
        assert!(has_label(&h, "1 entry uses"));
        assert!(has_label(&h, "trust where the file came from"));
    }

    /// Makes the first connection SSH, with a terminal that records what it was asked to
    /// run and then stays open until told to end.
    fn use_ssh(env: &TestEnv, h: &mut Harness<'static, App>) -> (Uuid, PathBuf) {
        let seen = env.dir.join("terminal-args");
        let terminal = env.dir.join("fake-terminal");
        std::fs::write(
            &terminal,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do echo \"[$a]\" >> '{}'; done\nexec sleep 30\n",
                seen.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&terminal, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = h.state_mut();
        state.config.settings.terminal = terminal.to_string_lossy().into_owned();
        let c = &mut state.config.connections[0];
        c.protocol = Protocol::Ssh;
        c.host = "pc1".into();
        c.port = 2222;
        c.username = "bob".into();
        c.new_window = true;
        (c.id, seen)
    }

    fn wait_for_file(path: &std::path::Path) -> String {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Ok(text) = std::fs::read_to_string(path)
                && text.contains("[--]")
            {
                return text;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("the terminal didn't start");
    }

    #[test]
    fn ssh_opens_a_terminal_without_asking_for_a_password() {
        let env = TestEnv::new("sshlaunch");
        let mut h = env.harness();
        let (id, seen) = use_ssh(&env, &mut h);

        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(3);

        assert!(h.state().prompt.is_none(), "ssh asks in the terminal");
        let args = wait_for_file(&seen);
        assert!(
            args.ends_with("[ssh]\n[-p]\n[2222]\n[-l]\n[bob]\n[--]\n[pc1]\n"),
            "{args}"
        );
        assert!(h.state().sessions[0].is_running());
        assert_eq!(h.state().sessions[0].command, "ssh -p 2222 -l bob -- pc1");

        // A second SSH session is fine, so it isn't questioned.
        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(3);
        assert!(h.state().confirm_second.is_none());
        assert_eq!(h.state().sessions.len(), 2);

        for i in 0..2 {
            h.state_mut().actions.push(Action::Stop(i));
        }
        h.run_steps(2);
        wait_for_sessions(&mut h);
        let Status::Exited(d) = &h.state().sessions[0].status else {
            panic!("still running");
        };
        assert_eq!(d.title, "Disconnected");
    }

    /// Makes the first connection SSH inside the main window, with `script` for `ssh`.
    fn use_ssh_in_main_window(env: &TestEnv, h: &mut Harness<'static, App>, script: &str) -> Uuid {
        let fake = env.dir.join("fake-ssh");
        std::fs::write(&fake, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let state = h.state_mut();
        state.ssh_program = fake.to_string_lossy().into_owned();
        let c = &mut state.config.connections[0];
        c.protocol = Protocol::Ssh;
        c.host = "pc1".into();
        c.id
    }

    fn wait_until(h: &mut Harness<'static, App>, what: &str, done: impl Fn(&App) -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !done(h.state()) {
            assert!(std::time::Instant::now() < deadline, "timed out: {what}");
            h.step();
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn ssh_opens_in_the_main_window_and_takes_the_keyboard() {
        let env = TestEnv::new("sshhere");
        let mut h = env.harness();
        let seen = env.dir.join("typed");
        let id = use_ssh_in_main_window(
            &env,
            &mut h,
            &format!(
                "read -r line; echo \"$line\" > '{}'; exit 0",
                seen.display()
            ),
        );
        h.state_mut().actions.push(Action::Select(id));
        h.run_steps(2);
        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(3);

        assert!(h.state().prompt.is_none());
        let uid = h.state().sessions[0].uid;
        assert_eq!(h.state().active_session, Some(uid));
        assert!(
            h.query_by_label("Connection").is_some(),
            "the tab back to the form"
        );
        assert!(!has_label(&h, "Display"), "the terminal replaces the form");
        h.run_steps(3);

        // Ctrl+N belongs to the remote machine now, not to "new connection".
        h.key_press_modifiers(Modifiers::CTRL, KeyCode::N);
        h.run_steps(2);
        assert!(!h.state().draft.as_ref().is_some_and(|d| d.is_new));

        h.event(egui::Event::Text("hello".into()));
        h.key_press(KeyCode::Enter);
        h.run_steps(2);
        wait_until(&mut h, "the program to end", |app| {
            !app.sessions[0].is_running()
        });
        // Ctrl+N (0x0e) came first, then the text.
        assert_eq!(std::fs::read(&seen).unwrap(), b"\x0ehello\n");

        // Its screen stays until closed, which also goes back to the form.
        assert_eq!(h.state().active_session, Some(uid));
        h.run_steps(2);
        assert!(has_label(&h, "Connect again"));
        h.state_mut().actions.push(Action::Dismiss(0));
        h.run_steps(3);
        assert!(h.state().active_session.is_none());
        assert!(has_label(&h, "General"));
    }

    #[test]
    fn switching_tabs_and_selecting_a_connection_leave_a_session_running() {
        let env = TestEnv::new("sshtabs");
        let mut h = env.harness();
        let id = use_ssh_in_main_window(&env, &mut h, "exec sleep 30");
        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(3);
        let uid = h.state().sessions[0].uid;

        let other = h.state().config.connections[1].id;
        h.state_mut().actions.push(Action::Select(other));
        h.run_steps(3);
        assert!(h.state().active_session.is_none());
        assert!(h.state().sessions[0].is_running());

        h.state_mut().actions.push(Action::ShowSession(Some(uid)));
        h.run_steps(3);
        assert_eq!(h.state().active_session, Some(uid));

        h.state_mut().actions.push(Action::Stop(0));
        h.run_steps(2);
        wait_until(&mut h, "the session to end", |app| {
            !app.sessions[0].is_running()
        });
        let Status::Exited(d) = &h.state().sessions[0].status else {
            panic!("still running");
        };
        assert_eq!(d.title, "Disconnected");
    }

    #[test]
    fn a_failed_ssh_connection_says_so_and_keeps_its_screen() {
        let env = TestEnv::new("sshfail");
        let mut h = env.harness();
        let id = use_ssh_in_main_window(&env, &mut h, "echo refused; exit 255");
        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(2);
        wait_until(&mut h, "the session to end", |app| {
            !app.sessions[0].is_running()
        });
        let Status::Exited(d) = &h.state().sessions[0].status else {
            panic!("still running");
        };
        assert_eq!(d.severity, Severity::Failed);
        assert!(h.state().active_session.is_some());
    }

    /// With no X11 main window (as here) an RDP session has to use its own.
    #[test]
    fn rdp_uses_its_own_window_when_it_can_not_be_embedded() {
        let env = TestEnv::new("rdpown");
        let mut h = env.harness();
        let id = h.state().config.connections[0].id;
        h.state_mut().actions.push(Action::Connect(id));
        h.run_steps(3);
        if let Some(p) = h.state_mut().prompt.as_mut() {
            p.password = "x".into();
        }
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(3);
        assert!(matches!(h.state().sessions[0].surface, Surface::OwnWindow));
        assert!(h.state().active_session.is_none());
    }

    #[test]
    fn the_open_in_choice_is_saved_per_connection() {
        let env = TestEnv::new("openin");
        let mut h = env.harness();
        let id = h.state().config.connections[0].id;
        h.state_mut().actions.push(Action::Select(id));
        h.run_steps(3);
        assert!(
            !h.state().draft.as_ref().unwrap().conn.new_window,
            "default"
        );
        assert!(!has_label(&h, "Fullscreen"), "the window decides the size");

        h.get_by_role_and_label(Role::RadioButton, "New window")
            .click();
        h.run_steps(3);
        assert!(has_label(&h, "Fullscreen"));
        h.state_mut().actions.push(Action::Save);
        h.run_steps(2);
        let saved = Config::load(&env.config_path()).unwrap();
        assert!(saved.connections[0].new_window);
        assert!(!saved.connections[1].new_window);
    }

    #[test]
    fn ssh_ignores_a_groups_gateway_and_saved_password() {
        let env = TestEnv::new("sshgroup");
        let mut h = env.harness();
        let state = h.state_mut();
        state.config.groups[0].gateway_enabled = true;
        state.config.groups[0].gateway_host = "gw.example.org".into();
        state.config.groups[0].has_saved_password = true;
        let c = state
            .config
            .connections
            .iter_mut()
            .find(|c| c.group == "Work")
            .unwrap();
        c.protocol = Protocol::Ssh;
        c.username = String::new();
        let c = c.clone();
        let r = h.state().config.resolve(&c);
        assert!(r.gateway.is_none());
        assert!(r.password_key.is_none());
        assert_eq!(r.username, "svc", "the group's username still applies");
    }

    #[test]
    fn the_form_shows_only_what_ssh_uses_and_switching_changes_the_default_port() {
        let env = TestEnv::new("sshform");
        let mut h = env.harness();
        let alpha = h.state().config.connections[0].id;
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(3);
        assert!(has_label(&h, "Display"));
        assert!(has_label(&h, "Domain"));

        h.get_by_role_and_label(Role::RadioButton, "SSH").click();
        h.run_steps(3);
        assert_eq!(h.state().draft.as_ref().unwrap().conn.port, 22);
        assert!(!has_label(&h, "Display"));
        assert!(!has_label(&h, "Domain"));
        assert!(!has_label(&h, "Gateway"));

        // A port chosen by hand stays when switching.
        h.state_mut().draft.as_mut().unwrap().conn.port = 2222;
        h.run_steps(2);
        h.get_by_role_and_label(Role::RadioButton, "RDP").click();
        h.run_steps(3);
        assert_eq!(h.state().draft.as_ref().unwrap().conn.port, 2222);
        assert!(has_label(&h, "Display"));
    }

    /// Replaces the connection's client with one that runs until it is stopped.
    fn use_slow_client(env: &TestEnv, h: &mut Harness<'static, App>) {
        let slow = env.dir.join("slow-freerdp");
        std::fs::write(&slow, "#!/bin/sh\ncat >/dev/null\nexec sleep 30\n").unwrap();
        std::fs::set_permissions(&slow, std::fs::Permissions::from_mode(0o755)).unwrap();
        h.state_mut().config.settings.client = slow.to_string_lossy().into_owned();
    }

    #[test]
    fn new_connection_without_a_host_can_be_left() {
        let env = TestEnv::new("leavenew");
        let mut h = env.harness();
        let alpha = h.state().config.connections[0].id;

        // Untouched: dropped without comment.
        h.state_mut().actions.push(Action::NewConnection);
        h.run_steps(2);
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        assert_eq!(h.state().draft.as_ref().unwrap().conn.id, alpha);
        assert!(h.state().notice.is_none());

        // Edited: dropped, and says so.
        h.state_mut().actions.push(Action::NewConnection);
        h.run_steps(2);
        h.state_mut().draft.as_mut().unwrap().conn.name = "Mine".into();
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        assert_eq!(h.state().draft.as_ref().unwrap().conn.id, alpha);
        assert!(has_label(&h, "Discarded the new connection"));

        // Discard works from the button, and quitting isn't held up by one either.
        h.state_mut().actions.push(Action::NewConnection);
        h.run_steps(3);
        h.get_by_label("✕ Discard").click();
        h.run_steps(3);
        assert!(h.state().draft.is_none());
        h.state_mut().actions.push(Action::NewConnection);
        h.run_steps(2);
        h.state_mut().actions.push(Action::AskQuit);
        h.run_steps(2);
        assert!(!h.state().confirm_quit);
        assert_eq!(
            Config::load(&env.config_path()).unwrap().connections.len(),
            2
        );

        // With a host, leaving saves it as before.
        h.state_mut().allow_close = false;
        h.state_mut().actions.push(Action::NewConnection);
        h.run_steps(2);
        h.state_mut().draft.as_mut().unwrap().conn.host = "pc9".into();
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        assert_eq!(
            Config::load(&env.config_path()).unwrap().connections.len(),
            3
        );
    }

    #[test]
    fn new_group_is_only_saved_if_touched() {
        let env = TestEnv::new("leavegroup");
        let mut h = env.harness();
        let alpha = h.state().config.connections[0].id;
        let groups = |env: &TestEnv| Config::load(&env.config_path()).unwrap().groups.len();

        h.state_mut().actions.push(Action::NewGroup);
        h.run_steps(2);
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        assert_eq!(groups(&env), 1, "an untouched new group isn't saved");

        h.state_mut().actions.push(Action::NewGroup);
        h.run_steps(3);
        h.get_by_label("✕ Discard").click();
        h.run_steps(3);
        assert!(h.state().group_draft.is_none());

        // Saving explicitly works even with nothing changed…
        h.state_mut().actions.push(Action::NewGroup);
        h.run_steps(2);
        h.key_press_modifiers(Modifiers::COMMAND, KeyCode::S);
        h.run_steps(3);
        assert_eq!(groups(&env), 2);

        // …and a change is saved on leaving.
        h.state_mut().actions.push(Action::NewGroup);
        h.run_steps(2);
        h.state_mut().group_draft.as_mut().unwrap().group.domain = "CORP".into();
        h.state_mut().actions.push(Action::Select(alpha));
        h.run_steps(2);
        assert_eq!(groups(&env), 3);

        // Names that would share a keyring entry are refused.
        h.state_mut().actions.push(Action::NewGroup);
        h.run_steps(2);
        h.state_mut().group_draft.as_mut().unwrap().group.name = "Work:gateway".into();
        h.state_mut().actions.push(Action::Save);
        h.run_steps(2);
        assert_eq!(groups(&env), 3);
        assert!(has_label(&h, "can't end in"));
    }

    #[test]
    fn second_session_asks_first() {
        let env = TestEnv::new("second");
        let mut h = env.harness();
        use_slow_client(&env, &mut h);
        h.state_mut().connect_target("Alpha");
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(2);
        assert_eq!(h.state().sessions.len(), 1);

        h.state_mut().connect_target("Alpha");
        h.run_steps(3);
        assert!(
            h.state().prompt.is_none(),
            "doesn't get as far as a password"
        );
        assert!(has_label(&h, "already has a session running"));
        h.get_by_label("Cancel").click();
        h.run_steps(3);
        assert!(h.state().confirm_second.is_none());
        assert_eq!(h.state().sessions.len(), 1);

        h.state_mut().connect_target("Alpha");
        h.run_steps(3);
        h.get_by_label("Connect anyway").click();
        h.run_steps(3);
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(2);
        assert_eq!(h.state().sessions.len(), 2);

        // From the tray the question brings the window back.
        let app = h.state_mut();
        app.exit = Exit::Hide;
        app.bus.send(Command::Connect {
            target: "Alpha".into(),
            token: None,
        });
        assert!(matches!(app.run_hidden(), Next::Show(None)));
        assert!(app.confirm_second.is_some());
    }

    #[test]
    fn tray_quit_asks_about_running_sessions() {
        let env = TestEnv::new("trayquit");
        let mut h = env.harness();
        use_slow_client(&env, &mut h);
        h.state_mut().connect_target("Alpha");
        h.state_mut().actions.push(Action::Launch);
        h.run_steps(2);

        let app = h.state_mut();
        app.exit = Exit::Hide;
        app.bus.send(Command::Quit);
        assert!(matches!(app.run_hidden(), Next::Show(None)));
        assert!(app.confirm_quit);
        assert!(app.sessions[0].is_running(), "still connected");
        h.run_steps(3);
        assert!(has_label(&h, "1 session(s) are still running"));
    }

    #[test]
    fn hidden_commands_are_all_handled() {
        let env = TestEnv::new("hiddencmds");
        let mut h = env.harness();
        let app = h.state_mut();
        app.exit = Exit::Hide;
        app.bus.send(Command::Show { token: None });
        app.bus.send(Command::Connect {
            target: "Alpha".into(),
            token: None,
        });
        assert!(matches!(app.run_hidden(), Next::Show(None)));
        assert!(app.prompt.is_some(), "the request after Show isn't lost");

        // Closing the window cancels the question rather than reopening for it.
        app.hide_to_tray();
        app.bus.send(Command::Quit);
        assert!(matches!(app.run_hidden(), Next::Quit));
        assert!(app.prompt.is_none());
    }

    #[test]
    fn shortcuts_wait_for_the_certificate_window() {
        let env = TestEnv::new("certmodal");
        let mut h = env.harness();
        select_alpha(&mut h);
        h.state_mut().actions.push(Action::OpenCertificates);
        h.run_steps(3);
        h.key_press(KeyCode::Delete);
        h.run_steps(3);
        assert!(h.state().confirm_delete.is_none());
        h.key_press(KeyCode::Enter);
        h.run_steps(3);
        assert!(h.state().prompt.is_none());
    }

    #[test]
    fn forgetting_a_certificate_confirms_and_then_asks() {
        let env = TestEnv::new("forgetcert");
        let mut h = env.harness();
        let cert = env.dir.join("pc1_3389.pem");
        std::fs::write(&cert, include_str!("../tests/data/test-cert.pem")).unwrap();
        let fingerprint = certs::read(&cert).fingerprint;
        h.state_mut().actions.push(Action::AskForgetKnownCert {
            host: "PC1".into(),
            port: 3389,
            path: cert.clone(),
            fingerprint: fingerprint.clone(),
        });
        h.run_steps(5);
        assert!(has_label(&h, "Forget this certificate?"));
        assert!(has_label(&h, &fingerprint), "shows what is being forgotten");
        assert!(cert.exists(), "nothing happens before confirming");

        h.get_by_label("Forget").click();
        h.run_steps(3);
        assert!(!cert.exists());
        let saved = Config::load(&env.config_path()).unwrap();
        assert_eq!(
            saved.cert_review,
            [CertReview {
                host: "pc1".into(),
                port: 3389
            }]
        );

        // The next connection to it doesn't use trust on first use, so FreeRDP asks.
        let conn = Connection {
            host: "pc1".into(),
            ..Default::default()
        };
        assert_eq!(h.state().config.resolve(&conn).cert, CertPolicy::Ask);
    }

    #[test]
    fn quick_connect_parsing() {
        let c = parse_quick(" rdp://CORP\\bob@[::1]:3390 ").unwrap();
        assert_eq!(
            (
                c.domain.as_str(),
                c.username.as_str(),
                c.host.as_str(),
                c.port
            ),
            ("CORP", "bob", "::1", 3390)
        );
        let c = parse_quick("pc1").unwrap();
        assert_eq!(
            (c.username.as_str(), c.host.as_str(), c.port),
            ("", "pc1", 3389)
        );
        assert!(parse_quick("  ").is_none());
        assert!(parse_quick("bob@").is_none());
        assert!(parse_quick("two words").is_none());
    }
}
