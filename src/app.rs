use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use eframe::egui::{self, Color32, Key as KeyCode, KeyboardShortcut, Modifiers, RichText};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::bus::{Bus, Command};
use crate::certs::{self, KnownCert};
use crate::command::{self, Credentials};
use crate::desktop;
use crate::diagnose::{Fix, Severity};
use crate::model::{
    self, CertPolicy, Config, Connection, GatewayMode, Group, Profile, Resolved, Scaling, Settings,
};
use crate::notify;
use crate::probe::{Prober, Reach, Target};
use crate::secrets::{self, Key};
use crate::session::{Session, Status};
use crate::single_instance::Primary;
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
            password: String::new(),
            gateway_password: String::new(),
        }
    }
}

struct PasswordPrompt {
    /// A copy, so quick connections (which aren't saved) work too.
    conn: Connection,
    target: String,
    password: String,
    /// Where "Save in keyring" stores the password and what to call it; `None` for
    /// quick connections.
    save_to: Option<(Key, String)>,
    remember: bool,
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
    ForgetCertificate(Uuid),
    ToggleFavorite(Uuid),
    Connect(Uuid),
    QuickConnect,
    OpenCertificates,
    ForgetKnownCert(PathBuf),
    AskQuit,
    Launch,
    Stop(usize),
    Dismiss(usize),
    ClearEnded,
    SaveSettings,
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
    settings_draft: Option<Settings>,
    confirm_quit: bool,
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
    /// Text of the quick-connect box.
    quick: String,
    /// Quick connections made this run; not saved.
    adhoc: Vec<Connection>,
    /// The certificate manager's list, while it is open.
    known_certs: Option<Vec<KnownCert>>,
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
            settings_draft: None,
            confirm_quit: false,
            allow_close: false,
            notice,
            prober: Prober::new(bus.clone()),
            actions: Vec::new(),
            _instance: instance,
            bus,
            inbox: Arc::default(),
            quick: String::new(),
            adhoc: Vec::new(),
            known_certs: None,
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
        loop {
            self.bus.wait(Duration::from_millis(500));
            self.poll_sessions();
            self.sync_integrations();
            for cmd in self.bus.take() {
                match cmd {
                    Command::Show { token } => return Next::Show(token),
                    Command::Connect { target, token } => {
                        self.connect_target(&target);
                        // A password prompt or an error needs the window.
                        if self.prompt.is_some() || self.notice.as_ref().is_some_and(|n| n.1) {
                            return Next::Show(token);
                        }
                    }
                    Command::Quit => {
                        self.terminate_all();
                        return Next::Quit;
                    }
                }
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
                    self.connect_target(&target);
                    if self.prompt.is_some() {
                        self.bring_to_front(ctx, token);
                    }
                }
                Command::Quit => self.actions.push(Action::AskQuit),
            }
        }
    }

    fn bring_to_front(&mut self, ctx: &egui::Context, token: Option<String>) {
        // Wayland doesn't let a window raise itself, but a new window may take focus
        // with an activation token, so close and reopen.
        if token.is_some() && std::env::var_os("WAYLAND_DISPLAY").is_some() {
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

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let modal_open = self.prompt.is_some()
            || self.confirm_delete.is_some()
            || self.settings_draft.is_some()
            || self.confirm_quit;
        if modal_open {
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
        if save && (self.conn_dirty() || self.group_dirty()) {
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
            g.group != g.original || !g.password.is_empty() || !g.gateway_password.is_empty()
        })
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), false));
    }

    fn error(&mut self, e: anyhow::Error) {
        self.notice = Some((format!("{e:#}"), true));
    }

    fn notify(&self, summary: String, body: String, urgent: bool) {
        if self.config.settings.notifications {
            notify::send(summary, body, urgent);
        }
    }

    fn save_config(&self) -> Result<()> {
        if let Some(e) = &self.load_error {
            bail!("not saving: config failed to load ({e})");
        }
        self.config.save(&self.config_path)
    }

    fn save_draft(&mut self) -> Result<()> {
        let Some(d) = self.draft.as_mut() else {
            return Ok(());
        };
        if d.conn.host.trim().is_empty() {
            bail!("host is required");
        }
        d.conn.group = d.conn.group.trim().to_string();
        if !d.password.is_empty() {
            secrets::set(&Key::Rdp(d.conn.id), &d.password)?;
            d.conn.has_saved_password = true;
            d.password.clear();
        }
        if !d.gateway_password.is_empty() {
            secrets::set(&Key::Gateway(d.conn.id), &d.gateway_password)?;
            d.conn.has_saved_gateway_password = true;
            d.gateway_password.clear();
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
        self.save_config()
    }

    fn save_group(&mut self) -> Result<()> {
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
        g.group.name = new_name.clone();

        // A brand-new group has no old name; don't sweep ungrouped connections into it.
        if new_name != old_name && !old_name.is_empty() {
            // Saved passwords are keyed by group name; move them along.
            let moves = [
                (
                    g.original.has_saved_password && g.password.is_empty(),
                    Key::GroupRdp(old_name.clone()),
                    Key::GroupRdp(new_name.clone()),
                ),
                (
                    g.original.has_saved_gateway_password && g.gateway_password.is_empty(),
                    Key::GroupGateway(old_name.clone()),
                    Key::GroupGateway(new_name.clone()),
                ),
            ];
            for (needed, old_key, new_key) in moves {
                if needed {
                    if let Some(pw) = secrets::get(&old_key)? {
                        secrets::set(&new_key, &pw)?;
                    }
                    secrets::delete(&old_key)?;
                }
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
        if !g.password.is_empty() {
            secrets::set(&Key::GroupRdp(new_name.clone()), &g.password)?;
            g.group.has_saved_password = true;
            g.password.clear();
        }
        if !g.gateway_password.is_empty() {
            secrets::set(&Key::GroupGateway(new_name.clone()), &g.gateway_password)?;
            g.group.has_saved_gateway_password = true;
            g.gateway_password.clear();
        }

        self.config
            .groups
            .retain(|x| x.name != old_name && x.name != new_name);
        self.config.groups.push(g.group.clone());
        self.config.groups.sort_by_key(|x| x.name.to_lowercase());
        g.original = g.group.clone();
        self.save_config()
    }

    /// Saves pending edits before navigating away; returns false if that failed.
    fn commit(&mut self) -> bool {
        let result = if self.conn_dirty() {
            self.save_draft()
        } else if self.group_dirty() {
            self.save_group()
        } else {
            Ok(())
        };
        match result {
            Ok(()) => true,
            Err(e) => {
                self.error(e.context("unsaved changes"));
                false
            }
        }
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
        match action {
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
                if let Some(g) = &mut self.group_draft {
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
                self.config.connections.retain(|c| c.id != id);
                if self.draft.as_ref().is_some_and(|d| d.conn.id == id) {
                    self.draft = None;
                }
                let result = secrets::delete(&Key::Rdp(id))
                    .and_then(|()| secrets::delete(&Key::Gateway(id)))
                    .and_then(|()| self.save_config());
                if let Err(e) = result {
                    self.error(e);
                }
            }
            Action::ClearGroup => {
                let Some(g) = self.group_draft.as_mut() else {
                    return;
                };
                let name = g.original.name.clone();
                self.config.groups.retain(|x| x.name != name);
                *g = GroupDraft::new(&self.config, &name);
                let result = secrets::delete(&Key::GroupGateway(name.clone()))
                    .and_then(|()| secrets::delete(&Key::GroupRdp(name.clone())))
                    .and_then(|()| self.save_config());
                match result {
                    Ok(()) => self.info(format!("Cleared the defaults of “{name}”")),
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
            Action::ForgetCertificate(id) => match self.forget_certificate(id) {
                Ok(msg) => self.info(msg),
                Err(e) => self.error(e),
            },
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
            Action::QuickConnect => {
                let target = std::mem::take(&mut self.quick);
                self.connect_target(&target);
            }
            Action::Launch => self.launch_from_prompt(),
            Action::OpenCertificates => self.known_certs = Some(self.load_certs()),
            Action::ForgetKnownCert(path) => {
                match certs::forget(&path) {
                    Ok(()) => self.info(format!("Forgot {}", path.display())),
                    Err(e) => self.error(e),
                }
                if self.known_certs.is_some() {
                    self.known_certs = Some(self.load_certs());
                }
            }
            Action::AskQuit => {
                if self.sessions.iter().any(Session::is_running) {
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
                let shown = self
                    .log_session
                    .and_then(|i| self.sessions.get(i))
                    .map(|s| s as *const Session);
                self.sessions.retain(Session::is_running);
                self.log_session =
                    shown.and_then(|p| self.sessions.iter().position(|s| std::ptr::eq(s, p)));
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
            Action::Quit => {
                self.terminate_all();
                self.exit = Exit::Quit;
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn forget(&mut self, key: &Key) -> Result<()> {
        secrets::delete(key)?;
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
                        c.has_saved_password = false;
                    } else {
                        c.has_saved_gateway_password = false;
                    }
                }
            }
            Key::GroupRdp(name) => {
                for g in self.config.groups.iter_mut().filter(|g| g.name == *name) {
                    g.has_saved_password = false;
                }
                if let Some(g) = self
                    .group_draft
                    .as_mut()
                    .filter(|g| g.original.name == *name)
                {
                    g.group.has_saved_password = false;
                    g.original.has_saved_password = false;
                }
            }
            Key::GroupGateway(name) => {
                for g in self.config.groups.iter_mut().filter(|g| g.name == *name) {
                    g.has_saved_gateway_password = false;
                }
                if let Some(g) = self
                    .group_draft
                    .as_mut()
                    .filter(|g| g.original.name == *name)
                {
                    g.group.has_saved_gateway_password = false;
                    g.original.has_saved_gateway_password = false;
                }
            }
        }
        self.save_config()
    }

    /// Removes FreeRDP's trust-on-first-use record for a host so a changed certificate
    /// can be accepted again.
    fn forget_certificate(&self, id: Uuid) -> Result<String> {
        let conn = self.find_any(id).context("connection no longer exists")?;
        let file = certs::path_for(&conn.host, conn.port)?;
        match std::fs::remove_file(&file) {
            Ok(()) => Ok(format!(
                "Forgot the saved certificate for {}. Connect again to review and trust the new one.",
                conn.display_name()
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok(format!("No saved certificate found at {}", file.display()))
            }
            Err(e) => Err(e).with_context(|| format!("removing {}", file.display())),
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

    fn connect(&mut self, id: Uuid) {
        if self.draft.as_ref().is_some_and(|d| d.conn.id == id) && !self.commit() {
            return;
        }
        let Some(conn) = self.find_any(id).cloned() else {
            return;
        };
        let saved_conn = self.find(id).is_some();
        let resolved = self.config.resolve(&conn);

        let saved = resolved.password_key.as_ref().and_then(|key| {
            secrets::get(key).unwrap_or_else(|e| {
                self.error(e);
                None
            })
        });
        match saved {
            Some(password) => self.launch(&conn, Some(password)),
            None => {
                let user = match (resolved.domain.as_str(), resolved.username.as_str()) {
                    (_, "") => String::new(),
                    ("", u) => format!("{u}@"),
                    (d, u) => format!("{d}\\{u}@"),
                };
                let save_to = match &resolved.creds_from_group {
                    Some(g) => Some((
                        Key::GroupRdp(g.clone()),
                        format!("Save in keyring for group “{g}”"),
                    )),
                    None if saved_conn => Some((Key::Rdp(id), "Save in keyring".to_string())),
                    None => None,
                };
                self.prompt = Some(PasswordPrompt {
                    target: format!("{user}{}", conn.host.trim()),
                    conn,
                    password: String::new(),
                    save_to,
                    remember: false,
                });
            }
        }
    }

    fn launch_from_prompt(&mut self) {
        let Some(p) = self.prompt.take() else { return };
        if let Some((key, _)) = p.save_to.filter(|_| p.remember && !p.password.is_empty()) {
            match secrets::set(&key, &p.password) {
                Ok(()) => {
                    self.mark_saved(&key);
                    if let Err(e) = self.save_config() {
                        self.error(e);
                    }
                }
                Err(e) => self.error(e),
            }
        }
        // An empty password lets FreeRDP prompt (or use Kerberos/smartcard) itself.
        let password = Some(p.password).filter(|p| !p.is_empty());
        let conn = self.find_any(p.conn.id).cloned().unwrap_or(p.conn);
        self.launch(&conn, password);
    }

    /// Records that a password is now in the keyring under `key`.
    fn mark_saved(&mut self, key: &Key) {
        match key {
            Key::Rdp(id) => {
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
                    c.has_saved_password = true;
                }
            }
            Key::GroupRdp(name) => {
                for g in self.config.groups.iter_mut().filter(|g| g.name == *name) {
                    g.has_saved_password = true;
                }
                if let Some(g) = self
                    .group_draft
                    .as_mut()
                    .filter(|g| g.original.name == *name)
                {
                    g.group.has_saved_password = true;
                    g.original.has_saved_password = true;
                }
            }
            Key::Gateway(_) | Key::GroupGateway(_) => {}
        }
    }

    fn launch(&mut self, conn: &Connection, password: Option<String>) {
        let resolved = self.config.resolve(conn);
        let gateway_password = match &resolved.gateway {
            Some(gw) if !gw.same_credentials => gw.saved_password.as_ref().and_then(|key| {
                secrets::get(key).unwrap_or_else(|e| {
                    self.error(e);
                    None
                })
            }),
            _ => None,
        };
        let creds = Credentials {
            password: password.as_deref(),
            gateway_password: gateway_password.as_deref(),
        };
        let settings = &self.config.settings;
        let result = command::build_args(&resolved, settings, &creds).and_then(|args| {
            Session::spawn(
                &settings.client,
                &args,
                conn.id,
                conn.display_name().to_string(),
                &self.bus,
            )
        });
        match result {
            Ok(session) => {
                self.sessions.push(session);
                self.info(format!("Connecting to {}…", conn.display_name()));
                self.touch(conn.id);
            }
            Err(e) => self.error(e),
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
        let targets = if self.config.settings.probe_hosts {
            self.config
                .connections
                .iter()
                .filter(|c| !c.host.trim().is_empty())
                .map(|c| {
                    // Behind a gateway the host itself is usually not reachable; check the gateway.
                    let (host, port) = match self.config.resolve(c).gateway {
                        Some(gw) if !gw.host.is_empty() => model::split_host_port(&gw.host, 443),
                        _ => (c.host.trim().to_string(), c.port),
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
                if ui
                    .add_enabled(dirty && !d.is_new, egui::Button::new("↺ Revert"))
                    .clicked()
                {
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

                section(ui, "Display", true, |ui| {
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
                                ui.add(egui::DragValue::new(&mut c.width).range(640..=8192))
                                    .accessible_name("Width");
                                ui.label("×");
                                ui.add(egui::DragValue::new(&mut c.height).range(480..=8192))
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
                                    egui::DragValue::new(&mut c.reconnect_retries).range(0..=1000),
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
                    row(ui, "", |ui| ui.checkbox(&mut c.clipboard, "Clipboard"));
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

                section(ui, "Advanced", false, |ui| {
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
                    row(ui, "Extra args", |ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut c.extra_args)
                                .hint_text("e.g. /kbd:layout:0x409")
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
                    password: (c.has_saved_password || !d.password.is_empty()).then_some("x"),
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
                    .add_enabled(dirty, egui::Button::new("💾 Save"))
                    .on_hover_text("Ctrl+S")
                    .on_disabled_hover_text("No unsaved changes (Ctrl+S)")
                    .clicked()
                {
                    actions.push(Action::Save);
                }
                if ui
                    .add_enabled(dirty, egui::Button::new("↺ Revert"))
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
                                "connected {:02}:{:02}:{:02}",
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
                                        "Forget saved certificate",
                                        "Only if you expected the certificate to change",
                                        Action::ForgetCertificate(s.connection_id),
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
            egui::ScrollArea::both()
                .id_salt("session_log")
                .stick_to_bottom(true)
                .auto_shrink(false)
                .show(ui, |ui| {
                    if out.lines.is_empty() {
                        ui.weak("(no output)");
                    }
                    for line in out.lines.iter() {
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
                field.request_focus();
                if let Some((_, label)) = &p.save_to {
                    ui.checkbox(&mut p.remember, label.as_str());
                }
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    // The field re-takes focus every frame, so it never reports losing it on
                    // Enter; treat Enter anywhere in this dialog as "Connect".
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
                ui.weak("sdl-freerdp is recommended on Wayland.");
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
                     replaced on purpose.",
                );
                ui.add_space(6.0);
                if list.is_empty() {
                    ui.weak("No certificates saved yet.");
                }
                egui::ScrollArea::vertical()
                    .max_height(380.0)
                    .show(ui, |ui| {
                        egui::Grid::new("cert_grid")
                            .num_columns(4)
                            .striped(true)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                for cert in list {
                                    let used_by: Vec<&str> = self
                                        .config
                                        .connections
                                        .iter()
                                        .filter(|c| {
                                            c.host.trim().eq_ignore_ascii_case(&cert.host)
                                                && c.port == cert.port
                                        })
                                        .map(|c| c.display_name())
                                        .collect();
                                    ui.vertical(|ui| {
                                        ui.label(
                                            RichText::new(format!("{}:{}", cert.host, cert.port))
                                                .strong(),
                                        );
                                        if !used_by.is_empty() {
                                            ui.weak(used_by.join(", "));
                                        }
                                    });
                                    match &cert.error {
                                        Some(e) => {
                                            ui.colored_label(ui.visuals().warn_fg_color, e);
                                        }
                                        None => {
                                            ui.vertical(|ui| {
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
                                            });
                                        }
                                    }
                                    let short: String = cert.fingerprint.chars().take(23).collect();
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
                                    if ui
                                        .button("Forget")
                                        .on_hover_text(
                                            "You'll be asked to trust it again on the next connect",
                                        )
                                        .accessible_name(format!(
                                            "Forget certificate for {}",
                                            cert.host
                                        ))
                                        .clicked()
                                    {
                                        self.actions
                                            .push(Action::ForgetKnownCert(cert.path.clone()));
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

        if self.confirm_quit {
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("confirm_quit")).show(ctx, |ui| {
                ui.heading("Quit?");
                let n = self.sessions.iter().filter(|s| s.is_running()).count();
                ui.label(format!(
                    "{n} session(s) are still running and will be disconnected."
                ));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Disconnect and quit").clicked() {
                        self.actions.push(Action::Quit);
                    }
                    close = ui.button("Cancel").clicked();
                });
            });
            if close || resp.should_close() {
                self.confirm_quit = false;
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
        self.sync_integrations();
        if let Some(n) = self.inbox.lock().unwrap().pop() {
            self.notice = Some(n);
        }

        let any_running = self.sessions.iter().any(Session::is_running);
        if any_running {
            // Keep the elapsed-time display, reconnect state and exit detection ticking.
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            if self.tray_active() {
                self.exit = Exit::Hide;
                if !self.told_about_tray {
                    self.told_about_tray = true;
                    self.notify(
                        "xrdp-gui is still running".into(),
                        "Open it again from the tray icon. Quit from the tray menu or with Ctrl+Q."
                            .into(),
                        false,
                    );
                }
            } else if any_running {
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
        egui::CentralPanel::default_margins().show(ui, |ui| self.editor(ui));

        self.modals(&ctx);

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

    let target = match config.resolve(c).gateway {
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
    match command::build_args(resolved, settings, creds) {
        Ok(args) => {
            let preview = command::preview(&settings.client, &args);
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
            ui.weak("Arguments are passed via /args-from:stdin, so passwords never appear in the process list.");
        }
        Err(e) => {
            ui.colored_label(ui.visuals().warn_fg_color, format!("{e:#}"));
        }
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
