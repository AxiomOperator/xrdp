use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use eframe::egui::{self, Color32, Key as KeyCode, KeyboardShortcut, Modifiers, RichText};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::command::{self, Credentials};
use crate::diagnose::{Fix, Severity};
use crate::model::{
    self, CertPolicy, Config, Connection, GatewayMode, Group, Profile, Resolved, Settings,
};
use crate::notify;
use crate::probe::{Prober, Reach, Target};
use crate::secrets::{self, Key};
use crate::session::{Session, Status};
use crate::single_instance::Primary;

/// eframe storage key for the last selected item.
const SELECTION_KEY: &str = "selection";
const SEARCH_ID: &str = "connection_search";

const SHORTCUT_NEW: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::N);
const SHORTCUT_SAVE: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::S);
const SHORTCUT_FIND: KeyboardShortcut = KeyboardShortcut::new(Modifiers::COMMAND, KeyCode::F);

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
    is_new: bool,
}

impl Draft {
    fn new(conn: Connection, is_new: bool) -> Self {
        Self {
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
            gateway_password: String::new(),
        }
    }
}

struct PasswordPrompt {
    id: Uuid,
    target: String,
    password: String,
    remember: bool,
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
    ForgetCertificate(Uuid),
    Connect(Uuid),
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
    /// Set when another launch asked this window to come to the front.
    show_requested: Option<Arc<AtomicBool>>,
    /// Notices from background work (e.g. saving a log file).
    inbox: Arc<Mutex<Vec<(String, bool)>>>,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, instance: Option<Primary>) -> Self {
        let path = Config::path().unwrap_or_else(|_| "xrdp-gui.toml".into());
        Self::with_config_path(cc, instance, path)
    }

    fn with_config_path(
        cc: &eframe::CreationContext<'_>,
        instance: Option<Primary>,
        config_path: std::path::PathBuf,
    ) -> Self {
        let (config, load_error) = match Config::load(&config_path) {
            Ok(c) => (c, None),
            Err(e) => (Config::default(), Some(format!("{e:#}"))),
        };
        let mut notice = load_error
            .as_ref()
            .map(|e| (format!("Config not loaded, saving disabled: {e}"), true));
        let show_requested = instance.as_ref().and_then(|p| {
            p.listen(cc.egui_ctx.clone())
                .inspect_err(|e| notice = Some((format!("{e:#}"), true)))
                .ok()
        });
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
            prober: Prober::new(cc.egui_ctx.clone()),
            actions: Vec::new(),
            _instance: instance,
            show_requested,
            inbox: Arc::default(),
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
        let (new, save, find) = ctx.input_mut(|i| {
            (
                i.consume_shortcut(&SHORTCUT_NEW),
                i.consume_shortcut(&SHORTCUT_SAVE),
                i.consume_shortcut(&SHORTCUT_FIND),
            )
        });
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
        self.config.connections.iter().find(|c| c.id == id)
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
        self.group_draft
            .as_ref()
            .is_some_and(|g| g.group != g.original || !g.gateway_password.is_empty())
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
            if g.original.has_saved_gateway_password && g.gateway_password.is_empty() {
                let old_key = Key::GroupGateway(old_name.clone());
                if let Some(pw) = secrets::get(&old_key)? {
                    secrets::set(&Key::GroupGateway(new_name.clone()), &pw)?;
                }
                secrets::delete(&old_key)?;
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
            Action::ForgetCertificate(id) => match self.forget_certificate(id) {
                Ok(msg) => self.info(msg),
                Err(e) => self.error(e),
            },
            Action::Connect(id) => self.connect(id, ctx),
            Action::Launch => self.launch_from_prompt(ctx),
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
                }
            }
            Action::Quit => {
                for s in &mut self.sessions {
                    s.terminate();
                }
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
        let conn = self.find(id).context("connection no longer exists")?;
        let dirs = directories::BaseDirs::new().context("could not determine config directory")?;
        let file = dirs.config_dir().join("freerdp/server").join(format!(
            "{}_{}.pem",
            conn.host.trim().to_lowercase(),
            conn.port
        ));
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

    fn connect(&mut self, id: Uuid, ctx: &egui::Context) {
        if self.draft.as_ref().is_some_and(|d| d.conn.id == id) && !self.commit() {
            return;
        }
        let Some(conn) = self.find(id).cloned() else {
            return;
        };

        let saved = if conn.has_saved_password {
            secrets::get(&Key::Rdp(id)).unwrap_or_else(|e| {
                self.error(e);
                None
            })
        } else {
            None
        };
        match saved {
            Some(password) => self.launch(&conn, Some(password), ctx),
            None => {
                let domain = self.config.resolve(&conn).domain;
                let user = match (domain.as_str(), conn.username.trim()) {
                    (_, "") => String::new(),
                    ("", u) => format!("{u}@"),
                    (d, u) => format!("{d}\\{u}@"),
                };
                self.prompt = Some(PasswordPrompt {
                    id,
                    target: format!("{user}{}", conn.host.trim()),
                    password: String::new(),
                    remember: false,
                });
            }
        }
    }

    fn launch_from_prompt(&mut self, ctx: &egui::Context) {
        let Some(p) = self.prompt.take() else { return };
        let Some(mut conn) = self.find(p.id).cloned() else {
            return;
        };
        if p.remember && !p.password.is_empty() {
            match secrets::set(&Key::Rdp(p.id), &p.password) {
                Ok(()) => {
                    conn.has_saved_password = true;
                    for c in self.config.connections.iter_mut().filter(|c| c.id == p.id) {
                        c.has_saved_password = true;
                    }
                    if let Some(d) = self.draft.as_mut().filter(|d| d.conn.id == p.id) {
                        d.conn.has_saved_password = true;
                    }
                    if let Err(e) = self.save_config() {
                        self.error(e);
                    }
                }
                Err(e) => self.error(e),
            }
        }
        // An empty password lets FreeRDP prompt (or use Kerberos/smartcard) itself.
        let password = Some(p.password).filter(|p| !p.is_empty());
        self.launch(&conn, password, ctx);
    }

    fn launch(&mut self, conn: &Connection, password: Option<String>, ctx: &egui::Context) {
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
                ctx,
            )
        });
        match result {
            Ok(session) => {
                self.sessions.push(session);
                self.info(format!("Connecting to {}…", conn.display_name()));
            }
            Err(e) => self.error(e),
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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("⚙ Settings").clicked() {
                    self.settings_draft = Some(self.config.settings.clone());
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
                .hint_text("🔍 Search (Ctrl+F)")
                .desired_width(f32::INFINITY),
        )
        .accessible_name("Search connections");
        ui.add_space(4.0);

        let query = self.search.trim().to_lowercase();
        let mut groups: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
        if query.is_empty() {
            // Show groups that only have defaults so they can be edited.
            for g in &self.config.groups {
                groups.entry(g.name.clone()).or_default();
            }
        }
        for c in &self.config.connections {
            let hit = query.is_empty()
                || [&c.name, &c.host, &c.username, &c.group]
                    .iter()
                    .any(|f| f.to_lowercase().contains(&query));
            if hit {
                groups
                    .entry(c.group.trim().to_string())
                    .or_default()
                    .push(c);
            }
        }

        let selected = self.draft.as_ref().map(|d| d.conn.id);
        let selected_group = self.group_draft.as_ref().map(|g| g.original.name.as_str());
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.config.connections.is_empty() {
                ui.weak("No connections yet.");
            }
            let show_headers = groups.len() > 1 || groups.keys().any(|g| !g.is_empty());
            for (group, mut conns) in groups {
                if show_headers {
                    ui.add_space(6.0);
                    if group.is_empty() {
                        ui.label(RichText::new("Ungrouped").small().strong());
                    } else {
                        let has_defaults = self.config.group(&group).is_some();
                        let label = RichText::new(if has_defaults {
                            format!("{group}  ⚙")
                        } else {
                            group.clone()
                        })
                        .small()
                        .strong();
                        let resp = ui
                            .add(egui::Button::selectable(
                                selected_group == Some(group.as_str()),
                                label,
                            ))
                            .on_hover_text("Click to edit this group's shared defaults");
                        if resp.clicked() {
                            self.actions.push(Action::SelectGroup(group.clone()));
                        }
                    }
                }
                if conns.is_empty() {
                    ui.weak("  (empty)");
                }
                conns.sort_by_key(|c| c.display_name().to_lowercase());
                for c in conns {
                    connection_row(
                        ui,
                        c,
                        selected == Some(c.id),
                        &self.config,
                        &self.sessions,
                        &self.prober,
                        &mut self.actions,
                    );
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
                     Double-click a connection to connect. Click a group name to edit its defaults.",
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
                    row(ui, "Username", |ui| {
                        ui.text_edit_singleline(&mut c.username)
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
                    row(ui, "Password", |ui| {
                        password_field(
                            ui,
                            "Password",
                            &mut d.password,
                            c.has_saved_password,
                            || actions.push(Action::Forget(Key::Rdp(id))),
                        )
                    });
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
                    row(ui, "Domain", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut gr.domain).hint_text("e.g. CORP"))
                    });
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
                                        Action::Forget(Key::Rdp(s.connection_id)),
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
                ui.checkbox(&mut p.remember, "Save in keyring");
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
        let ctx = ui.ctx().clone();
        self.poll_sessions();
        self.update_probe_targets();
        self.handle_shortcuts(&ctx);

        if self
            .show_requested
            .as_ref()
            .is_some_and(|f| f.swap(false, Ordering::SeqCst))
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            // Wayland compositors may refuse to steal focus; flag the window instead.
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
        if let Some(n) = self.inbox.lock().unwrap().pop() {
            self.notice = Some(n);
        }

        let any_running = self.sessions.iter().any(Session::is_running);
        if any_running {
            // Keep the elapsed-time display, reconnect state and exit detection ticking.
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if ctx.input(|i| i.viewport().close_requested()) && any_running && !self.allow_close {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.confirm_quit = true;
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
        for s in &mut self.sessions {
            s.terminate();
        }
    }
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
    match session.map(|s| s.reconnecting()) {
        Some(Some(_)) => text.append("  ⟳", 0.0, fmt(AMBER)),
        Some(None) => text.append("  ▶", 0.0, fmt(GREEN)),
        None => {}
    }

    let target = match config.resolve(c).gateway {
        Some(gw) => format!("{}:{} via gateway {}", c.host, c.port, gw.host),
        None => format!("{}:{}", c.host, c.port),
    };
    let resp = ui
        .add_sized(
            [ui.available_width(), 22.0],
            egui::Button::selectable(selected, text),
        )
        .on_hover_text(format!("{target}\n{reach_text}"));
    if resp.double_clicked() {
        actions.push(Action::Connect(c.id));
    } else if resp.clicked() {
        actions.push(Action::Select(c.id));
    }
    resp.context_menu(|ui| {
        if ui.button("Connect").clicked() {
            actions.push(Action::Connect(c.id));
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
        h.get_by_label("Work  ⚙").click();
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
}
