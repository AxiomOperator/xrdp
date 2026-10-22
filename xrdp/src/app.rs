use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{bail, Result};
use eframe::egui::{self, Color32, RichText};
use uuid::Uuid;

use crate::command::{self, Credentials};
use crate::model::{CertPolicy, Config, Connection, Settings};
use crate::secrets::{self, Kind};
use crate::session::{Session, Status};

const RESOLUTIONS: &[(u32, u32)] = &[
    (1280, 720),
    (1366, 768),
    (1600, 900),
    (1920, 1080),
    (2560, 1440),
    (3840, 2160),
];
const LOG_LEVELS: &[&str] = &["OFF", "FATAL", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"];
const CLIENTS: &[&str] = &["sdl-freerdp", "xfreerdp", "sdl-freerdp3", "xfreerdp3", "wlfreerdp"];
const RUNNING: Color32 = Color32::from_rgb(80, 200, 120);

/// The connection being edited, plus any newly typed passwords (never persisted to disk).
struct Draft {
    conn: Connection,
    password: String,
    gateway_password: String,
    is_new: bool,
}

impl Draft {
    fn new(conn: Connection, is_new: bool) -> Self {
        Self { conn, password: String::new(), gateway_password: String::new(), is_new }
    }
}

struct PasswordPrompt {
    id: Uuid,
    target: String,
    password: String,
    remember: bool,
}

enum Action {
    New,
    Select(Uuid),
    Save,
    Revert,
    Duplicate(Uuid),
    AskDelete(Uuid),
    Delete(Uuid),
    Forget(Kind),
    Connect(Uuid),
    Launch,
    Stop(usize),
    Dismiss(usize),
    SaveSettings,
    Quit,
}

pub struct App {
    config: Config,
    /// Set when the config file failed to load; saving is disabled so it is not clobbered.
    load_error: Option<String>,
    draft: Option<Draft>,
    search: String,
    sessions: Vec<Session>,
    log_session: Option<usize>,
    prompt: Option<PasswordPrompt>,
    confirm_delete: Option<Uuid>,
    settings_draft: Option<Settings>,
    confirm_quit: bool,
    allow_close: bool,
    notice: Option<(String, bool)>,
    actions: Vec<Action>,
}

impl App {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let (config, load_error) = match Config::load() {
            Ok(c) => (c, None),
            Err(e) => (Config::default(), Some(format!("{e:#}"))),
        };
        let notice = load_error
            .as_ref()
            .map(|e| (format!("Config not loaded, saving disabled: {e}"), true));
        Self {
            config,
            load_error,
            draft: None,
            search: String::new(),
            sessions: Vec::new(),
            log_session: None,
            prompt: None,
            confirm_delete: None,
            settings_draft: None,
            confirm_quit: false,
            allow_close: false,
            notice,
            actions: Vec::new(),
        }
    }

    // ---- state helpers -------------------------------------------------------------

    fn find(&self, id: Uuid) -> Option<&Connection> {
        self.config.connections.iter().find(|c| c.id == id)
    }

    fn is_dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(|d| {
            d.is_new
                || !d.password.is_empty()
                || !d.gateway_password.is_empty()
                || self.find(d.conn.id) != Some(&d.conn)
        })
    }

    fn info(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), false));
    }

    fn error(&mut self, e: anyhow::Error) {
        self.notice = Some((format!("{e:#}"), true));
    }

    fn save_config(&self) -> Result<()> {
        if let Some(e) = &self.load_error {
            bail!("not saving: config failed to load ({e})");
        }
        self.config.save()
    }

    fn save_draft(&mut self) -> Result<()> {
        let Some(d) = self.draft.as_mut() else { return Ok(()) };
        if d.conn.host.trim().is_empty() {
            bail!("host is required");
        }
        if !d.password.is_empty() {
            secrets::set(d.conn.id, Kind::Rdp, &d.password)?;
            d.conn.has_saved_password = true;
            d.password.clear();
        }
        if !d.gateway_password.is_empty() {
            secrets::set(d.conn.id, Kind::Gateway, &d.gateway_password)?;
            d.conn.has_saved_gateway_password = true;
            d.gateway_password.clear();
        }
        match self.config.connections.iter_mut().find(|c| c.id == d.conn.id) {
            Some(c) => *c = d.conn.clone(),
            None => self.config.connections.push(d.conn.clone()),
        }
        d.is_new = false;
        self.save_config()
    }

    /// Saves pending edits before navigating away; returns false if that failed.
    fn commit_draft(&mut self) -> bool {
        if !self.is_dirty() {
            return true;
        }
        match self.save_draft() {
            Ok(()) => true,
            Err(e) => {
                self.error(e.context("unsaved changes"));
                false
            }
        }
    }

    // ---- actions -------------------------------------------------------------------

    fn apply(&mut self, action: Action, ctx: &egui::Context) {
        match action {
            Action::New => {
                if self.commit_draft() {
                    let conn = Connection { name: "New connection".into(), ..Default::default() };
                    self.draft = Some(Draft::new(conn, true));
                }
            }
            Action::Select(id) => {
                if self.draft.as_ref().is_some_and(|d| d.conn.id == id) || !self.commit_draft() {
                    return;
                }
                self.draft = self.find(id).cloned().map(|c| Draft::new(c, false));
            }
            Action::Save => match self.save_draft() {
                Ok(()) => self.info("Saved"),
                Err(e) => self.error(e),
            },
            Action::Revert => {
                if let Some(d) = &self.draft {
                    self.draft = self.find(d.conn.id).cloned().map(|c| Draft::new(c, false));
                }
            }
            Action::Duplicate(id) => {
                if !self.commit_draft() {
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
                let result = secrets::delete(id, Kind::Rdp)
                    .and_then(|()| secrets::delete(id, Kind::Gateway))
                    .and_then(|()| self.save_config());
                if let Err(e) = result {
                    self.error(e);
                }
            }
            Action::Forget(kind) => {
                let Some(d) = self.draft.as_mut() else { return };
                let id = d.conn.id;
                if let Err(e) = secrets::delete(id, kind) {
                    return self.error(e);
                }
                for conn in std::iter::once(&mut d.conn)
                    .chain(self.config.connections.iter_mut().filter(|c| c.id == id))
                {
                    match kind {
                        Kind::Rdp => conn.has_saved_password = false,
                        Kind::Gateway => conn.has_saved_gateway_password = false,
                    }
                }
                match self.save_config() {
                    Ok(()) => self.info("Password removed from keyring"),
                    Err(e) => self.error(e),
                }
            }
            Action::Connect(id) => self.connect(id, ctx),
            Action::Launch => self.launch_from_prompt(ctx),
            Action::Stop(i) => {
                if let Some(s) = self.sessions.get(i) {
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
            Action::SaveSettings => {
                if let Some(s) = self.settings_draft.take() {
                    self.config.settings = s;
                    if let Err(e) = self.save_config() {
                        self.error(e);
                    }
                }
            }
            Action::Quit => {
                for s in &self.sessions {
                    s.terminate();
                }
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn connect(&mut self, id: Uuid, ctx: &egui::Context) {
        if self.draft.as_ref().is_some_and(|d| d.conn.id == id) && !self.commit_draft() {
            return;
        }
        let Some(conn) = self.find(id).cloned() else { return };

        let saved = if conn.has_saved_password {
            secrets::get(id, Kind::Rdp).unwrap_or_else(|e| {
                self.error(e);
                None
            })
        } else {
            None
        };
        match saved {
            Some(password) => self.launch(&conn, Some(password), ctx),
            None => {
                let user = match (conn.domain.trim(), conn.username.trim()) {
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
        let Some(mut conn) = self.find(p.id).cloned() else { return };
        if p.remember && !p.password.is_empty() {
            match secrets::set(p.id, Kind::Rdp, &p.password) {
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
        let gateway_password = if conn.gateway_enabled
            && !conn.gateway_same_credentials
            && conn.has_saved_gateway_password
        {
            secrets::get(conn.id, Kind::Gateway).unwrap_or_else(|e| {
                self.error(e);
                None
            })
        } else {
            None
        };
        let creds = Credentials {
            password: password.as_deref(),
            gateway_password: gateway_password.as_deref(),
        };
        let settings = &self.config.settings;
        let result = command::build_args(conn, settings, &creds).and_then(|args| {
            Session::spawn(&settings.client, &args, conn.id, conn.display_name().to_string(), ctx)
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
        let mut failed = None;
        for (i, s) in self.sessions.iter_mut().enumerate() {
            if s.poll()
                && let Status::Exited(st) = &s.status
                    && !st.success() {
                        failed = Some((i, format!("{} exited: {st}. See the session log.", s.name)));
                    }
        }
        if let Some((i, msg)) = failed {
            self.log_session = Some(i);
            self.notice = Some((msg, true));
        }
    }

    // ---- UI ------------------------------------------------------------------------

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("xrdp-gui");
            ui.separator();
            if ui.button("➕ New").clicked() {
                self.actions.push(Action::New);
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
                .hint_text("🔍 Search")
                .desired_width(f32::INFINITY),
        );
        ui.add_space(4.0);

        let query = self.search.trim().to_lowercase();
        let mut groups: BTreeMap<&str, Vec<&Connection>> = BTreeMap::new();
        for c in &self.config.connections {
            let hit = query.is_empty()
                || [&c.name, &c.host, &c.username, &c.group]
                    .iter()
                    .any(|f| f.to_lowercase().contains(&query));
            if hit {
                groups.entry(c.group.trim()).or_default().push(c);
            }
        }

        let selected = self.draft.as_ref().map(|d| d.conn.id);
        egui::ScrollArea::vertical().show(ui, |ui| {
            if self.config.connections.is_empty() {
                ui.weak("No connections yet.");
            }
            let show_headers = groups.len() > 1 || groups.keys().any(|g| !g.is_empty());
            for (group, mut conns) in groups {
                if show_headers {
                    ui.add_space(4.0);
                    ui.label(RichText::new(if group.is_empty() { "Ungrouped" } else { group }).small().strong());
                }
                conns.sort_by_key(|c| c.display_name().to_lowercase());
                for c in conns {
                    let running = self.sessions.iter().any(|s| s.connection_id == c.id && s.is_running());
                    let mut text = egui::text::LayoutJob::default();
                    let dot_color = if running { RUNNING } else { Color32::TRANSPARENT };
                    text.append("● ", 0.0, egui::TextFormat { color: dot_color, ..Default::default() });
                    text.append(c.display_name(), 0.0, egui::TextFormat {
                        color: ui.visuals().text_color(),
                        ..Default::default()
                    });
                    let resp = ui.add_sized(
                        [ui.available_width(), 22.0],
                        egui::Button::selectable(selected == Some(c.id), text),
                    );
                    let resp = resp.on_hover_text(format!("{}:{}", c.host, c.port));
                    if resp.double_clicked() {
                        self.actions.push(Action::Connect(c.id));
                    } else if resp.clicked() {
                        self.actions.push(Action::Select(c.id));
                    }
                    resp.context_menu(|ui| {
                        if ui.button("Connect").clicked() {
                            self.actions.push(Action::Connect(c.id));
                        }
                        if ui.button("Duplicate").clicked() {
                            self.actions.push(Action::Duplicate(c.id));
                        }
                        if ui.button("Delete…").clicked() {
                            self.actions.push(Action::AskDelete(c.id));
                        }
                    });
                }
            }
        });
    }

    fn editor(&mut self, ui: &mut egui::Ui) {
        let dirty = self.is_dirty();
        let settings = self.config.settings.clone();
        let Some(d) = self.draft.as_mut() else {
            ui.centered_and_justified(|ui| {
                ui.weak("Select a connection, or create one with ➕ New.\nDouble-click a connection to connect.");
            });
            return;
        };
        let actions = &mut self.actions;
        let id = d.conn.id;

        ui.horizontal(|ui| {
            ui.heading(d.conn.display_name().to_owned());
            if dirty {
                ui.weak("(unsaved)");
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let connect = egui::Button::new(RichText::new("▶ Connect").strong());
                if ui.add_enabled(!d.conn.host.trim().is_empty(), connect).clicked() {
                    actions.push(Action::Connect(id));
                }
                if ui.add_enabled(dirty, egui::Button::new("💾 Save")).clicked() {
                    actions.push(Action::Save);
                }
                if ui.add_enabled(dirty && !d.is_new, egui::Button::new("↺ Revert")).clicked() {
                    actions.push(Action::Revert);
                }
                if ui.add_enabled(!d.is_new, egui::Button::new("Duplicate")).clicked() {
                    actions.push(Action::Duplicate(id));
                }
                if ui.add_enabled(!d.is_new, egui::Button::new("🗑 Delete")).clicked() {
                    actions.push(Action::AskDelete(id));
                }
            });
        });
        ui.separator();

        egui::ScrollArea::vertical().auto_shrink(false).show(ui, |ui| {
            let c = &mut d.conn;

            section(ui, "General", true, |ui| {
                row(ui, "Name", |ui| ui.text_edit_singleline(&mut c.name));
                row(ui, "Group", |ui| ui.text_edit_singleline(&mut c.group));
                row(ui, "Host", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut c.host).hint_text("hostname or IP"))
                });
                row(ui, "Port", |ui| ui.add(egui::DragValue::new(&mut c.port).range(1..=65535)));
                row(ui, "Username", |ui| ui.text_edit_singleline(&mut c.username));
                row(ui, "Domain", |ui| ui.text_edit_singleline(&mut c.domain));
                row(ui, "Password", |ui| {
                    password_field(ui, &mut d.password, c.has_saved_password, || {
                        actions.push(Action::Forget(Kind::Rdp))
                    })
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
                    row(ui, "", |ui| ui.checkbox(&mut c.multimon, "Span all monitors"));
                } else {
                    row(ui, "Size", |ui| {
                        ui.horizontal(|ui| {
                            ui.add(egui::DragValue::new(&mut c.width).range(640..=8192));
                            ui.label("×");
                            ui.add(egui::DragValue::new(&mut c.height).range(480..=8192));
                            egui::ComboBox::from_id_salt("res_presets")
                                .selected_text("Presets")
                                .show_ui(ui, |ui| {
                                    for &(w, h) in RESOLUTIONS {
                                        if ui.button(format!("{w} × {h}")).clicked() {
                                            (c.width, c.height) = (w, h);
                                        }
                                    }
                                });
                        })
                        .response
                    });
                }
                row(ui, "", |ui| {
                    ui.checkbox(&mut c.dynamic_resolution, "Resize remote desktop with the window")
                });
            });

            section(ui, "Redirection", true, |ui| {
                row(ui, "", |ui| ui.checkbox(&mut c.clipboard, "Clipboard"));
                row(ui, "", |ui| ui.checkbox(&mut c.home_drive, "Home folder as a drive"));
                row(ui, "", |ui| ui.checkbox(&mut c.sound, "Play remote audio locally"));
                row(ui, "", |ui| ui.checkbox(&mut c.microphone, "Microphone"));
            });

            section(ui, "Gateway", c.gateway_enabled, |ui| {
                row(ui, "", |ui| ui.checkbox(&mut c.gateway_enabled, "Connect through an RD Gateway"));
                ui.add_enabled_ui(c.gateway_enabled, |ui| {
                    row(ui, "Gateway", |ui| {
                        ui.add(egui::TextEdit::singleline(&mut c.gateway_host).hint_text("gateway[:port]"))
                    });
                    row(ui, "", |ui| {
                        ui.checkbox(&mut c.gateway_same_credentials, "Use the same credentials")
                    });
                    if !c.gateway_same_credentials {
                        row(ui, "Username", |ui| ui.text_edit_singleline(&mut c.gateway_username));
                        row(ui, "Domain", |ui| ui.text_edit_singleline(&mut c.gateway_domain));
                        row(ui, "Password", |ui| {
                            password_field(ui, &mut d.gateway_password, c.has_saved_gateway_password, || {
                                actions.push(Action::Forget(Kind::Gateway))
                            })
                        });
                    }
                });
            });

            section(ui, "Advanced", false, |ui| {
                row(ui, "Certificate", |ui| {
                    egui::ComboBox::from_id_salt("cert")
                        .selected_text(c.cert.label())
                        .show_ui(ui, |ui| {
                            for p in CertPolicy::ALL {
                                ui.selectable_value(&mut c.cert, p, p.label());
                            }
                        })
                        .response
                });
                row(ui, "", |ui| ui.checkbox(&mut c.admin, "Admin / console session"));
                row(ui, "Extra args", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut c.extra_args)
                            .hint_text("e.g. /network:lan /gfx:AVC444")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                });
            });

            ui.add_space(8.0);
            ui.label(RichText::new("Command").strong());
            let will_have_password = c.has_saved_password || !d.password.is_empty();
            let creds = Credentials {
                password: will_have_password.then_some("x"),
                gateway_password: (c.has_saved_gateway_password || !d.gateway_password.is_empty()).then_some("x"),
            };
            match command::build_args(c, &settings, &creds) {
                Ok(args) => {
                    let preview = command::preview(&settings, &args);
                    ui.horizontal_wrapped(|ui| {
                        ui.add(egui::Label::new(RichText::new(&preview).monospace().weak()).wrap());
                        if ui.small_button("📋").on_hover_text("Copy (passwords masked)").clicked() {
                            ui.ctx().copy_text(preview.clone());
                        }
                    });
                    ui.weak("Arguments are passed via /args-from:stdin, so passwords never appear in the process list.");
                }
                Err(e) => {
                    ui.colored_label(ui.visuals().warn_fg_color, format!("{e:#}"));
                }
            }
        });
    }

    fn sessions_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Sessions").strong());
            let running = self.sessions.iter().filter(|s| s.is_running()).count();
            ui.weak(format!("{running} running"));
        });
        egui::ScrollArea::vertical()
            .id_salt("session_list")
            .max_height(110.0)
            .show(ui, |ui| {
                for (i, s) in self.sessions.iter().enumerate() {
                    ui.horizontal(|ui| {
                        let secs = s.started.elapsed().as_secs();
                        let (color, state) = match &s.status {
                            Status::Running => (
                                RUNNING,
                                format!("running {:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60),
                            ),
                            Status::Exited(st) if st.success() => (ui.visuals().weak_text_color(), "ended".into()),
                            Status::Exited(st) => (ui.visuals().error_fg_color, st.to_string()),
                        };
                        ui.colored_label(color, "●");
                        ui.label(&s.name);
                        ui.weak(state);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if s.is_running() {
                                if ui.small_button("⏹ Disconnect").clicked() {
                                    self.actions.push(Action::Stop(i));
                                }
                            } else if ui.small_button("✕").on_hover_text("Dismiss").clicked() {
                                self.actions.push(Action::Dismiss(i));
                            }
                            let showing = self.log_session == Some(i);
                            if ui.selectable_label(showing, "Log").clicked() {
                                self.log_session = if showing { None } else { Some(i) };
                            }
                        });
                    });
                }
            });

        if let Some(s) = self.log_session.and_then(|i| self.sessions.get(i)) {
            ui.separator();
            let log = s.log.lock().unwrap();
            egui::ScrollArea::both()
                .id_salt("session_log")
                .stick_to_bottom(true)
                .auto_shrink(false)
                .show(ui, |ui| {
                    if log.is_empty() {
                        ui.weak("(no output)");
                    }
                    for line in log.iter() {
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
                let field = ui.add(
                    egui::TextEdit::singleline(&mut p.password)
                        .password(true)
                        .hint_text("Leave empty to let FreeRDP ask")
                        .desired_width(f32::INFINITY),
                );
                field.request_focus();
                ui.checkbox(&mut p.remember, "Save in keyring");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
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
            let name = self.find(id).map(|c| c.display_name().to_owned()).unwrap_or_default();
            let mut close = false;
            let resp = egui::Modal::new(egui::Id::unique("confirm_delete")).show(ctx, |ui| {
                ui.heading("Delete connection?");
                ui.label(format!("“{name}” and its saved passwords will be removed."));
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Delete").color(ui.visuals().error_fg_color)).clicked() {
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
                ui.set_width(380.0);
                ui.heading("Settings");
                ui.add_space(6.0);
                egui::Grid::new("settings_grid").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
                    ui.label("FreeRDP client");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut s.client);
                        egui::ComboBox::from_id_salt("client_presets")
                            .selected_text("")
                            .width(20.0)
                            .show_ui(ui, |ui| {
                                for c in CLIENTS {
                                    ui.selectable_value(&mut s.client, c.to_string(), *c);
                                }
                            });
                    });
                    ui.end_row();
                    ui.label("Log level");
                    egui::ComboBox::from_id_salt("log_level")
                        .selected_text(s.log_level.as_str())
                        .show_ui(ui, |ui| {
                            for l in LOG_LEVELS {
                                ui.selectable_value(&mut s.log_level, l.to_string(), *l);
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
                ui.label(format!("{n} session(s) are still running and will be disconnected."));
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll_sessions();

        let any_running = self.sessions.iter().any(Session::is_running);
        if any_running {
            // Keep the elapsed-time display and exit detection ticking.
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
            let size = if self.log_session.is_some() { 260.0 } else { 90.0 };
            egui::Panel::bottom("sessions")
                .resizable(true)
                .default_size(size)
                .show(ui, |ui| self.sessions_panel(ui));
        }
        egui::Panel::left("connections")
            .resizable(true)
            .default_size(240.0)
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
        for s in &self.sessions {
            s.terminate();
        }
    }
}

fn section(ui: &mut egui::Ui, title: &str, open: bool, body: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).strong())
        .default_open(open)
        .show(ui, |ui| {
            egui::Grid::new(title).num_columns(2).spacing([12.0, 6.0]).show(ui, body);
        });
}

fn row(ui: &mut egui::Ui, label: &str, add: impl FnOnce(&mut egui::Ui) -> egui::Response) {
    ui.label(label);
    add(ui);
    ui.end_row();
}

fn password_field(
    ui: &mut egui::Ui,
    value: &mut String,
    saved: bool,
    forget: impl FnOnce(),
) -> egui::Response {
    ui.horizontal(|ui| {
        let hint = if saved { "•••••••• (saved; type to replace)" } else { "ask when connecting" };
        ui.add(egui::TextEdit::singleline(value).password(true).hint_text(hint));
        if saved && ui.small_button("Forget").on_hover_text("Remove from keyring").clicked() {
            forget();
        }
    })
    .response
}
