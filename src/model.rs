use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secrets::Key;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertPolicy {
    /// Let FreeRDP ask interactively.
    Ask,
    /// Trust on first use, fail on change.
    Tofu,
    /// Abort if the certificate is unknown or does not match.
    Deny,
    /// Skip all certificate checks.
    Ignore,
}

impl CertPolicy {
    pub const ALL: [CertPolicy; 4] = [Self::Ask, Self::Tofu, Self::Deny, Self::Ignore];
    pub const DEFAULT: CertPolicy = Self::Tofu;

    pub fn label(self) -> &'static str {
        match self {
            Self::Ask => "Ask",
            Self::Tofu => "Trust on first use",
            Self::Deny => "Deny unknown",
            Self::Ignore => "Ignore (insecure)",
        }
    }
}

/// Bandwidth/quality presets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    /// Let FreeRDP auto-detect the link.
    Auto,
    Lan,
    Vpn,
    Wan,
}

impl Profile {
    pub const ALL: [Profile; 4] = [Self::Auto, Self::Lan, Self::Vpn, Self::Wan];
    pub const DEFAULT: Profile = Self::Auto;

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto-detect",
            Self::Lan => "LAN (best quality)",
            Self::Vpn => "VPN / fast broadband",
            Self::Wan => "WAN / slow link",
        }
    }

    pub fn args(self) -> &'static [&'static str] {
        match self {
            Self::Auto => &[],
            Self::Lan => &["/network:lan", "/gfx:AVC444"],
            Self::Vpn => &[
                "/network:broadband-high",
                "/gfx:AVC444",
                "/compression-level:2",
                "-wallpaper",
            ],
            // AVC420 needs roughly half the bandwidth of AVC444.
            Self::Wan => &[
                "/network:wan",
                "/gfx:AVC420",
                "/compression-level:2",
                "-wallpaper",
                "-themes",
                "-window-drag",
                "-menu-anims",
            ],
        }
    }
}

/// How the remote desktop is scaled for high-DPI screens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scaling {
    /// FreeRDP's default (100%).
    #[default]
    Off,
    /// Match the scale of the screen xrdp-gui's window is on.
    Auto,
    Percent(u32),
}

impl Scaling {
    pub const PRESETS: [u32; 7] = [100, 125, 150, 175, 200, 250, 300];

    pub fn label(self) -> String {
        match self {
            Self::Off => "Off (100%)".into(),
            Self::Auto => format!("Match this screen ({}%)", screen_scale()),
            Self::Percent(p) => format!("{p}%"),
        }
    }

    /// The remote desktop scale in percent, if any.
    pub fn percent(self) -> Option<u32> {
        match self {
            Self::Off => None,
            Self::Auto => Some(screen_scale()),
            Self::Percent(p) => Some(p),
        }
    }
}

/// The local screen's scale in percent, as last seen by the window (100 until then).
static SCREEN_SCALE: AtomicU32 = AtomicU32::new(100);

pub fn screen_scale() -> u32 {
    SCREEN_SCALE.load(Ordering::Relaxed)
}

pub fn set_screen_scale(pixels_per_point: f32) {
    let percent = (pixels_per_point * 100.0).round().clamp(100.0, 500.0) as u32;
    SCREEN_SCALE.store(percent, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayMode {
    /// Use the group's gateway, if it has one.
    #[default]
    Inherit,
    Off,
    On,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub id: Uuid,
    pub name: String,
    pub group: String,

    pub host: String,
    pub port: u16,
    pub username: String,
    /// Empty means "use the group's domain".
    pub domain: String,
    /// Whether a password for this connection is stored in the keyring.
    pub has_saved_password: bool,

    pub fullscreen: bool,
    pub width: u32,
    pub height: u32,
    pub dynamic_resolution: bool,
    pub multimon: bool,
    pub scaling: Scaling,

    /// `None` inherits from the group.
    pub profile: Option<Profile>,
    pub auto_reconnect: bool,
    /// 0 means unlimited.
    pub reconnect_retries: u32,

    pub clipboard: bool,
    pub home_drive: bool,
    pub sound: bool,
    pub microphone: bool,

    pub gateway: GatewayMode,
    /// Pre-0.2 configs stored a plain on/off flag; migrated on load.
    #[serde(skip_serializing)]
    pub gateway_enabled: Option<bool>,
    pub gateway_host: String,
    pub gateway_same_credentials: bool,
    pub gateway_username: String,
    pub gateway_domain: String,
    pub has_saved_gateway_password: bool,

    /// `None` inherits from the group.
    pub cert: Option<CertPolicy>,
    pub admin: bool,
    pub extra_args: String,

    pub favorite: bool,
    /// When this connection was last launched (Unix seconds).
    pub last_used: Option<i64>,
    pub tags: Vec<String>,
    pub notes: String,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            group: String::new(),
            host: String::new(),
            port: 3389,
            username: String::new(),
            domain: String::new(),
            has_saved_password: false,
            fullscreen: false,
            width: 1600,
            height: 900,
            dynamic_resolution: true,
            multimon: false,
            scaling: Scaling::Off,
            profile: None,
            auto_reconnect: true,
            reconnect_retries: 10,
            clipboard: true,
            home_drive: false,
            sound: true,
            microphone: false,
            gateway: GatewayMode::Inherit,
            gateway_enabled: None,
            gateway_host: String::new(),
            gateway_same_credentials: true,
            gateway_username: String::new(),
            gateway_domain: String::new(),
            has_saved_gateway_password: false,
            cert: None,
            admin: false,
            extra_args: String::new(),
            favorite: false,
            last_used: None,
            tags: Vec::new(),
            notes: String::new(),
        }
    }
}

impl Connection {
    pub fn display_name(&self) -> &str {
        if !self.name.trim().is_empty() {
            &self.name
        } else if !self.host.trim().is_empty() {
            &self.host
        } else {
            "(unnamed)"
        }
    }

    /// Whether `query` (already lower-cased) matches this connection. `#tag` matches a
    /// tag exactly; anything else matches part of the name, host, user, group, a tag or
    /// the notes.
    pub fn matches(&self, query: &str) -> bool {
        if let Some(tag) = query.strip_prefix('#') {
            return self.tags.iter().any(|t| t.to_lowercase() == tag);
        }
        [
            &self.name,
            &self.host,
            &self.username,
            &self.group,
            &self.notes,
        ]
        .into_iter()
        .chain(&self.tags)
        .any(|f| f.to_lowercase().contains(query))
    }
}

/// Splits "a, b,c" into tags, dropping empties and duplicates.
pub fn parse_tags(text: &str) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for t in text
        .split(',')
        .map(|t| t.trim().trim_start_matches('#').trim())
    {
        if !t.is_empty() && !tags.iter().any(|x| x.eq_ignore_ascii_case(t)) {
            tags.push(t.to_string());
        }
    }
    tags
}

/// Defaults shared by every connection in a group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub name: String,
    pub domain: String,
    /// Used by member connections that leave their own username empty.
    pub username: String,
    pub has_saved_password: bool,
    pub cert: Option<CertPolicy>,
    pub profile: Option<Profile>,
    pub gateway_enabled: bool,
    pub gateway_host: String,
    pub gateway_same_credentials: bool,
    pub gateway_username: String,
    pub gateway_domain: String,
    pub has_saved_gateway_password: bool,
}

impl Default for Group {
    fn default() -> Self {
        Self {
            name: String::new(),
            domain: String::new(),
            username: String::new(),
            has_saved_password: false,
            cert: None,
            profile: None,
            gateway_enabled: false,
            gateway_host: String::new(),
            gateway_same_credentials: true,
            gateway_username: String::new(),
            gateway_domain: String::new(),
            has_saved_gateway_password: false,
        }
    }
}

/// A gateway after inheritance has been applied.
#[derive(Debug, Clone, PartialEq)]
pub struct GatewayTarget {
    pub host: String,
    pub same_credentials: bool,
    pub username: String,
    pub domain: String,
    /// Keyring entry holding the separate gateway password, if one is saved.
    pub saved_password: Option<Key>,
    /// The group the gateway was inherited from, if any.
    pub from_group: Option<String>,
}

/// A connection with all group defaults applied.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub conn: Connection,
    pub username: String,
    pub domain: String,
    /// Keyring entry holding the password to use, if one is saved.
    pub password_key: Option<Key>,
    /// The group whose credentials are used, if the connection inherits them.
    pub creds_from_group: Option<String>,
    /// Remote desktop scale in percent.
    pub scale: Option<u32>,
    pub cert: CertPolicy,
    pub profile: Profile,
    pub gateway: Option<GatewayTarget>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// FreeRDP client binary, e.g. `sdl-freerdp` or `xfreerdp`.
    pub client: String,
    pub log_level: String,
    /// Periodically check whether each host's RDP port is reachable.
    pub probe_hosts: bool,
    pub notifications: bool,
    /// Show a tray icon; closing the window then keeps xrdp-gui running in the tray.
    pub tray: bool,
    /// Opening a group in the sidebar closes the others.
    pub accordion: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            client: "sdl-freerdp".into(),
            log_level: "WARN".into(),
            probe_hosts: true,
            notifications: true,
            tray: true,
            accordion: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub settings: Settings,
    pub groups: Vec<Group>,
    pub connections: Vec<Connection>,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("", "", "xrdp-gui")
            .context("could not determine config directory")?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    pub fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(text) => {
                let mut config: Self =
                    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
                config.migrate();
                Ok(config)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self)?;
        // Write to a temp file and rename so a crash never leaves a truncated config.
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    fn migrate(&mut self) {
        for c in &mut self.connections {
            match c.gateway_enabled.take() {
                Some(true) => c.gateway = GatewayMode::On,
                // Groups did not exist yet, so inheriting is equivalent to "off".
                Some(false) => c.gateway = GatewayMode::Inherit,
                None => {}
            }
        }
    }

    pub fn group(&self, name: &str) -> Option<&Group> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        self.groups.iter().find(|g| g.name == name)
    }

    /// All group names: those with saved defaults plus those used by connections.
    pub fn group_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .groups
            .iter()
            .map(|g| g.name.clone())
            .chain(self.connections.iter().map(|c| c.group.trim().to_string()))
            .filter(|n| !n.is_empty())
            .collect();
        names.sort_by_key(|n| n.to_lowercase());
        names.dedup();
        names
    }

    pub fn find(&self, id: Uuid) -> Option<&Connection> {
        self.connections.iter().find(|c| c.id == id)
    }

    pub fn resolve(&self, conn: &Connection) -> Resolved {
        let group = self.group(&conn.group);
        // A connection without its own username uses its group's credentials.
        let creds_group = group.filter(|g| {
            conn.username.trim().is_empty()
                && (!g.username.trim().is_empty() || g.has_saved_password)
        });
        let (username, password_key) = match creds_group {
            Some(g) => (
                g.username.trim().to_string(),
                g.has_saved_password.then(|| Key::GroupRdp(g.name.clone())),
            ),
            None => (
                conn.username.trim().to_string(),
                conn.has_saved_password.then_some(Key::Rdp(conn.id)),
            ),
        };
        let domain = match conn.domain.trim() {
            "" => group
                .map(|g| g.domain.trim().to_string())
                .unwrap_or_default(),
            d => d.to_string(),
        };
        let gateway = match conn.gateway {
            GatewayMode::Off => None,
            GatewayMode::On => Some(GatewayTarget {
                host: conn.gateway_host.trim().to_string(),
                same_credentials: conn.gateway_same_credentials,
                username: conn.gateway_username.trim().to_string(),
                domain: conn.gateway_domain.trim().to_string(),
                saved_password: conn
                    .has_saved_gateway_password
                    .then_some(Key::Gateway(conn.id)),
                from_group: None,
            }),
            GatewayMode::Inherit => group.filter(|g| g.gateway_enabled).map(|g| GatewayTarget {
                host: g.gateway_host.trim().to_string(),
                same_credentials: g.gateway_same_credentials,
                username: g.gateway_username.trim().to_string(),
                domain: g.gateway_domain.trim().to_string(),
                saved_password: g
                    .has_saved_gateway_password
                    .then(|| Key::GroupGateway(g.name.clone())),
                from_group: Some(g.name.clone()),
            }),
        };
        Resolved {
            conn: conn.clone(),
            username,
            domain,
            password_key,
            creds_from_group: creds_group.map(|g| g.name.clone()),
            scale: conn.scaling.percent(),
            cert: conn
                .cert
                .or(group.and_then(|g| g.cert))
                .unwrap_or(CertPolicy::DEFAULT),
            profile: conn
                .profile
                .or(group.and_then(|g| g.profile))
                .unwrap_or(Profile::DEFAULT),
            gateway,
        }
    }
}

/// Splits `host[:port]` / `[v6]:port`, falling back to `default_port`.
pub fn split_host_port(s: &str, default_port: u16) -> (String, u16) {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return (host.to_string(), port);
    }
    match s.rsplit_once(':') {
        // A single colon is a port separator; more than one is a bare IPv6 address.
        Some((host, port)) if !host.contains(':') => {
            (host.to_string(), port.parse().unwrap_or(default_port))
        }
        _ => (s.to_string(), default_port),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_defaults_are_inherited_and_overridable() {
        let mut config = Config {
            groups: vec![Group {
                name: "Work".into(),
                domain: "CORP".into(),
                cert: Some(CertPolicy::Deny),
                profile: Some(Profile::Vpn),
                gateway_enabled: true,
                gateway_host: "gw.corp".into(),
                has_saved_gateway_password: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let conn = Connection {
            group: "Work".into(),
            host: "pc1".into(),
            ..Default::default()
        };
        config.connections.push(conn.clone());

        let r = config.resolve(&conn);
        assert_eq!(r.domain, "CORP");
        assert_eq!(r.cert, CertPolicy::Deny);
        assert_eq!(r.profile, Profile::Vpn);
        let gw = r.gateway.unwrap();
        assert_eq!(gw.host, "gw.corp");
        assert_eq!(gw.from_group.as_deref(), Some("Work"));
        assert_eq!(gw.saved_password, Some(Key::GroupGateway("Work".into())));

        let own = Connection {
            domain: "OTHER".into(),
            cert: Some(CertPolicy::Ask),
            profile: Some(Profile::Lan),
            gateway: GatewayMode::Off,
            ..conn.clone()
        };
        let r = config.resolve(&own);
        assert_eq!(
            (r.domain.as_str(), r.cert, r.profile),
            ("OTHER", CertPolicy::Ask, Profile::Lan)
        );
        assert!(r.gateway.is_none());

        let loose = Connection {
            group: String::new(),
            ..conn
        };
        let r = config.resolve(&loose);
        assert_eq!(
            (r.domain.as_str(), r.cert, r.profile),
            ("", CertPolicy::DEFAULT, Profile::DEFAULT)
        );
        assert!(r.gateway.is_none());
    }

    #[test]
    fn migrates_old_config() {
        let old = r#"
            [[connections]]
            name = "a"
            host = "h"
            gateway_enabled = true
            gateway_host = "gw"
            cert = "tofu"
            [[connections]]
            name = "b"
            host = "h"
            gateway_enabled = false
        "#;
        let mut config: Config = toml::from_str(old).unwrap();
        config.migrate();
        assert_eq!(config.connections[0].gateway, GatewayMode::On);
        assert_eq!(config.connections[0].cert, Some(CertPolicy::Tofu));
        assert_eq!(config.connections[1].gateway, GatewayMode::Inherit);
        assert!(config.connections[1].auto_reconnect);
        assert!(
            !toml::to_string(&config)
                .unwrap()
                .contains("gateway_enabled")
        );
    }

    #[test]
    fn group_credentials_apply_without_own_username() {
        let config = Config {
            groups: vec![Group {
                name: "Work".into(),
                username: "svc".into(),
                has_saved_password: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        let member = Connection {
            group: "Work".into(),
            host: "pc1".into(),
            has_saved_password: true,
            ..Default::default()
        };
        let r = config.resolve(&member);
        assert_eq!(r.username, "svc");
        assert_eq!(r.password_key, Some(Key::GroupRdp("Work".into())));
        assert_eq!(r.creds_from_group.as_deref(), Some("Work"));

        // Its own username means its own password.
        let own = Connection {
            username: "alice".into(),
            ..member.clone()
        };
        let r = config.resolve(&own);
        assert_eq!(r.username, "alice");
        assert_eq!(r.password_key, Some(Key::Rdp(own.id)));
        assert_eq!(r.creds_from_group, None);

        // A group without credentials changes nothing.
        let plain = Config {
            groups: vec![Group {
                name: "Work".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let r = plain.resolve(&member);
        assert_eq!((r.username.as_str(), r.creds_from_group), ("", None));
        assert_eq!(r.password_key, Some(Key::Rdp(member.id)));
    }

    #[test]
    fn tags_and_search() {
        assert_eq!(parse_tags(" web, #prod,, Web ,db"), ["web", "prod", "db"]);
        let c = Connection {
            name: "Mail".into(),
            host: "mx1".into(),
            tags: vec!["Exchange".into()],
            notes: "Owned by the messaging team".into(),
            ..Default::default()
        };
        assert!(c.matches("mail"));
        assert!(c.matches("exch"));
        assert!(c.matches("messaging"));
        assert!(c.matches("#exchange"));
        assert!(!c.matches("#exch"));
        assert!(!c.matches("web"));
    }

    #[test]
    fn scaling_round_trips_through_toml() {
        for scaling in [Scaling::Off, Scaling::Auto, Scaling::Percent(150)] {
            let c = Connection {
                scaling,
                ..Default::default()
            };
            let back: Connection = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
            assert_eq!(back.scaling, scaling);
        }
        assert_eq!(Scaling::Percent(175).percent(), Some(175));
        assert_eq!(Scaling::Off.percent(), None);
    }

    #[test]
    fn host_port_parsing() {
        assert_eq!(split_host_port("gw", 443), ("gw".into(), 443));
        assert_eq!(split_host_port("gw:8443", 443), ("gw".into(), 8443));
        assert_eq!(split_host_port("[::1]:444", 443), ("::1".into(), 444));
        assert_eq!(split_host_port("fe80::1", 443), ("fe80::1".into(), 443));
    }
}
