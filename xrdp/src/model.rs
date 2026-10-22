use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

    pub fn label(self) -> &'static str {
        match self {
            Self::Ask => "Ask",
            Self::Tofu => "Trust on first use",
            Self::Deny => "Deny unknown",
            Self::Ignore => "Ignore (insecure)",
        }
    }
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
    pub domain: String,
    /// Whether a password for this connection is stored in the keyring.
    pub has_saved_password: bool,

    pub fullscreen: bool,
    pub width: u32,
    pub height: u32,
    pub dynamic_resolution: bool,
    pub multimon: bool,

    pub clipboard: bool,
    pub home_drive: bool,
    pub sound: bool,
    pub microphone: bool,

    pub gateway_enabled: bool,
    pub gateway_host: String,
    pub gateway_same_credentials: bool,
    pub gateway_username: String,
    pub gateway_domain: String,
    pub has_saved_gateway_password: bool,

    pub cert: CertPolicy,
    pub admin: bool,
    pub extra_args: String,
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
            clipboard: true,
            home_drive: false,
            sound: true,
            microphone: false,
            gateway_enabled: false,
            gateway_host: String::new(),
            gateway_same_credentials: true,
            gateway_username: String::new(),
            gateway_domain: String::new(),
            has_saved_gateway_password: false,
            cert: CertPolicy::Tofu,
            admin: false,
            extra_args: String::new(),
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// FreeRDP client binary, e.g. `sdl-freerdp` or `xfreerdp`.
    pub client: String,
    pub log_level: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            client: "sdl-freerdp".into(),
            log_level: "WARN".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub settings: Settings,
    pub connections: Vec<Connection>,
}

impl Config {
    pub fn path() -> Result<PathBuf> {
        let dirs = directories::ProjectDirs::from("", "", "xrdp-gui")
            .context("could not determine config directory")?;
        Ok(dirs.config_dir().join("config.toml"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        let text = toml::to_string_pretty(self)?;
        // Write to a temp file and rename so a crash never leaves a truncated config.
        let tmp = path.with_extension("toml.tmp");
        fs::write(&tmp, text).with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }
}
