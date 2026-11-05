//! Backing up connections, groups and settings to a file, and restoring them.
//!
//! Backups never hold passwords (those stay in the keyring) or trusted certificates (those
//! are FreeRDP's). A restored connection only counts as having a saved password if this
//! computer already holds one for it, whatever the file says.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{CertPolicy, Config, Connection, Group, Settings};
use crate::secrets::Key;

/// Tells a backup from any other TOML file: nearly every field is optional, so without
/// this an unrelated file would read as an empty backup, and replacing with it would
/// remove everything.
const FORMAT: &str = "xrdp-gui backup";
const VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Backup {
    pub format: String,
    pub version: u32,
    /// When the backup was made, in local time, for showing to people.
    pub created: String,
    pub settings: Settings,
    pub groups: Vec<Group>,
    pub connections: Vec<Connection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreMode {
    /// Adds what's missing; nothing already here changes.
    Add,
    /// Makes connections, groups and settings match the backup.
    Replace,
}

/// What a restore would do, or did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    pub added_connections: usize,
    pub added_groups: usize,
    pub removed_connections: usize,
    pub removed_groups: usize,
    /// Passwords of removed connections and groups, to delete once the change is saved.
    pub stale_passwords: Vec<Key>,
}

impl Backup {
    pub fn of(config: &Config) -> Self {
        let mut backup = Self {
            format: FORMAT.into(),
            version: VERSION,
            created: chrono::Local::now().format("%Y-%m-%d %H:%M").to_string(),
            settings: config.settings.clone(),
            groups: config.groups.clone(),
            connections: config.connections.clone(),
        };
        // A flag in the file would only mislead: the passwords aren't in it.
        for c in &mut backup.connections {
            c.has_saved_password = false;
            c.has_saved_gateway_password = false;
        }
        for g in &mut backup.groups {
            g.has_saved_password = false;
            g.has_saved_gateway_password = false;
        }
        backup
    }

    /// Readable only by this user, since extra arguments and notes are included as typed.
    pub fn write(&self, path: &Path) -> Result<()> {
        let text = toml::to_string_pretty(self)?;
        let mut name = path.as_os_str().to_owned();
        name.push(".tmp");
        let tmp = std::path::PathBuf::from(name);
        // A leftover could have looser permissions, which `mode` wouldn't change.
        let _ = fs::remove_file(&tmp);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        file.write_all(text.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        drop(file);
        fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
    }

    pub fn read(path: &Path) -> Result<Self> {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("restoring {}", path.display()))
    }

    fn parse(text: &str) -> Result<Self> {
        let mut backup: Self = toml::from_str(text).context("not a valid backup file")?;
        if backup.format != FORMAT {
            bail!("this isn't an xrdp-gui backup file");
        }
        if backup.version > VERSION {
            bail!("this backup was made by a newer version of xrdp-gui");
        }
        // Only a hand-edited file has these, but they'd make connections unselectable.
        let mut ids = HashSet::new();
        for c in &mut backup.connections {
            if !ids.insert(c.id) {
                c.id = Uuid::new_v4();
            }
        }
        let mut names = HashSet::new();
        backup.groups.retain(|g| names.insert(g.name.clone()));
        Ok(backup)
    }

    pub fn is_empty(&self) -> bool {
        self.connections.is_empty() && self.groups.is_empty()
    }

    /// How many entries could change how safely this computer connects, or what it runs.
    /// Worth a warning: the file may have come from someone else.
    pub fn risky_entries(&self) -> usize {
        let conns = self
            .connections
            .iter()
            .filter(|c| !c.extra_args.trim().is_empty() || c.cert == Some(CertPolicy::Ignore));
        let groups = self
            .groups
            .iter()
            .filter(|g| g.cert == Some(CertPolicy::Ignore));
        conns.count() + groups.count()
    }

    /// Applies the backup to `config`. The list of certificates awaiting review is left
    /// alone in every mode: forgetting one is a safety decision about this computer.
    pub fn restore(&self, config: &mut Config, mode: RestoreMode) -> Outcome {
        let mut outcome = Outcome::default();

        if mode == RestoreMode::Replace {
            for c in &config.connections {
                if self.connections.iter().any(|b| b.id == c.id) {
                    continue;
                }
                outcome.removed_connections += 1;
                if c.has_saved_password {
                    outcome.stale_passwords.push(Key::Rdp(c.id));
                }
                if c.has_saved_gateway_password {
                    outcome.stale_passwords.push(Key::Gateway(c.id));
                }
            }
            for g in &config.groups {
                if self.groups.iter().any(|b| b.name == g.name) {
                    continue;
                }
                outcome.removed_groups += 1;
                if g.has_saved_password {
                    outcome.stale_passwords.push(Key::GroupRdp(g.name.clone()));
                }
                if g.has_saved_gateway_password {
                    outcome
                        .stale_passwords
                        .push(Key::GroupGateway(g.name.clone()));
                }
            }
        }

        let connections = self.connections.iter().filter_map(|b| {
            let mine = config.connections.iter().find(|c| c.id == b.id);
            if mine.is_none() {
                outcome.added_connections += 1;
            } else if mode == RestoreMode::Add {
                return None;
            }
            Some(Connection {
                has_saved_password: mine.is_some_and(|c| c.has_saved_password),
                has_saved_gateway_password: mine.is_some_and(|c| c.has_saved_gateway_password),
                ..b.clone()
            })
        });
        let connections: Vec<Connection> = connections.collect();

        let groups = self.groups.iter().filter_map(|b| {
            let mine = config.groups.iter().find(|g| g.name == b.name);
            if mine.is_none() {
                outcome.added_groups += 1;
            } else if mode == RestoreMode::Add {
                return None;
            }
            Some(Group {
                has_saved_password: mine.is_some_and(|g| g.has_saved_password),
                has_saved_gateway_password: mine.is_some_and(|g| g.has_saved_gateway_password),
                ..b.clone()
            })
        });
        let groups: Vec<Group> = groups.collect();

        match mode {
            RestoreMode::Add => {
                config.connections.extend(connections);
                config.groups.extend(groups);
            }
            RestoreMode::Replace => {
                config.connections = connections;
                config.groups = groups;
                config.settings = self.settings.clone();
            }
        }
        outcome
    }

    /// Whether replacing would change which programs xrdp-gui runs on this computer.
    pub fn changes_programs(&self, config: &Config) -> bool {
        self.settings.client != config.settings.client
            || self.settings.terminal != config.settings.terminal
    }

    /// What restoring would do, without doing it.
    pub fn preview(&self, config: &Config, mode: RestoreMode) -> Outcome {
        self.restore(&mut config.clone(), mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::CertReview;
    use std::os::unix::fs::PermissionsExt;

    fn conn(name: &str) -> Connection {
        Connection {
            name: name.into(),
            host: format!("{name}.example.org"),
            ..Default::default()
        }
    }

    fn sample() -> Config {
        Config {
            settings: Settings {
                client: "xfreerdp".into(),
                accordion: false,
                ..Default::default()
            },
            groups: vec![Group {
                name: "Work".into(),
                domain: "CORP".into(),
                has_saved_password: true,
                has_saved_gateway_password: true,
                ..Default::default()
            }],
            connections: vec![Connection {
                group: "Work".into(),
                has_saved_password: true,
                has_saved_gateway_password: true,
                favorite: true,
                tags: vec!["lab".into()],
                notes: "the old one".into(),
                ..conn("alpha")
            }],
            ..Default::default()
        }
    }

    /// `name` in a fresh directory that's cleaned up by the OS's temp policy.
    fn temp_path(test: &str, name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("xrdp-gui-backup-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn a_backup_round_trips_through_a_private_file_without_password_flags() {
        let path = temp_path("roundtrip", "backup.toml");
        let backup = Backup::of(&sample());
        backup.write(&path).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!path.with_extension("toml.tmp").exists());

        let text = fs::read_to_string(&path).unwrap();
        assert!(!text.contains("has_saved_password = true"));
        assert!(!text.contains("has_saved_gateway_password = true"));

        let read = Backup::read(&path).unwrap();
        assert_eq!(read, backup);
        assert_eq!(read.connections[0].notes, "the old one");
        assert_eq!(read.settings.client, "xfreerdp");
    }

    #[test]
    fn writing_replaces_a_more_open_file() {
        let path = temp_path("perms", "backup.toml");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        Backup::of(&sample()).write(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn other_files_are_refused() {
        let empty = Backup::parse("").unwrap_err().to_string();
        assert!(empty.contains("isn't an xrdp-gui backup"), "{empty}");

        // The app's own config is valid TOML with the right tables, but isn't a backup.
        let config = toml::to_string_pretty(&sample()).unwrap();
        assert!(Backup::parse(&config).is_err());

        assert!(Backup::parse("not toml = = =").is_err());
        let newer = format!("format = \"{FORMAT}\"\nversion = {}\n", VERSION + 1);
        let newer = Backup::parse(&newer).unwrap_err().to_string();
        assert!(newer.contains("newer version"), "{newer}");
    }

    #[test]
    fn duplicates_in_a_file_are_made_harmless() {
        let mut backup = Backup::of(&sample());
        backup.connections.push(backup.connections[0].clone());
        backup.groups.push(backup.groups[0].clone());
        let read = Backup::parse(&toml::to_string_pretty(&backup).unwrap()).unwrap();
        assert_eq!(read.connections.len(), 2);
        assert_ne!(read.connections[0].id, read.connections[1].id);
        assert_eq!(read.groups.len(), 1);
    }

    #[test]
    fn add_only_adds() {
        let mut here = sample();
        let mut backup = Backup::of(&here);
        here.connections[0].notes = "edited since".into();
        here.settings.client = "sdl-freerdp".into();
        backup.connections.push(conn("beta"));
        backup.groups.push(Group {
            name: "Home".into(),
            ..Default::default()
        });
        backup.groups[0].domain = "OTHER".into();

        let outcome = backup.restore(&mut here, RestoreMode::Add);

        assert_eq!(outcome.added_connections, 1);
        assert_eq!(outcome.added_groups, 1);
        assert!(outcome.stale_passwords.is_empty());
        assert_eq!(here.connections.len(), 2);
        assert_eq!(here.connections[0].notes, "edited since");
        assert!(here.connections[0].has_saved_password);
        assert_eq!(here.groups[0].domain, "CORP");
        assert!(here.groups[0].has_saved_password);
        assert_eq!(here.settings.client, "sdl-freerdp");

        // Doing it again finds nothing new.
        let again = backup.restore(&mut here, RestoreMode::Add);
        assert_eq!(again, Outcome::default());
        assert_eq!(here.connections.len(), 2);
    }

    #[test]
    fn replace_matches_the_backup_and_keeps_passwords_of_what_stays() {
        let mut here = sample();
        let backup = Backup::of(&here);
        here.connections[0].notes = "edited since".into();
        let extra = Connection {
            has_saved_password: true,
            has_saved_gateway_password: true,
            ..conn("gone")
        };
        let plain = conn("gone-no-password");
        let (extra_id, plain_id) = (extra.id, plain.id);
        here.connections.extend([extra, plain]);
        here.groups.push(Group {
            name: "Gone".into(),
            has_saved_password: true,
            has_saved_gateway_password: true,
            ..Default::default()
        });
        here.settings.client = "other".into();

        let outcome = backup.restore(&mut here, RestoreMode::Replace);

        assert_eq!(here.connections.len(), 1);
        assert_eq!(here.connections[0].notes, "the old one");
        assert!(here.connections[0].has_saved_password);
        assert!(here.connections[0].has_saved_gateway_password);
        assert!(here.groups[0].has_saved_password);
        assert_eq!(here.groups.len(), 1);
        assert_eq!(here.settings.client, "xfreerdp");
        assert_eq!(outcome.added_connections, 0);
        assert_eq!(outcome.removed_connections, 2);
        assert_eq!(outcome.removed_groups, 1);
        assert_eq!(
            outcome.stale_passwords,
            [
                Key::Rdp(extra_id),
                Key::Gateway(extra_id),
                Key::GroupRdp("Gone".into()),
                Key::GroupGateway("Gone".into()),
            ]
        );
        assert!(!outcome.stale_passwords.contains(&Key::Rdp(plain_id)));
    }

    /// On another computer, or for something deleted here, the keyring has no password,
    /// even if a file edited by hand claims otherwise.
    #[test]
    fn restored_entries_never_claim_a_password_this_computer_lacks() {
        let mut backup = Backup::of(&sample());
        backup.connections[0].has_saved_password = true;
        backup.connections[0].has_saved_gateway_password = true;
        backup.groups[0].has_saved_password = true;
        backup.groups[0].has_saved_gateway_password = true;
        for mode in [RestoreMode::Add, RestoreMode::Replace] {
            let mut here = Config::default();
            backup.restore(&mut here, mode);
            assert!(!here.connections[0].has_saved_password);
            assert!(!here.connections[0].has_saved_gateway_password);
            assert!(!here.groups[0].has_saved_password);
            assert!(!here.groups[0].has_saved_gateway_password);
        }
    }

    #[test]
    fn certificates_awaiting_review_survive_a_restore() {
        let review = CertReview {
            host: "pc1".into(),
            port: 3389,
        };
        let mut here = Config {
            cert_review: vec![review.clone()],
            ..Default::default()
        };
        Backup::of(&sample()).restore(&mut here, RestoreMode::Replace);
        assert_eq!(here.cert_review, [review]);
    }

    #[test]
    fn preview_changes_nothing() {
        let here = sample();
        let before = toml::to_string(&here).unwrap();
        let mut backup = Backup::of(&here);
        backup.connections.clear();
        let outcome = backup.preview(&here, RestoreMode::Replace);
        assert_eq!(outcome.removed_connections, 1);
        assert_eq!(toml::to_string(&here).unwrap(), before);
    }

    #[test]
    fn a_different_client_or_terminal_is_noticed() {
        let here = sample();
        let mut backup = Backup::of(&here);
        assert!(!backup.changes_programs(&here));
        backup.settings.terminal = "something-else -e".into();
        assert!(backup.changes_programs(&here));
    }

    #[test]
    fn risky_entries_are_counted() {
        let mut backup = Backup::of(&sample());
        assert_eq!(backup.risky_entries(), 0);
        backup.connections[0].extra_args = "/drive:all,/".into();
        backup.connections.push(Connection {
            cert: Some(CertPolicy::Ignore),
            ..conn("b")
        });
        backup.groups[0].cert = Some(CertPolicy::Ignore);
        assert_eq!(backup.risky_entries(), 3);
    }
}
