//! Password storage in the desktop keyring (Secret Service: KWallet, GNOME Keyring, ...).

use anyhow::{Context, Result};
use keyring::{Entry, Error};
use uuid::Uuid;

const SERVICE: &str = "xrdp-gui";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Key {
    Rdp(Uuid),
    Gateway(Uuid),
    GroupGateway(String),
}

impl Key {
    fn account(&self) -> String {
        match self {
            Key::Rdp(id) => format!("{id}"),
            Key::Gateway(id) => format!("{id}:gateway"),
            Key::GroupGateway(name) => format!("group:{name}:gateway"),
        }
    }

    fn entry(&self) -> Result<Entry> {
        Entry::new(SERVICE, &self.account()).context("keyring unavailable")
    }
}

pub fn get(key: &Key) -> Result<Option<String>> {
    match key.entry()?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("reading password from keyring"),
    }
}

pub fn set(key: &Key, password: &str) -> Result<()> {
    key.entry()?
        .set_password(password)
        .context("saving password to keyring")
}

pub fn delete(key: &Key) -> Result<()> {
    match key.entry()?.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting password from keyring"),
    }
}
