//! Password storage in the desktop keyring (Secret Service: KWallet, GNOME Keyring, ...).

use anyhow::{Context, Result};
use keyring::{Entry, Error};
use uuid::Uuid;

const SERVICE: &str = "xrdp-gui";

#[derive(Debug, Clone, Copy)]
pub enum Kind {
    Rdp,
    Gateway,
}

fn entry(id: Uuid, kind: Kind) -> Result<Entry> {
    let account = match kind {
        Kind::Rdp => format!("{id}"),
        Kind::Gateway => format!("{id}:gateway"),
    };
    Entry::new(SERVICE, &account).context("keyring unavailable")
}

pub fn get(id: Uuid, kind: Kind) -> Result<Option<String>> {
    match entry(id, kind)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(Error::NoEntry) => Ok(None),
        Err(e) => Err(e).context("reading password from keyring"),
    }
}

pub fn set(id: Uuid, kind: Kind, password: &str) -> Result<()> {
    entry(id, kind)?
        .set_password(password)
        .context("saving password to keyring")
}

pub fn delete(id: Uuid, kind: Kind) -> Result<()> {
    match entry(id, kind)?.delete_credential() {
        Ok(()) | Err(Error::NoEntry) => Ok(()),
        Err(e) => Err(e).context("deleting password from keyring"),
    }
}
