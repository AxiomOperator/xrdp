//! FreeRDP's store of trusted server certificates (`~/.config/freerdp/server`), which it
//! fills when a certificate is accepted (or trusted on first use).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use sha2::{Digest, Sha256};

pub struct KnownCert {
    pub path: PathBuf,
    pub host: String,
    pub port: u16,
    /// Common name of the subject, or the full subject if it has none.
    pub subject: String,
    pub issuer: String,
    pub expires: Option<DateTime<Local>>,
    /// SHA-256 of the certificate, as colon-separated hex.
    pub fingerprint: String,
    /// Set if the file could not be read as a certificate.
    pub error: Option<String>,
}

impl KnownCert {
    pub fn expired(&self) -> bool {
        self.expires.is_some_and(|t| t < Local::now())
    }
}

pub fn dir() -> Result<PathBuf> {
    let dirs = directories::BaseDirs::new().context("could not determine config directory")?;
    Ok(dirs.config_dir().join("freerdp/server"))
}

/// Where FreeRDP keeps the certificate it trusts for `host:port`.
pub fn path_for(host: &str, port: u16) -> Result<PathBuf> {
    Ok(dir()?.join(format!("{}_{port}.pem", host.trim().to_lowercase())))
}

/// All trusted certificates, sorted by host.
pub fn list() -> Result<Vec<KnownCert>> {
    list_in(&dir()?)
}

fn list_in(dir: &Path) -> Result<Vec<KnownCert>> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut certs: Vec<KnownCert> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pem"))
        .map(|p| read(&p))
        .collect();
    certs.sort_by(|a, b| (&a.host, a.port).cmp(&(&b.host, b.port)));
    Ok(certs)
}

fn read(path: &Path) -> KnownCert {
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (host, port) = match stem.rsplit_once('_') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(3389)),
        None => (stem, 3389),
    };
    let mut cert = KnownCert {
        path: path.to_path_buf(),
        host,
        port,
        subject: String::new(),
        issuer: String::new(),
        expires: None,
        fingerprint: String::new(),
        error: None,
    };
    if let Err(e) = parse_into(path, &mut cert) {
        cert.error = Some(format!("{e:#}"));
    }
    cert
}

fn parse_into(path: &Path, cert: &mut KnownCert) -> Result<()> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&bytes)
        .map_err(|e| anyhow::anyhow!("not a PEM certificate: {e}"))?;
    let x509 = pem
        .parse_x509()
        .map_err(|e| anyhow::anyhow!("invalid certificate: {e}"))?;
    let name = |n: &x509_parser::x509::X509Name| {
        n.iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .map(String::from)
            .unwrap_or_else(|| n.to_string())
    };
    cert.subject = name(x509.subject());
    cert.issuer = name(x509.issuer());
    cert.expires = DateTime::from_timestamp(x509.validity().not_after.timestamp(), 0)
        .map(|t| t.with_timezone(&Local));
    cert.fingerprint = Sha256::digest(&pem.contents)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(())
}

pub fn forget(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Self-signed, CN=xrdp-gui-test, valid for 100 years.
    const GOOD: &str = include_str!("../tests/data/test-cert.pem");
    /// A truncated certificate.
    const BROKEN: &str = "-----BEGIN CERTIFICATE-----
MIIBkjCB/AIJAKHHIGDHkHSUMA0GCSqGSIb3DQEBCwUAMBcxFTATBgNVBAMMDHRl
c3QuZXhhbXBsZTAeFw0yNDAxMDEwMDAwMDBaFw0zNDAxMDEwMDAwMDBaMBcxFTAT
BgNVBAMMDHRlc3QuZXhhbXBsZTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQC7o96F
-----END CERTIFICATE-----
";

    #[test]
    fn lists_and_parses() {
        let dir = std::env::temp_dir().join(format!("xrdp-gui-certs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("dc01.corp_3389.pem"), GOOD).unwrap();
        fs::write(dir.join("broken_3390.pem"), BROKEN).unwrap();
        fs::write(dir.join("notes.txt"), "ignored").unwrap();

        let certs = list_in(&dir).unwrap();
        assert_eq!(certs.len(), 2);
        let broken = &certs[0];
        assert_eq!((broken.host.as_str(), broken.port), ("broken", 3390));
        assert!(broken.error.is_some());
        let good = &certs[1];
        assert_eq!((good.host.as_str(), good.port), ("dc01.corp", 3389));
        assert!(good.error.is_none(), "{:?}", good.error);
        assert_eq!(good.subject, "xrdp-gui-test");
        assert_eq!(good.fingerprint.len(), 32 * 3 - 1);
        assert!(good.expires.is_some());

        forget(&good.path).unwrap();
        assert_eq!(list_in(&dir).unwrap().len(), 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
