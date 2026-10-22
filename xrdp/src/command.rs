//! Translates a [`Connection`] into FreeRDP 3 command-line arguments.

use anyhow::{bail, Result};

use crate::model::{CertPolicy, Connection, Settings};

pub struct Credentials<'a> {
    pub password: Option<&'a str>,
    pub gateway_password: Option<&'a str>,
}

pub fn build_args(conn: &Connection, settings: &Settings, creds: &Credentials) -> Result<Vec<String>> {
    let host = conn.host.trim();
    if host.is_empty() {
        bail!("host is required");
    }

    let mut args = vec![format!("/v:{host}")];
    if conn.port != 3389 {
        args.push(format!("/port:{}", conn.port));
    }
    push_nonempty(&mut args, "/u:", &conn.username);
    push_nonempty(&mut args, "/d:", &conn.domain);
    if let Some(p) = creds.password {
        args.push(format!("/p:{p}"));
    }
    args.push(format!("/t:{}", conn.display_name()));

    if conn.fullscreen {
        args.push("+f".into());
        if conn.multimon {
            args.push("/multimon".into());
        }
    } else {
        args.push(format!("/size:{}x{}", conn.width, conn.height));
    }
    if conn.dynamic_resolution {
        args.push("+dynamic-resolution".into());
    }

    if !conn.clipboard {
        args.push("-clipboard".into());
    }
    if conn.home_drive {
        args.push("+home-drive".into());
    }
    if conn.sound {
        args.push("/sound".into());
    }
    if conn.microphone {
        args.push("/microphone".into());
    }

    if conn.gateway_enabled {
        args.push(gateway_arg(conn, creds)?);
    }

    match conn.cert {
        CertPolicy::Ask => {}
        CertPolicy::Tofu => args.push("/cert:tofu".into()),
        CertPolicy::Deny => args.push("/cert:deny".into()),
        CertPolicy::Ignore => args.push("/cert:ignore".into()),
    }
    if conn.admin {
        args.push("+admin".into());
    }
    if !settings.log_level.is_empty() {
        args.push(format!("/log-level:{}", settings.log_level));
    }

    let extra = conn.extra_args.trim();
    if !extra.is_empty() {
        match shlex::split(extra) {
            Some(extra) => args.extend(extra),
            None => bail!("extra arguments have unbalanced quotes"),
        }
    }

    // Arguments are passed to FreeRDP one per line via `/args-from:stdin`.
    if let Some(bad) = args.iter().find(|a| a.contains(['\n', '\r'])) {
        bail!("argument contains a line break: {}", mask(bad));
    }
    Ok(args)
}

fn gateway_arg(conn: &Connection, creds: &Credentials) -> Result<String> {
    let gw_host = conn.gateway_host.trim();
    if gw_host.is_empty() {
        bail!("gateway host is required when the gateway is enabled");
    }
    let (user, domain, password) = if conn.gateway_same_credentials {
        (conn.username.trim(), conn.domain.trim(), creds.password)
    } else {
        (conn.gateway_username.trim(), conn.gateway_domain.trim(), creds.gateway_password)
    };

    // The gateway option uses ',' as its sub-option separator.
    for (what, value) in [("host", gw_host), ("username", user), ("domain", domain)]
        .into_iter()
        .chain(password.map(|p| ("password", p)))
    {
        if value.contains(',') {
            bail!("gateway {what} cannot contain ','");
        }
    }

    let mut parts = vec![format!("g:{gw_host}")];
    if !user.is_empty() {
        parts.push(format!("u:{user}"));
    }
    if !domain.is_empty() {
        parts.push(format!("d:{domain}"));
    }
    if let Some(p) = password {
        parts.push(format!("p:{p}"));
    }
    Ok(format!("/gateway:{}", parts.join(",")))
}

fn push_nonempty(args: &mut Vec<String>, prefix: &str, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        args.push(format!("{prefix}{value}"));
    }
}

/// Replaces password values with `***` so arguments can be displayed or logged.
pub fn mask(arg: &str) -> String {
    if arg.starts_with("/p:") {
        return "/p:***".into();
    }
    if let Some(rest) = arg.strip_prefix("/gateway:") {
        let parts: Vec<String> = rest
            .split(',')
            .map(|p| if p.starts_with("p:") { "p:***".into() } else { p.to_string() })
            .collect();
        return format!("/gateway:{}", parts.join(","));
    }
    arg.to_string()
}

/// A shell-quoted, password-masked rendering of the full command line.
pub fn preview(settings: &Settings, args: &[String]) -> String {
    std::iter::once(settings.client.clone())
        .chain(args.iter().map(|a| {
            let m = mask(a);
            shlex::try_quote(&m).map(|q| q.into_owned()).unwrap_or(m)
        }))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn() -> Connection {
        Connection {
            name: "Lab".into(),
            host: "rdp.example.com".into(),
            username: "alice".into(),
            domain: "CORP".into(),
            ..Default::default()
        }
    }

    const NO_CREDS: Credentials = Credentials { password: None, gateway_password: None };

    #[test]
    fn basic_windowed() {
        let args = build_args(&conn(), &Settings::default(), &NO_CREDS).unwrap();
        assert_eq!(
            args,
            [
                "/v:rdp.example.com",
                "/u:alice",
                "/d:CORP",
                "/t:Lab",
                "/size:1600x900",
                "+dynamic-resolution",
                "/sound",
                "/cert:tofu",
                "/log-level:WARN",
            ]
        );
    }

    #[test]
    fn fullscreen_multimon_port_and_extras() {
        let c = Connection {
            port: 3390,
            fullscreen: true,
            multimon: true,
            dynamic_resolution: false,
            clipboard: false,
            extra_args: r#"/drive:"My Docs",/tmp +admin"#.into(),
            ..conn()
        };
        let args = build_args(&c, &Settings::default(), &NO_CREDS).unwrap();
        assert!(args.contains(&"/port:3390".into()));
        assert!(args.contains(&"+f".into()));
        assert!(args.contains(&"/multimon".into()));
        assert!(args.contains(&"-clipboard".into()));
        assert!(!args.iter().any(|a| a.starts_with("/size")));
        assert!(args.ends_with(&["/drive:My Docs,/tmp".into(), "+admin".into()]));
    }

    #[test]
    fn gateway_and_masking() {
        let c = Connection {
            gateway_enabled: true,
            gateway_host: "gw.example.com".into(),
            ..conn()
        };
        let creds = Credentials { password: Some("s3cret pass"), gateway_password: None };
        let args = build_args(&c, &Settings::default(), &creds).unwrap();
        assert!(args.contains(&"/p:s3cret pass".into()));
        assert!(args.contains(&"/gateway:g:gw.example.com,u:alice,d:CORP,p:s3cret pass".into()));

        let shown = preview(&Settings::default(), &args);
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("/gateway:g:gw.example.com,u:alice,d:CORP,p:***"));
    }

    #[test]
    fn rejects_bad_input() {
        let s = Settings::default();
        assert!(build_args(&Connection::default(), &s, &NO_CREDS).is_err());
        let creds = Credentials { password: Some("a\nb"), gateway_password: None };
        assert!(build_args(&conn(), &s, &creds).is_err());
        let c = Connection { extra_args: "\"unterminated".into(), ..conn() };
        assert!(build_args(&c, &s, &NO_CREDS).is_err());
    }
}
