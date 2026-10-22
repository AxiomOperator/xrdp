//! Translates a resolved [`Connection`](crate::model::Connection) into FreeRDP 3
//! command-line arguments.

use anyhow::{Result, bail};

use crate::model::{CertPolicy, GatewayTarget, Resolved, Settings};

/// Window class / app id for session windows. It matches `xrdp-gui-session.desktop`, so
/// the desktop shows our icon on them, while keeping them apart from the main window
/// (and its remember-position rule).
pub const SESSION_APP_ID: &str = "xrdp-gui-session";

/// FreeRDP logs reconnect attempts at INFO under this tag; we watch for them.
const RECONNECT_LOG_TAG: &str = "com.freerdp.client.common";

pub struct Credentials<'a> {
    pub password: Option<&'a str>,
    pub gateway_password: Option<&'a str>,
}

pub fn build_args(r: &Resolved, settings: &Settings, creds: &Credentials) -> Result<Vec<String>> {
    let conn = &r.conn;
    let host = conn.host.trim();
    if host.is_empty() {
        bail!("host is required");
    }

    let mut args = vec![format!("/v:{host}")];
    if conn.port != 3389 {
        args.push(format!("/port:{}", conn.port));
    }
    push_nonempty(&mut args, "/u:", &conn.username);
    push_nonempty(&mut args, "/d:", &r.domain);
    if let Some(p) = creds.password {
        args.push(format!("/p:{p}"));
    }
    args.push(format!("/t:{}", conn.display_name()));
    // xfreerdp (X11/XWayland) reads this; sdl-freerdp gets SDL_APP_ID instead (see Session::spawn).
    args.push(format!("/wm-class:{SESSION_APP_ID}"));

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
    args.extend(r.profile.args().iter().map(|a| a.to_string()));

    if conn.auto_reconnect {
        args.push("+auto-reconnect".into());
        args.push(format!(
            "/auto-reconnect-max-retries:{}",
            conn.reconnect_retries
        ));
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

    if let Some(gw) = &r.gateway {
        args.push(gateway_arg(gw, &conn.username, &r.domain, creds)?);
    }

    match r.cert {
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
        if conn.auto_reconnect && !matches!(settings.log_level.as_str(), "INFO" | "DEBUG" | "TRACE")
        {
            args.push(format!("/log-filters:{RECONNECT_LOG_TAG}:INFO"));
        }
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

fn gateway_arg(
    gw: &GatewayTarget,
    username: &str,
    domain: &str,
    creds: &Credentials,
) -> Result<String> {
    if gw.host.is_empty() {
        match &gw.from_group {
            Some(g) => bail!("group “{g}” has a gateway enabled but no gateway host"),
            None => bail!("gateway host is required when the gateway is enabled"),
        }
    }
    let (user, domain, password) = if gw.same_credentials {
        (username.trim(), domain, creds.password)
    } else {
        (
            gw.username.as_str(),
            gw.domain.as_str(),
            creds.gateway_password,
        )
    };

    // The gateway option uses ',' as its sub-option separator.
    for (what, value) in [
        ("host", gw.host.as_str()),
        ("username", user),
        ("domain", domain),
    ]
    .into_iter()
    .chain(password.map(|p| ("password", p)))
    {
        if value.contains(',') {
            bail!("gateway {what} cannot contain ','");
        }
    }

    let mut parts = vec![format!("g:{}", gw.host)];
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
            .map(|p| {
                if p.starts_with("p:") {
                    "p:***".into()
                } else {
                    p.to_string()
                }
            })
            .collect();
        return format!("/gateway:{}", parts.join(","));
    }
    arg.to_string()
}

/// A shell-quoted, password-masked rendering of the full command line.
pub fn preview(client: &str, args: &[String]) -> String {
    std::iter::once(client.to_string())
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
    use crate::model::{Config, Connection, GatewayMode, Group, Profile};

    fn conn() -> Connection {
        Connection {
            name: "Lab".into(),
            host: "rdp.example.com".into(),
            username: "alice".into(),
            domain: "CORP".into(),
            ..Default::default()
        }
    }

    fn build(c: &Connection, creds: &Credentials) -> Result<Vec<String>> {
        build_args(&Config::default().resolve(c), &Settings::default(), creds)
    }

    const NO_CREDS: Credentials = Credentials {
        password: None,
        gateway_password: None,
    };

    #[test]
    fn basic_windowed() {
        let c = Connection {
            auto_reconnect: false,
            ..conn()
        };
        let args = build(&c, &NO_CREDS).unwrap();
        assert_eq!(
            args,
            [
                "/v:rdp.example.com",
                "/u:alice",
                "/d:CORP",
                "/t:Lab",
                "/wm-class:xrdp-gui-session",
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
        let args = build(&c, &NO_CREDS).unwrap();
        assert!(args.contains(&"/port:3390".into()));
        assert!(args.contains(&"+f".into()));
        assert!(args.contains(&"/multimon".into()));
        assert!(args.contains(&"-clipboard".into()));
        assert!(!args.iter().any(|a| a.starts_with("/size")));
        assert!(args.ends_with(&["/drive:My Docs,/tmp".into(), "+admin".into()]));
    }

    #[test]
    fn auto_reconnect_and_profile() {
        let c = Connection {
            reconnect_retries: 7,
            profile: Some(Profile::Lan),
            ..conn()
        };
        let args = build(&c, &NO_CREDS).unwrap();
        for want in [
            "+auto-reconnect",
            "/auto-reconnect-max-retries:7",
            "/network:lan",
            "/gfx:AVC444",
            "/log-filters:com.freerdp.client.common:INFO",
        ] {
            assert!(args.contains(&want.into()), "missing {want} in {args:?}");
        }
        let wan = Connection {
            profile: Some(Profile::Wan),
            ..conn()
        };
        let args = build(&wan, &NO_CREDS).unwrap();
        assert!(args.contains(&"/network:wan".into()));
        assert!(args.contains(&"-wallpaper".into()));
    }

    #[test]
    fn gateway_and_masking() {
        let c = Connection {
            gateway: GatewayMode::On,
            gateway_host: "gw.example.com".into(),
            ..conn()
        };
        let creds = Credentials {
            password: Some("s3cret pass"),
            gateway_password: None,
        };
        let args = build(&c, &creds).unwrap();
        assert!(args.contains(&"/p:s3cret pass".into()));
        assert!(args.contains(&"/gateway:g:gw.example.com,u:alice,d:CORP,p:s3cret pass".into()));

        let shown = preview("sdl-freerdp", &args);
        assert!(!shown.contains("s3cret"), "{shown}");
        assert!(shown.contains("/gateway:g:gw.example.com,u:alice,d:CORP,p:***"));
    }

    #[test]
    fn inherited_group_gateway_and_domain() {
        let config = Config {
            groups: vec![Group {
                name: "Work".into(),
                domain: "FB".into(),
                gateway_enabled: true,
                gateway_host: "gw.fb".into(),
                gateway_same_credentials: false,
                gateway_username: "gwuser".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let c = Connection {
            group: "Work".into(),
            domain: String::new(),
            ..conn()
        };
        let creds = Credentials {
            password: Some("pw"),
            gateway_password: Some("gwpw"),
        };
        let args = build_args(&config.resolve(&c), &Settings::default(), &creds).unwrap();
        assert!(args.contains(&"/d:FB".into()));
        assert!(
            args.contains(&"/gateway:g:gw.fb,u:gwuser,p:gwpw".into()),
            "{args:?}"
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(build(&Connection::default(), &NO_CREDS).is_err());
        let creds = Credentials {
            password: Some("a\nb"),
            gateway_password: None,
        };
        assert!(build(&conn(), &creds).is_err());
        let c = Connection {
            extra_args: "\"unterminated".into(),
            ..conn()
        };
        assert!(build(&c, &NO_CREDS).is_err());
    }
}
