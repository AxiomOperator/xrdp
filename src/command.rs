//! Translates a resolved [`Connection`](crate::model::Connection) into FreeRDP 3
//! command-line arguments.

use anyhow::{Result, bail};

use crate::model::{CertPolicy, ClipboardShare, GatewayTarget, Protocol, Resolved, Settings};

/// Window class / app id for session windows. It matches `xrdp-gui-session.desktop`, so
/// the desktop shows our icon on them, while keeping them apart from the main window
/// (and its remember-position rule).
pub const SESSION_APP_ID: &str = "xrdp-gui-session";

/// FreeRDP logs reconnect attempts at INFO under this tag; we watch for them.
const RECONNECT_LOG_TAG: &str = "com.freerdp.client.common";

/// Terminals known to stay running until their command ends, so the session list is
/// right, with the arguments that make them run a command.
const TERMINALS: &[(&str, &[&str])] = &[
    ("konsole", &["--nofork", "-e"]),
    ("gnome-terminal", &["--wait", "--"]),
    ("ptyxis", &["--standalone", "--"]),
    ("xfce4-terminal", &["--disable-server", "-x"]),
    ("alacritty", &["-e"]),
    ("kitty", &[]),
    ("foot", &[]),
    ("wezterm", &["start", "--always-new-process", "--"]),
    ("xterm", &["-e"]),
];

/// Runs `ssh` with its arguments as `$@`. Terminals close when their command ends, which
/// would take an error message with them, so a failure waits for a key press. Only exit
/// code 255 is `ssh`'s own: anything else is what the remote shell ended with.
const SSH_WRAPPER: &str = r#"ssh "$@"
status=$?
if [ "$status" -eq 255 ]; then
    printf '\nThe connection failed or dropped. Press Enter to close this window. '
    read -r _
fi
exit "$status""#;

pub struct Credentials<'a> {
    pub password: Option<&'a str>,
    pub gateway_password: Option<&'a str>,
}

/// The arguments for `ssh`. Leaves signing in to `ssh`, so keys, the agent and
/// `~/.ssh/config` all work, and host keys are checked as usual.
pub fn ssh_args(r: &Resolved) -> Result<Vec<String>> {
    let conn = &r.conn;
    let host = conn.host.trim().trim_matches(['[', ']']);
    if host.is_empty() {
        bail!("host is required");
    }
    // `ssh` would read a host like `-oProxyCommand=…` as an option, and run it.
    if host.starts_with('-') || host.contains(char::is_whitespace) {
        bail!("“{host}” isn't a valid host name");
    }
    let mut args = Vec::new();
    if conn.port != Protocol::Ssh.default_port() {
        args.extend(["-p".to_string(), conn.port.to_string()]);
    }
    if !r.username.is_empty() {
        args.extend(["-l".to_string(), r.username.clone()]);
    }
    let extra = conn.extra_args.trim();
    if !extra.is_empty() {
        match shlex::split(extra) {
            Some(extra) => args.extend(extra),
            None => bail!("extra arguments have unbalanced quotes"),
        }
    }
    args.extend(["--".to_string(), host.to_string()]);
    Ok(args)
}

/// The full command that opens a terminal running `ssh` with `ssh_args`.
pub fn terminal_command(settings: &Settings, ssh_args: &[String]) -> Result<Vec<String>> {
    let mut argv = terminal_prefix(&settings.terminal, on_path)?;
    argv.extend(["sh", "-c", SSH_WRAPPER, "ssh"].map(String::from));
    argv.extend_from_slice(ssh_args);
    Ok(argv)
}

/// The terminal command for a setting: its words as given, except that the bare name of
/// a known terminal also gets the arguments it needs. Empty picks an installed one.
fn terminal_prefix(setting: &str, installed: impl Fn(&str) -> bool) -> Result<Vec<String>> {
    let with_args = |name: &str, args: &[&str]| {
        std::iter::once(name)
            .chain(args.iter().copied())
            .map(String::from)
            .collect::<Vec<_>>()
    };
    let setting = setting.trim();
    if setting.is_empty() {
        return match TERMINALS.iter().find(|(name, _)| installed(name)) {
            Some((name, args)) => Ok(with_args(name, args)),
            None => bail!("No terminal program found. Set one in Settings to use SSH."),
        };
    }
    if let Some((name, args)) = TERMINALS.iter().find(|(name, _)| *name == setting) {
        return Ok(with_args(name, args));
    }
    match shlex::split(setting) {
        Some(words) if !words.is_empty() => Ok(words),
        _ => bail!("the terminal command in Settings has unbalanced quotes"),
    }
}

/// The FreeRDP client that can draw inside another window, if there is one.
pub fn embeddable_client(settings: &Settings) -> Option<String> {
    if settings.client.contains("xfreerdp") {
        return Some(settings.client.clone());
    }
    on_path("xfreerdp").then(|| "xfreerdp".to_string())
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|paths| std::env::split_paths(&paths).any(|dir| dir.join(program).is_file()))
}

pub fn build_args(r: &Resolved, settings: &Settings, creds: &Credentials) -> Result<Vec<String>> {
    let conn = &r.conn;
    let host = conn.host.trim();
    if host.is_empty() {
        bail!("host is required");
    }

    let mut args = vec![host_arg(host)];
    if conn.port != 3389 {
        args.push(format!("/port:{}", conn.port));
    }
    push_nonempty(&mut args, "/u:", &r.username);
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
    if let Some(p) = r.scale.filter(|&p| p != 100) {
        // Desktop scale takes any percentage; the device (app) scale only these three.
        let device = match p {
            ..=120 => 100,
            121..=160 => 140,
            _ => 180,
        };
        args.push(format!("/scale-desktop:{p}"));
        args.push(format!("/scale-device:{device}"));
    }
    args.extend(r.profile.args().iter().map(|a| a.to_string()));

    if conn.auto_reconnect {
        args.push("+auto-reconnect".into());
        args.push(format!(
            "/auto-reconnect-max-retries:{}",
            conn.reconnect_retries
        ));
    }

    match (conn.clipboard_text, conn.clipboard_files) {
        (ClipboardShare::Off, ClipboardShare::Off) => args.push("-clipboard".into()),
        // FreeRDP's default.
        (ClipboardShare::Both, ClipboardShare::Both) => {}
        (text, files) => args.push(format!(
            "/clipboard:direction-to:{},files-to:{}",
            text.freerdp(),
            files.freerdp()
        )),
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
        args.push(gateway_arg(gw, &r.username, &r.domain, creds)?);
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
        (username.trim(), domain.trim(), creds.password)
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

/// FreeRDP reads `/v:` up to the first ':' as the host, so an IPv6 address needs brackets.
fn host_arg(host: &str) -> String {
    if host.matches(':').count() >= 2 && !host.starts_with('[') {
        format!("/v:[{host}]")
    } else {
        format!("/v:{host}")
    }
}

fn push_nonempty(args: &mut Vec<String>, prefix: &str, value: &str) {
    let value = value.trim();
    if !value.is_empty() {
        args.push(format!("{prefix}{value}"));
    }
}

/// Replaces passwords, hashes and tokens with `***` so arguments can be displayed or
/// logged. Extra arguments are free-form, so this covers FreeRDP's options that take them.
pub fn mask(arg: &str) -> String {
    for prefix in ["/p:", "/pth:", "/assistance:", "/endpointfedauth:"] {
        if arg.starts_with(prefix) {
            return format!("{prefix}***");
        }
    }
    // [<proto>://][<user>:<password>@]<host>[:<port>]
    if let Some(rest) = arg.strip_prefix("/proxy:")
        && let Some((credentials, host)) = rest.rsplit_once('@')
    {
        let (scheme, credentials) = match credentials.split_once("://") {
            Some((scheme, rest)) => (format!("{scheme}://"), rest),
            None => (String::new(), credentials),
        };
        let user = credentials.split(':').next().unwrap_or_default();
        return format!("/proxy:{scheme}{user}:***@{host}");
    }
    for option in ["/gateway:", "/smartcard-logon:"] {
        if let Some(rest) = arg.strip_prefix(option) {
            let parts: Vec<String> = rest
                .split(',')
                .map(|part| {
                    match ["p:", "access-token:", "bearer:", "pin:"]
                        .into_iter()
                        .find(|key| part.starts_with(key))
                    {
                        Some(key) => format!("{key}***"),
                        None => part.to_string(),
                    }
                })
                .collect();
            return format!("{option}{}", parts.join(","));
        }
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

    fn ssh(c: Connection) -> Result<Vec<String>> {
        ssh_args(&Config::default().resolve(&Connection {
            protocol: Protocol::Ssh,
            port: 22,
            ..c
        }))
    }

    #[test]
    fn ssh_arguments() {
        let plain = Connection {
            host: " pc1 ".into(),
            ..Default::default()
        };
        assert_eq!(ssh(plain).unwrap(), ["--", "pc1"]);

        let config = Config::default();
        let full = config.resolve(&Connection {
            protocol: Protocol::Ssh,
            host: "[::1]".into(),
            port: 2222,
            username: "bob".into(),
            domain: "IGNORED".into(),
            extra_args: r#"-i "~/my key""#.into(),
            ..Default::default()
        });
        assert_eq!(
            ssh_args(&full).unwrap(),
            ["-p", "2222", "-l", "bob", "-i", "~/my key", "--", "::1"]
        );
    }

    #[test]
    fn ssh_refuses_hosts_it_would_read_as_options() {
        for host in ["-oProxyCommand=touch /tmp/x", "a b", "  ", ""] {
            let c = Connection {
                host: host.into(),
                ..Default::default()
            };
            assert!(ssh(c).is_err(), "{host:?}");
        }
    }

    #[test]
    fn terminal_is_found_or_taken_from_the_setting() {
        let only = |want: &'static str| move |name: &str| name == want;
        assert_eq!(
            terminal_prefix("", only("konsole")).unwrap(),
            ["konsole", "--nofork", "-e"]
        );
        assert_eq!(terminal_prefix("", only("foot")).unwrap(), ["foot"]);
        assert!(terminal_prefix("", |_| false).is_err());
        // A known name gets what it needs, even if a different terminal is installed.
        assert_eq!(
            terminal_prefix("gnome-terminal", only("konsole")).unwrap(),
            ["gnome-terminal", "--wait", "--"]
        );
        assert_eq!(
            terminal_prefix("my-term --flag 'a b' -e", |_| false).unwrap(),
            ["my-term", "--flag", "a b", "-e"]
        );
        assert!(terminal_prefix("bad 'quote", |_| false).is_err());
    }

    /// Runs the real wrapper with a stand-in `ssh`, as a terminal would.
    fn run_wrapper(test: &str, exit: u8) -> (std::process::Output, String) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("xrdp-gui-wrap-{test}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let seen = dir.join("seen");
        let fake = dir.join("ssh");
        std::fs::write(
            &fake,
            format!(
                "#!/bin/sh\nfor a in \"$@\"; do echo \"[$a]\" >> '{}'; done\nexit {exit}\n",
                seen.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!("{}:{}", dir.display(), std::env::var("PATH").unwrap());
        let output = std::process::Command::new("sh")
            .args(["-c", SSH_WRAPPER, "ssh", "-i", "my key", "--", "pc1"])
            .env("PATH", path)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        (output, std::fs::read_to_string(seen).unwrap())
    }

    #[test]
    fn wrapper_passes_arguments_intact_and_waits_only_on_ssh_errors() {
        let (failed, seen) = run_wrapper("failed", 255);
        assert_eq!(seen, "[-i]\n[my key]\n[--]\n[pc1]\n");
        assert_eq!(failed.status.code(), Some(255));
        assert!(String::from_utf8_lossy(&failed.stdout).contains("Press Enter"));

        // What the remote shell ended with is no reason to hold the window open.
        let (remote, _) = run_wrapper("remote", 3);
        assert_eq!(remote.status.code(), Some(3));
        assert!(remote.stdout.is_empty());
    }

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
    fn hidpi_scaling() {
        use crate::model::Scaling;
        let scaled = |scaling| {
            let c = Connection { scaling, ..conn() };
            build(&c, &NO_CREDS)
                .unwrap()
                .into_iter()
                .filter(|a| a.starts_with("/scale"))
                .collect::<Vec<_>>()
        };
        assert!(scaled(Scaling::Off).is_empty());
        assert!(scaled(Scaling::Percent(100)).is_empty());
        assert_eq!(
            scaled(Scaling::Percent(150)),
            ["/scale-desktop:150", "/scale-device:140"]
        );
        assert_eq!(
            scaled(Scaling::Percent(200)),
            ["/scale-desktop:200", "/scale-device:180"]
        );
    }

    #[test]
    fn group_credentials_are_used() {
        let config = Config {
            groups: vec![Group {
                name: "Work".into(),
                username: "svc".into(),
                domain: "CORP".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let c = Connection {
            group: "Work".into(),
            username: String::new(),
            domain: String::new(),
            ..conn()
        };
        let creds = Credentials {
            password: Some("pw"),
            gateway_password: None,
        };
        let args = build_args(&config.resolve(&c), &Settings::default(), &creds).unwrap();
        assert!(args.contains(&"/u:svc".into()), "{args:?}");
        assert!(args.contains(&"/d:CORP".into()));
        assert!(args.contains(&"/p:pw".into()));
    }

    #[test]
    fn fullscreen_multimon_port_and_extras() {
        let c = Connection {
            port: 3390,
            fullscreen: true,
            multimon: true,
            dynamic_resolution: false,
            clipboard_text: ClipboardShare::Off,
            clipboard_files: ClipboardShare::Off,
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
    fn shared_clipboard() {
        let clip = |clipboard_text, clipboard_files| {
            let c = Connection {
                clipboard_text,
                clipboard_files,
                ..conn()
            };
            build(&c, &NO_CREDS)
                .unwrap()
                .into_iter()
                .filter(|a| a.contains("clipboard"))
                .collect::<Vec<_>>()
        };
        use ClipboardShare::*;
        assert!(
            clip(Both, Both).is_empty(),
            "FreeRDP shares both ways by default"
        );
        assert_eq!(clip(Off, Off), ["-clipboard"]);
        assert_eq!(
            clip(Both, Off),
            ["/clipboard:direction-to:all,files-to:off"]
        );
        assert_eq!(
            clip(ToRemote, ToLocal),
            ["/clipboard:direction-to:remote,files-to:local"]
        );
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
    fn ipv6_hosts_get_brackets() {
        let v = |host: &str| {
            let c = Connection {
                host: host.into(),
                ..conn()
            };
            build(&c, &NO_CREDS).unwrap().remove(0)
        };
        assert_eq!(v("fe80::1"), "/v:[fe80::1]");
        assert_eq!(v("[fe80::1]"), "/v:[fe80::1]");
        assert_eq!(v("10.0.0.1"), "/v:10.0.0.1");
        assert_eq!(v("pc1:3390"), "/v:pc1:3390");
    }

    #[test]
    fn masks_every_kind_of_secret() {
        for (arg, shown) in [
            ("/p:hunter2", "/p:***"),
            ("/pth:hunter2", "/pth:***"),
            ("/assistance:hunter2", "/assistance:***"),
            ("/endpointfedauth:hunter2", "/endpointfedauth:***"),
            (
                "/proxy:http://bob:hunter2@proxy:3128",
                "/proxy:http://bob:***@proxy:3128",
            ),
            ("/proxy:bob:hunter2@proxy", "/proxy:bob:***@proxy"),
            ("/proxy:http://proxy:3128", "/proxy:http://proxy:3128"),
            (
                "/gateway:g:gw,access-token:hunter2,bearer:hunter2",
                "/gateway:g:gw,access-token:***,bearer:***",
            ),
            (
                "/smartcard-logon:pin:hunter2,csp:x",
                "/smartcard-logon:pin:***,csp:x",
            ),
            ("/size:1600x900", "/size:1600x900"),
        ] {
            assert_eq!(mask(arg), shown);
        }
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
