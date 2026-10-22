//! Turns FreeRDP log output and exit codes into plain-English explanations.

use std::process::ExitStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The session ended the way the user asked it to.
    Normal,
    /// An established session was lost.
    Dropped,
    /// The connection never came up.
    Failed,
}

/// A one-click remedy offered next to the explanation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fix {
    ForgetPassword,
    ForgetCertificate,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Diagnosis {
    pub title: String,
    pub hint: String,
    pub severity: Severity,
    pub fix: Option<Fix>,
    /// The FreeRDP code the explanation was derived from.
    pub code: Option<String>,
}

enum Pattern {
    Code(&'static str),
    CodePrefix(&'static str),
    Text(&'static str),
}

struct Rule {
    patterns: &'static [Pattern],
    title: &'static str,
    hint: &'static str,
    severity: Severity,
    fix: Option<Fix>,
}

use Pattern::{Code, CodePrefix, Text};
use Severity::{Dropped, Failed, Normal};

/// Ordered from most to least specific: FreeRDP often logs a precise code followed by
/// generic ones such as `ERRCONNECT_CONNECT_FAILED`.
const RULES: &[Rule] = &[
    Rule {
        patterns: &[
            Text("has changed!!!"),
            Text("does not match the certificate used for previous"),
        ],
        title: "The server's certificate changed",
        hint: "The computer presented a different certificate than last time. This is normal after it was \
               reinstalled or its certificate renewed, but can also mean someone is intercepting the connection. \
               If you expected the change, forget the saved certificate and connect again.",
        severity: Failed,
        fix: Some(Fix::ForgetCertificate),
    },
    Rule {
        patterns: &[
            Text("AutoReconnect retries exceeded"),
            Text("Automatic reconnection disabled, terminating"),
        ],
        title: "Connection lost",
        hint: "The network connection dropped and reconnecting failed. Check your network or VPN, then connect \
               again — your remote apps are usually still running.",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRINFO_LOGOFF_BY_USER"),
            Code("ERRINFO_RPC_INITIATED_LOGOFF"),
        ],
        title: "Signed out",
        hint: "You signed out of the remote session.",
        severity: Normal,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER"),
            Code("ERRCONNECT_CONNECT_CANCELLED"),
        ],
        title: "Disconnected",
        hint: "The session was disconnected by you. Apps left open keep running on the remote computer.",
        severity: Normal,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_LOGON_FAILURE"),
            Code("ERRCONNECT_WRONG_PASSWORD"),
            Code("ERRCONNECT_AUTHENTICATION_FAILED"),
        ],
        title: "Wrong username or password",
        hint: "Check the username, domain and password. If your password changed recently, forget the saved \
               one and connect again to enter the new one.",
        severity: Failed,
        fix: Some(Fix::ForgetPassword),
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_PASSWORD_EXPIRED"),
            Code("ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED"),
            Code("ERRCONNECT_PASSWORD_MUST_CHANGE"),
        ],
        title: "Your password has expired",
        hint: "Change your password (for example by pressing Ctrl+Alt+Del on a Windows PC, or through your \
               organisation's password portal), then connect again with the new one.",
        severity: Failed,
        fix: Some(Fix::ForgetPassword),
    },
    Rule {
        patterns: &[Code("ERRCONNECT_ACCOUNT_LOCKED_OUT")],
        title: "Your account is locked",
        hint: "Too many failed sign-ins locked the account. Wait for it to unlock or ask your IT administrator, \
               and make sure no device is retrying an old saved password.",
        severity: Failed,
        fix: Some(Fix::ForgetPassword),
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_ACCOUNT_DISABLED"),
            Code("ERRCONNECT_ACCOUNT_EXPIRED"),
            Code("ERRCONNECT_CLIENT_REVOKED"),
        ],
        title: "Your account is disabled or expired",
        hint: "The domain refused this account. Ask your IT administrator to re-enable it.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_LOGON_TYPE_NOT_GRANTED"),
            Code("ERRCONNECT_INSUFFICIENT_PRIVILEGES"),
            Code("ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES"),
            Code("ERRCONNECT_ACCOUNT_RESTRICTION"),
            Code("ERRCONNECT_ACCESS_DENIED"),
        ],
        title: "You're not allowed to sign in remotely",
        hint: "The password was accepted, but this account may not use Remote Desktop on that computer (or at \
               this time). Ask an administrator to add you to the “Remote Desktop Users” group.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_NO_OR_MISSING_CREDENTIALS")],
        title: "No credentials were provided",
        hint: "Enter a username and password for this connection, or save a password in the keyring.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_KDC_UNREACHABLE")],
        title: "Can't reach the domain controller",
        hint: "Kerberos sign-in needs a domain controller. Connect to the office network or VPN, or use a \
               password sign-in.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED")],
        title: "The server wants you to sign in again",
        hint: "This server does not accept saved credentials. Connect again and type your password.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_DNS_NAME_NOT_FOUND"),
            Code("ERRCONNECT_DNS_ERROR"),
        ],
        title: "Computer name not found",
        hint: "The host name doesn't resolve. Check for typos, use the IP address, or connect to the VPN if \
               it's an internal name.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_TARGET_BOOTING")],
        title: "The computer is still starting up",
        hint: "Wait a minute and connect again.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_HYBRID_REQUIRED_BY_SERVER")],
        title: "The server requires Network Level Authentication",
        hint: "Remove any /sec: option from the extra arguments and make sure a username is set.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_TLS_CONNECT_FAILED")],
        title: "Secure connection failed",
        hint: "The TLS handshake failed. The server may use outdated security settings, or something on the \
               network is interfering. The log has the details.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED")],
        title: "Security negotiation failed",
        hint: "Client and server couldn't agree on a security protocol. This often means wrong credentials \
               with NLA, or a server that only allows older protocols.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION")],
        title: "Someone else signed in",
        hint: "Another connection took over this session (perhaps you, from another device).",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_IDLE_TIMEOUT"), Code("ERRINFO_LOGON_TIMEOUT")],
        title: "Disconnected for inactivity",
        hint: "The server's idle or sign-in time limit was reached. Connect again to resume.",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_RPC_INITIATED_DISCONNECT")],
        title: "Disconnected by an administrator",
        hint: "The session was disconnected from the server side. Connect again to resume.",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_SERVER_DENIED_CONNECTION")],
        title: "The server refused the connection",
        hint: "The server is reachable but declined the session — it may be at its connection limit or \
               restricted by policy.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[CodePrefix("ERRINFO_LICENSE_")],
        title: "Remote Desktop licensing problem",
        hint: "The server couldn't issue a Remote Desktop license. This needs to be fixed by its administrator.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRINFO_SERVER_WINLOGON_CRASH"),
            Code("ERRINFO_SERVER_CSRSS_CRASH"),
            Code("ERRINFO_SERVER_DWM_CRASH"),
        ],
        title: "The remote session crashed",
        hint: "A system process on the remote computer failed. Connect again; if it repeats, the computer may \
               need a restart.",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[CodePrefix("ERRINFO_GRAPHICS_")],
        title: "Graphics mode not supported",
        hint: "The server rejected the requested graphics mode. Set the performance profile to Auto-detect.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Text("HTTP_STATUS_DENIED"), Text("HTTP_STATUS_FORBIDDEN")],
        title: "The gateway rejected your sign-in",
        hint: "Check the gateway username, domain and password.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[Code("ERRINFO_PEER_DISCONNECTED")],
        title: "The server closed the connection",
        hint: "The remote computer ended the session, for example because it is restarting.",
        severity: Dropped,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_CONNECT_FAILED"),
            Code("ERRCONNECT_CONNECT_TRANSPORT_FAILED"),
            Code("ERRCONNECT_MCS_CONNECT_INITIAL_ERROR"),
            Code("ERRINFO_CONNECT_FAILED"),
        ],
        title: "Can't reach the computer",
        hint: "Make sure the computer is on, Remote Desktop is enabled, the port is right, and you're on the \
               right network or VPN. A red dot next to the connection means the port isn't answering.",
        severity: Failed,
        fix: None,
    },
    Rule {
        patterns: &[
            Code("ERRCONNECT_PRE_CONNECT_FAILED"),
            Code("ERRCONNECT_POST_CONNECT_FAILED"),
        ],
        title: "FreeRDP couldn't set up the session",
        hint: "This is often caused by an unsupported option. Try removing extra arguments; the log has the \
               details.",
        severity: Failed,
        fix: None,
    },
];

/// Exit codes of FreeRDP 3's xfreerdp/sdl-freerdp, mapped back to the error codes they stand
/// for. Used only when the log has nothing better (e.g. log level OFF).
fn exit_code_name(code: i32) -> Option<&'static str> {
    Some(match code {
        1 => "ERRINFO_RPC_INITIATED_DISCONNECT",
        2 => "ERRINFO_RPC_INITIATED_LOGOFF",
        3 => "ERRINFO_IDLE_TIMEOUT",
        4 => "ERRINFO_LOGON_TIMEOUT",
        5 => "ERRINFO_DISCONNECTED_BY_OTHER_CONNECTION",
        7 => "ERRINFO_SERVER_DENIED_CONNECTION",
        9 => "ERRINFO_SERVER_INSUFFICIENT_PRIVILEGES",
        10 => "ERRINFO_SERVER_FRESH_CREDENTIALS_REQUIRED",
        11 => "ERRINFO_RPC_INITIATED_DISCONNECT_BY_USER",
        12 => "ERRINFO_LOGOFF_BY_USER",
        131 | 141 => "ERRCONNECT_CONNECT_FAILED",
        132 => "ERRCONNECT_AUTHENTICATION_FAILED",
        133 => "ERRCONNECT_SECURITY_NEGO_CONNECT_FAILED",
        134 => "ERRCONNECT_LOGON_FAILURE",
        135 => "ERRCONNECT_ACCOUNT_LOCKED_OUT",
        136 => "ERRCONNECT_PRE_CONNECT_FAILED",
        138 => "ERRCONNECT_POST_CONNECT_FAILED",
        139 => "ERRCONNECT_DNS_ERROR",
        140 => "ERRCONNECT_DNS_NAME_NOT_FOUND",
        142 => "ERRCONNECT_MCS_CONNECT_INITIAL_ERROR",
        143 => "ERRCONNECT_TLS_CONNECT_FAILED",
        144 => "ERRCONNECT_INSUFFICIENT_PRIVILEGES",
        145 => "ERRCONNECT_CONNECT_CANCELLED",
        147 => "ERRCONNECT_CONNECT_TRANSPORT_FAILED",
        148 => "ERRCONNECT_PASSWORD_EXPIRED",
        149 => "ERRCONNECT_PASSWORD_MUST_CHANGE",
        150 => "ERRCONNECT_KDC_UNREACHABLE",
        151 => "ERRCONNECT_ACCOUNT_DISABLED",
        152 => "ERRCONNECT_PASSWORD_CERTAINLY_EXPIRED",
        153 => "ERRCONNECT_CLIENT_REVOKED",
        154 => "ERRCONNECT_WRONG_PASSWORD",
        155 => "ERRCONNECT_ACCESS_DENIED",
        156 => "ERRCONNECT_ACCOUNT_RESTRICTION",
        157 => "ERRCONNECT_ACCOUNT_EXPIRED",
        158 => "ERRCONNECT_LOGON_TYPE_NOT_GRANTED",
        159 => "ERRCONNECT_NO_OR_MISSING_CREDENTIALS",
        _ => return None,
    })
}

/// Extracts `ERRCONNECT_*` / `ERRINFO_*` tokens from a log line.
fn codes_in(line: &str) -> impl Iterator<Item = &str> {
    line.match_indices("ERR").filter_map(move |(i, _)| {
        let rest = &line[i..];
        if !(rest.starts_with("ERRCONNECT_") || rest.starts_with("ERRINFO_")) {
            return None;
        }
        let end = rest
            .find(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .unwrap_or(rest.len());
        Some(&rest[..end])
    })
}

fn from_rule(rule: &Rule, code: Option<&str>) -> Diagnosis {
    Diagnosis {
        title: rule.title.into(),
        hint: rule.hint.into(),
        severity: rule.severity,
        fix: rule.fix,
        code: code.map(str::to_string),
    }
}

pub fn diagnose(log: &[String], exit: ExitStatus, stopped_by_user: bool) -> Diagnosis {
    if stopped_by_user {
        return Diagnosis {
            title: "Disconnected".into(),
            hint: "You disconnected this session.".into(),
            severity: Normal,
            fix: None,
            code: None,
        };
    }

    let codes: Vec<&str> = log
        .iter()
        .flat_map(|l| codes_in(l))
        .filter(|c| !c.ends_with("_SUCCESS") && !c.ends_with("_NONE"))
        .collect();
    for rule in RULES {
        for pattern in rule.patterns {
            let hit = match pattern {
                Code(want) => codes.iter().find(|c| *c == want).copied(),
                CodePrefix(prefix) => codes.iter().find(|c| c.starts_with(prefix)).copied(),
                Text(text) => log.iter().any(|l| l.contains(text)).then_some(""),
            };
            if let Some(code) = hit {
                return from_rule(rule, Some(code).filter(|c| !c.is_empty()));
            }
        }
    }

    match exit.code() {
        Some(0) => Diagnosis {
            title: "Session ended".into(),
            hint: String::new(),
            severity: Normal,
            fix: None,
            code: None,
        },
        Some(128) => Diagnosis {
            title: "FreeRDP rejected the options".into(),
            hint: "One of the arguments isn't valid for this FreeRDP version — check the extra arguments.".into(),
            severity: Failed,
            fix: None,
            code: None,
        },
        Some(n) => {
            if let Some(name) = exit_code_name(n)
                && let Some(rule) = RULES.iter().find(|r| r.patterns.iter().any(|p| matches!(p, Code(c) if *c == name)))
            {
                return from_rule(rule, Some(name));
            }
            Diagnosis {
                title: format!("FreeRDP stopped unexpectedly (exit code {n})"),
                hint: "Open the session log for details.".into(),
                severity: Failed,
                fix: None,
                code: codes.last().map(|c| c.to_string()),
            }
        }
        None => Diagnosis {
            title: "FreeRDP crashed".into(),
            hint: format!("The client was terminated ({exit}). Open the session log for details."),
            severity: Dropped,
            fix: None,
            code: None,
        },
    }
}

/// Parses FreeRDP's "Attempting reconnect (n of m)" log line.
pub fn reconnect_attempt(line: &str) -> Option<(u32, u32)> {
    let rest = line.split("Attempting reconnect (").nth(1)?;
    let (n, rest) = rest.split_once(" of ")?;
    let m = rest.split(')').next()?;
    Some((n.trim().parse().ok()?, m.trim().parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;

    fn exit(code: i32) -> ExitStatus {
        ExitStatus::from_raw(code << 8)
    }

    fn lines(s: &[&str]) -> Vec<String> {
        s.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn specific_code_beats_generic() {
        let log = lines(&[
            "[ERROR][com.freerdp.core] - [nla_client]: ERRCONNECT_LOGON_FAILURE [0x00020014]",
            "[ERROR][com.freerdp.core] - [transport]: ERRCONNECT_CONNECT_FAILED [0x00020006]",
        ]);
        let d = diagnose(&log, exit(134), false);
        assert_eq!(d.title, "Wrong username or password");
        assert_eq!(d.fix, Some(Fix::ForgetPassword));
        assert_eq!(d.code.as_deref(), Some("ERRCONNECT_LOGON_FAILURE"));
    }

    #[test]
    fn real_dns_failure_log() {
        let log = lines(&[
            "[20:05:31:843] [126988:0001f018] [ERROR][com.freerdp.core] - [freerdp_tcp_is_hostname_resolvable]: ERRCONNECT_DNS_NAME_NOT_FOUND [0x00020005]",
            "[20:05:31:843] [126988:0001f018] [ERROR][com.freerdp.core.nego] - [nego_connect]: Failed to connect",
        ]);
        assert_eq!(
            diagnose(&log, exit(140), false).title,
            "Computer name not found"
        );
    }

    #[test]
    fn certificate_change() {
        let log = lines(&["[ERROR] !!!Certificate for 10.0.0.5:3389 (10.0.0.5) has changed!!!"]);
        let d = diagnose(&log, exit(131), false);
        assert_eq!(d.fix, Some(Fix::ForgetCertificate));
        assert_eq!(d.severity, Failed);
    }

    #[test]
    fn exit_code_fallback_and_normal_endings() {
        assert_eq!(
            diagnose(&[], exit(141), false).title,
            "Can't reach the computer"
        );
        assert_eq!(diagnose(&[], exit(12), false).severity, Normal);
        assert_eq!(diagnose(&[], exit(0), false).severity, Normal);
        assert_eq!(diagnose(&[], exit(5), false).severity, Dropped);
        assert_eq!(diagnose(&[], exit(99), false).severity, Failed);
        assert_eq!(
            diagnose(&[], ExitStatus::from_raw(15), true).severity,
            Normal
        );
        assert_eq!(
            diagnose(&[], ExitStatus::from_raw(11), false).title,
            "FreeRDP crashed"
        );
    }

    #[test]
    fn reconnect_parsing() {
        let line = "[INFO][com.freerdp.client.common] - [client_auto_reconnect_ex]: Attempting reconnect (3 of 10)";
        assert_eq!(reconnect_attempt(line), Some((3, 10)));
        assert_eq!(reconnect_attempt("nothing"), None);
        let log = lines(&[line, "[ERROR] AutoReconnect retries exceeded."]);
        assert_eq!(diagnose(&log, exit(131), false).title, "Connection lost");
    }
}
