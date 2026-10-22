//! Keeps favourite connections as actions in the installed `.desktop` file, so they show
//! up when right-clicking xrdp-gui in the launcher or taskbar.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use uuid::Uuid;

fn installed_file() -> Option<PathBuf> {
    let dirs = directories::BaseDirs::new()?;
    Some(dirs.data_dir().join("applications/xrdp-gui.desktop"))
}

/// Rewrites the favourite actions of the installed desktop file (if xrdp-gui is
/// installed) in the background.
pub fn update_favourites(favourites: Vec<(Uuid, String)>) {
    std::thread::spawn(move || {
        let Some(path) = installed_file().filter(|p| p.exists()) else {
            return;
        };
        match rewrite(&path, &favourites) {
            Ok(true) => {
                // Plasma usually notices on its own; this makes it immediate.
                let _ = std::process::Command::new("kbuildsycoca6")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status();
            }
            Ok(false) => {}
            Err(e) => eprintln!("warning: updating {}: {e:#}", path.display()),
        }
    });
}

/// Returns whether the file changed.
fn rewrite(path: &PathBuf, favourites: &[(Uuid, String)]) -> Result<bool> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let new = with_actions(&text, favourites);
    if new == text {
        return Ok(false);
    }
    let tmp = path.with_extension("desktop.tmp");
    fs::write(&tmp, &new).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(true)
}

/// `text` with its actions replaced by one "connect" action per favourite.
fn with_actions(text: &str, favourites: &[(Uuid, String)]) -> String {
    // Keep only the main group, minus any previous Actions= line.
    let main: Vec<&str> = text
        .lines()
        .take_while(|l| !l.trim_start().starts_with("[Desktop Action "))
        .filter(|l| !l.starts_with("Actions="))
        .collect();
    let exec = main
        .iter()
        .find_map(|l| l.strip_prefix("Exec="))
        .and_then(|e| e.split_whitespace().next())
        .unwrap_or("xrdp-gui");

    let mut out = main.join("\n").trim_end().to_string();
    out.push('\n');
    if favourites.is_empty() {
        return out;
    }
    let ids: Vec<String> = favourites
        .iter()
        .map(|(id, _)| format!("connect-{}", id.simple()))
        .collect();
    out.push_str(&format!("Actions={};\n", ids.join(";")));
    for ((id, name), action) in favourites.iter().zip(&ids) {
        // Desktop entry values are single-line; '\' and leading spaces need escaping.
        let name = name.replace('\\', "\\\\").replace(['\n', '\r'], " ");
        out.push_str(&format!(
            "\n[Desktop Action {action}]\nName=Connect to {}\nIcon=xrdp-gui\nExec={exec} --connect {id}\n",
            name.trim()
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLED: &str = "[Desktop Entry]\nType=Application\nName=xrdp-gui\n\
                             Exec=/home/u/.local/bin/xrdp-gui\nIcon=xrdp-gui\n";

    #[test]
    fn adds_replaces_and_removes_actions() {
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let one = with_actions(INSTALLED, &[(a, "Lab".into())]);
        assert!(one.contains("Actions=connect-00000000000000000000000000000001;\n"));
        assert!(one.contains("[Desktop Action connect-00000000000000000000000000000001]"));
        assert!(one.contains("Name=Connect to Lab\n"));
        assert!(one.contains(&format!("Exec=/home/u/.local/bin/xrdp-gui --connect {a}\n")));

        // Rewriting replaces the old actions rather than appending.
        let two = with_actions(&one, &[(b, "Mail".into()), (a, "Lab".into())]);
        assert_eq!(two.matches("Actions=").count(), 1);
        assert_eq!(two.matches("[Desktop Action").count(), 2);
        assert!(two.find("Mail").unwrap() < two.find("Name=Connect to Lab").unwrap());

        // Idempotent, and removing all favourites restores the original.
        assert_eq!(
            with_actions(&two, &[(b, "Mail".into()), (a, "Lab".into())]),
            two
        );
        assert_eq!(with_actions(&two, &[]), INSTALLED);
    }
}
