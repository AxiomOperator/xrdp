# xrdp-gui

A small connection manager for [FreeRDP 3](https://www.freerdp.com/), written in Rust with egui.
It stores your RDP connections and launches `sdl-freerdp` (or `xfreerdp`) for them.

- Connections in collapsible groups (an accordion: opening one group closes the others, which
  can be turned off in Settings), with search; double-click to connect
- **Favourites and recent connections** at the top of the list, in the tray menu, and as
  right-click actions on the launcher / taskbar entry
- **Tray icon**: closing the window keeps xrdp-gui running in the tray; connect to a favourite
  or recent connection from its menu without opening the window
- **Quick connect**: type `[DOMAIN\]user@host[:port]` in the top bar (Ctrl+L) to connect
  without saving a connection; `xrdp-gui --connect <name|host>` does the same from a terminal
- **Group defaults**: click a group's ⚙ to set its domain, credentials, RD Gateway,
  certificate policy and performance profile once; connections inherit them unless they set
  their own (a connection with an empty username uses the group's username and password)
- **Notes and tags** per connection; search covers both, and `#tag` matches a tag exactly
- **HiDPI scaling**: scale the remote desktop to 125–300%, or match the local screen
  (`/scale-desktop`)
- **Certificate manager**: see which server certificates FreeRDP trusts (subject, expiry,
  SHA-256 fingerprint, which connections use them) and forget one
- **Host status dots**: green/red per connection from a background check of the RDP port
  (or the gateway, when one is used) every 30 s
- **Performance profiles**: LAN, VPN and WAN presets (`/network:`, `/gfx:AVC444`/`AVC420`,
  compression and visual-effect trimming)
- **Auto-reconnect** with a retry limit; the session list shows reconnect attempts live
- **Plain-English errors**: FreeRDP error codes and exit codes become messages like
  "Wrong username or password" with a suggested fix and one-click remedies
  (forget saved password, forget a changed certificate)
- **Desktop notifications** when a connection fails, drops, starts reconnecting, or comes back
- Passwords stored in the desktop keyring (Secret Service: KWallet, GNOME Keyring)
- Arguments are passed to FreeRDP via `/args-from:stdin`, so passwords never show up in `ps`
- Display options (window/fullscreen, size presets, multi-monitor, dynamic resolution)
- Redirection (clipboard, home drive, audio, microphone), extra args
- Session list with live FreeRDP log output and disconnect; **copy or save a session's log**
  (with connection details, passwords masked) to send to support
- Only one copy runs at a time; launching it again opens or brings forward the existing window
- Remembers window size, position, panel widths and the last selected connection or group
  (on Wayland the position is remembered by a KWin window rule that `install.sh` adds)

## Install

```sh
./install.sh            # builds and installs for your user into ~/.local
./install.sh --uninstall
```

This puts `xrdp-gui` in `~/.local/bin`, adds it to the application menu (Internet / Network),
installs its icon, and adds a KWin rule so KDE remembers where you put the window. Set `PREFIX` to install somewhere else.

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| Enter | Connect to the selected connection |
| Ctrl+N | New connection |
| Ctrl+S | Save |
| Ctrl+F | Search |
| Ctrl+L | Quick connect |
| Ctrl+Q | Quit (also from the tray menu) |
| Delete | Delete the selected connection |

Enter and Delete apply when you're not typing in a field.

## Command line

```sh
xrdp-gui                      # open the window (or bring the running one forward)
xrdp-gui --connect "Lab"      # connect to a saved connection by name, host or id…
xrdp-gui --connect bob@pc1    # …or to any host, without saving it
```

If xrdp-gui is already running, the request goes to the running copy.

## Build & run

```sh
cargo run --release
```

Requires FreeRDP 3 (`sdl-freerdp` or `xfreerdp`) on `PATH`. No `-devel` packages are needed.

Config lives in `~/.config/xrdp-gui/config.toml`. Passwords are stored only in the keyring.
