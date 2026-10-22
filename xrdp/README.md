# xrdp-gui

A small connection manager for [FreeRDP 3](https://www.freerdp.com/), written in Rust with egui.
It stores your RDP connections and launches `sdl-freerdp` (or `xfreerdp`) for them.

- Connections in groups, with search; double-click to connect
- **Group defaults**: click a group name to set its domain, RD Gateway, certificate policy and
  performance profile once; connections inherit them unless they set their own
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
- Session list with live FreeRDP log output and disconnect

## Build & run

```sh
cargo run --release
```

Requires FreeRDP 3 (`sdl-freerdp` or `xfreerdp`) on `PATH`. No `-devel` packages are needed.

Config lives in `~/.config/xrdp-gui/config.toml`. Passwords are stored only in the keyring.
