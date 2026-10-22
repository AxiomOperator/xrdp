# xrdp-gui

A small connection manager for [FreeRDP 3](https://www.freerdp.com/), written in Rust with egui.
It stores your RDP connections and launches `sdl-freerdp` (or `xfreerdp`) for them.

- Connections in groups, with search; double-click to connect
- Passwords stored in the desktop keyring (Secret Service: KWallet, GNOME Keyring)
- Arguments are passed to FreeRDP via `/args-from:stdin`, so passwords never show up in `ps`
- Display options (window/fullscreen, size presets, multi-monitor, dynamic resolution)
- Redirection (clipboard, home drive, audio, microphone), RD Gateway, certificate policy, extra args
- Session list with live FreeRDP log output and disconnect

## Build & run

```sh
cargo run --release
```

Requires FreeRDP 3 (`sdl-freerdp` or `xfreerdp`) on `PATH`. No `-devel` packages are needed.

Config lives in `~/.config/xrdp-gui/config.toml`. Passwords are stored only in the keyring.
