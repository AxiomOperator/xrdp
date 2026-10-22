#!/usr/bin/env sh
# Builds xrdp-gui and installs it for the current user (no root needed):
#   binary   -> $PREFIX/bin/xrdp-gui
#   menu     -> $PREFIX/share/applications/xrdp-gui.desktop
#               (+ a hidden xrdp-gui-session.desktop that gives session windows the icon)
#   icon     -> $PREFIX/share/icons/hicolor/scalable/apps/xrdp-gui.svg
#   KDE      -> a KWin window rule that remembers the window's position (Wayland
#               doesn't let apps place their own windows, so KWin does it)
# PREFIX defaults to ~/.local. Run with --uninstall to remove all of that again
# (your connections in ~/.config/xrdp-gui are left alone).
set -eu

PREFIX="${PREFIX:-$HOME/.local}"
BIN="$PREFIX/bin/xrdp-gui"
DESKTOP="$PREFIX/share/applications/xrdp-gui.desktop"
SESSION_DESKTOP="$PREFIX/share/applications/xrdp-gui-session.desktop"
ICON="$PREFIX/share/icons/hicolor/scalable/apps/xrdp-gui.svg"

KWIN_RULE=xrdp-gui-remember-position

kwin_reconfigure() {
    gdbus call --session --dest org.kde.KWin --object-path /KWin \
        --method org.kde.KWin.reconfigure >/dev/null 2>&1 || true
}

# Prints the KWin rule list with our rule added (add) or removed (remove).
kwin_rule_list() {
    current=$(kreadconfig6 --file kwinrulesrc --group General --key rules 2>/dev/null || true)
    others=$(printf '%s' "$current" | tr ',' '\n' | grep -vx "$KWIN_RULE" | grep . | paste -sd, - || true)
    if [ "$1" = add ]; then
        printf '%s' "${others:+$others,}$KWIN_RULE"
    else
        printf '%s' "$others"
    fi
}

set_kwin_rules() {
    list=$1
    count=$(printf '%s' "$list" | tr ',' '\n' | grep -c . || true)
    kwriteconfig6 --file kwinrulesrc --group General --key rules "$list"
    kwriteconfig6 --file kwinrulesrc --group General --key count "$count"
}

add_kwin_rule() {
    command -v kwriteconfig6 >/dev/null || return 0
    w() { kwriteconfig6 --file kwinrulesrc --group "$KWIN_RULE" --key "$1" "$2"; }
    w Description "xrdp-gui: remember window position"
    w wmclass xrdp-gui
    w wmclassmatch 1      # exact match on the app id
    w wmclasscomplete false
    w types 1             # normal windows only
    w positionrule 4      # 4 = Remember
    set_kwin_rules "$(kwin_rule_list add)"
    kwin_reconfigure
}

remove_kwin_rule() {
    command -v kwriteconfig6 >/dev/null || return 0
    for key in Description wmclass wmclassmatch wmclasscomplete types positionrule position; do
        kwriteconfig6 --file kwinrulesrc --group "$KWIN_RULE" --key "$key" --delete
    done
    set_kwin_rules "$(kwin_rule_list remove)"
    kwin_reconfigure
}

refresh_menus() {
    update-desktop-database "$PREFIX/share/applications" >/dev/null 2>&1 || true
    gtk-update-icon-cache -q "$PREFIX/share/icons/hicolor" >/dev/null 2>&1 || true
    kbuildsycoca6 >/dev/null 2>&1 || kbuildsycoca5 >/dev/null 2>&1 || true
}

if [ "${1:-}" = "--uninstall" ]; then
    rm -f "$BIN" "$DESKTOP" "$SESSION_DESKTOP" "$ICON"
    remove_kwin_rule
    refresh_menus
    echo "Removed xrdp-gui from $PREFIX."
    exit 0
fi

cd "$(dirname "$0")"
PATH="$HOME/.cargo/bin:$PATH"
command -v cargo >/dev/null || { echo "cargo not found; install Rust from https://rustup.rs" >&2; exit 1; }

cargo build --release --locked

install -Dm755 target/release/xrdp-gui "$BIN"
install -Dm644 assets/xrdp-gui.svg "$ICON"
mkdir -p "$(dirname "$DESKTOP")"
# Use an absolute path: the desktop session's PATH may not include ~/.local/bin.
for f in xrdp-gui xrdp-gui-session; do
    sed "s|^Exec=.*|Exec=$BIN|" "assets/$f.desktop" > "$PREFIX/share/applications/$f.desktop"
done
chmod 644 "$DESKTOP" "$SESSION_DESKTOP"
add_kwin_rule
refresh_menus

echo "Installed xrdp-gui to $BIN"
echo "It's in your application menu under Internet / Network."
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "Note: $PREFIX/bin is not on your PATH; add it to run 'xrdp-gui' from a terminal." ;;
esac
