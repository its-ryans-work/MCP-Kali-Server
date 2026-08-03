#!/usr/bin/env bash
#
# install-desktop-launcher.sh — put a "MCP Kali Server" launcher on the desktop.
#
# Run this ON the Kali host, from the repo directory. It installs a control
# script to ~/.local/bin and a .desktop entry to both the desktop and the
# application menu. Paths are resolved here rather than committed, so nothing
# host-specific ends up in the repository.
#
# Usage:
#   ./install-desktop-launcher.sh                 # install
#   ./install-desktop-launcher.sh --uninstall     # remove
#   MKS_API_PORT=5111 ./install-desktop-launcher.sh
#
set -euo pipefail

SERVER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${MKS_PREFIX:-$HOME/.local}/bin"
APP_DIR="$HOME/.local/share/applications"
API_PORT="${MKS_API_PORT:-5111}"
BIND_IP="${MKS_BIND_IP:-127.0.0.1}"
APP_ID="mcp-kali-server"

log()  { printf '\033[34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*" >&2; }

# Honour the user's configured desktop directory rather than assuming ~/Desktop,
# which is wrong on any non-English or customised system.
desktop_dir() {
    local d
    d="$(xdg-user-dir DESKTOP 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d" ] && { echo "$d"; return; }
    # shellcheck disable=SC1090
    [ -f "$HOME/.config/user-dirs.dirs" ] && . "$HOME/.config/user-dirs.dirs" 2>/dev/null || true
    echo "${XDG_DESKTOP_DIR:-$HOME/Desktop}"
}

DESKTOP_DIR="$(desktop_dir)"

if [ "${1:-}" = "--uninstall" ]; then
    rm -fv "$BIN_DIR/$APP_ID" "$APP_DIR/$APP_ID.desktop" "$DESKTOP_DIR/$APP_ID.desktop"
    command -v update-desktop-database >/dev/null && update-desktop-database "$APP_DIR" 2>/dev/null || true
    ok "launcher removed"
    exit 0
fi

[ -f "$SERVER_DIR/server.py" ] || { warn "server.py not found in $SERVER_DIR"; exit 1; }
[ -f "$SERVER_DIR/bin/mcp-kali-server" ] || { warn "bin/mcp-kali-server missing"; exit 1; }

mkdir -p "$BIN_DIR" "$APP_DIR" "$DESKTOP_DIR"

# ---------------------------------------------------------------- control script

log "installing control script to $BIN_DIR/$APP_ID"
sed "s|__SERVER_DIR__|$SERVER_DIR|g" "$SERVER_DIR/bin/mcp-kali-server" > "$BIN_DIR/$APP_ID"
chmod 0755 "$BIN_DIR/$APP_ID"

# ------------------------------------------------------------------ desktop entry

# Terminal=true lets the desktop environment pick the user's terminal, instead of
# hardcoding gnome-terminal/xfce4-terminal here.
#
# Categories lists exactly one main category (System); adding more makes the
# entry show up several times in the application menu. Security is an additional
# category and does not count as a main one.
write_desktop_entry() {
    cat > "$1" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=MCP Kali Server
GenericName=Kali Tools API Server
Comment=Start the MCP Kali Tools API server on $BIND_IP:$API_PORT
Exec=env MKS_SERVER_DIR=$SERVER_DIR MKS_API_PORT=$API_PORT MKS_BIND_IP=$BIND_IP $BIN_DIR/$APP_ID launch
Path=$SERVER_DIR
Icon=security-high
Terminal=true
Categories=System;Security;
Keywords=mcp;kali;pentest;api;server;tools;
StartupNotify=true
Actions=Status;Stop;

[Desktop Action Status]
Name=Show status
Exec=env MKS_SERVER_DIR=$SERVER_DIR MKS_API_PORT=$API_PORT $BIN_DIR/$APP_ID status

[Desktop Action Stop]
Name=Stop server
Exec=env MKS_SERVER_DIR=$SERVER_DIR MKS_API_PORT=$API_PORT $BIN_DIR/$APP_ID stop
EOF
    chmod 0755 "$1"
}

log "installing application entry to $APP_DIR"
write_desktop_entry "$APP_DIR/$APP_ID.desktop"

log "installing desktop shortcut to $DESKTOP_DIR"
write_desktop_entry "$DESKTOP_DIR/$APP_ID.desktop"

# GNOME (and the ding extension) refuses to run a .desktop file dropped on the
# desktop until it is marked trusted — otherwise it shows as "Untrusted
# application launcher" and needs a manual "Allow Launching" right-click.
if command -v gio >/dev/null 2>&1; then
    if gio set "$DESKTOP_DIR/$APP_ID.desktop" metadata::trusted true 2>/dev/null; then
        ok "marked launcher trusted"
    else
        warn "could not set metadata::trusted — if the icon shows as untrusted,"
        warn "right-click it and choose 'Allow Launching'"
    fi
fi

command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APP_DIR" 2>/dev/null || true

# ------------------------------------------------------------------------ report

if ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
    warn "$BIN_DIR is not on PATH — add: export PATH=\"$BIN_DIR:\$PATH\""
fi

ok "installed"
printf '\n  Desktop icon : %s/%s.desktop\n' "$DESKTOP_DIR" "$APP_ID"
printf '  App menu     : "MCP Kali Server" (right-click for Status / Stop)\n'
printf '  Command line : %s {start|stop|restart|status|logs}\n\n' "$APP_ID"
