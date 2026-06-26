#!/bin/bash
#
# Installer for berkeley-vpn — a lightweight openconnect wrapper for the UC
# Berkeley VPN. Downloads the two scripts and links a `berkeley-vpn` command.
#
#   curl -fsSL https://raw.githubusercontent.com/shahaadi/berkeley-vpn/main/install.sh | bash
#
set -euo pipefail

REPO_RAW="https://raw.githubusercontent.com/shahaadi/berkeley-vpn/main"
INSTALL_DIR="${BERKELEY_VPN_DIR:-$HOME/.local/share/berkeley-vpn}"

say()  { printf '%s\n' "$*"; }
warn() { printf '!! %s\n' "$*" >&2; }

say ">> Installing berkeley-vpn into $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
for f in capture.swift connect.sh; do
    curl -fsSL "$REPO_RAW/$f" -o "$INSTALL_DIR/$f"
done
chmod +x "$INSTALL_DIR/connect.sh"

# Link a `berkeley-vpn` command into the first writable bin dir on PATH.
LINKED=""
for bindir in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
    if [ -d "$bindir" ] && [ -w "$bindir" ]; then
        ln -sf "$INSTALL_DIR/connect.sh" "$bindir/berkeley-vpn"
        LINKED="$bindir/berkeley-vpn"
        break
    fi
done
if [ -z "$LINKED" ] && mkdir -p "$HOME/.local/bin" 2>/dev/null; then
    ln -sf "$INSTALL_DIR/connect.sh" "$HOME/.local/bin/berkeley-vpn"
    LINKED="$HOME/.local/bin/berkeley-vpn"
fi

say ""
say ">> Installed."
if [ -n "$LINKED" ]; then
    say "   Command: berkeley-vpn  ->  $LINKED"
    case ":$PATH:" in
        *":$(dirname "$LINKED"):"*) : ;;
        *) warn "$(dirname "$LINKED") is not on your PATH. Add it, or run $INSTALL_DIR/connect.sh directly." ;;
    esac
else
    say "   Run it with: $INSTALL_DIR/connect.sh"
fi

# Dependency hints — don't auto-install, just tell the user what's missing.
command -v openconnect >/dev/null 2>&1 || warn "openconnect is not installed. Install it with:  brew install openconnect"
command -v swift       >/dev/null 2>&1 || warn "Swift toolchain not found. Install it with:  xcode-select --install"

say ""
say "   Usage:  berkeley-vpn [split | full | restricted]      (-h for help)"
say "     e.g.  berkeley-vpn          # split tunnel (default)"
say "           berkeley-vpn full     # full tunnel (all traffic)"
