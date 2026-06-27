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
# Download BOTH files to a temp dir first, then move both into place, so a dropped
# connection can't leave a truncated script. The temp dir is cleaned on any exit.
tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT
for f in capture.swift connect.sh; do
    curl -fsSL "$REPO_RAW/$f" -o "$tmpd/$f" || { warn "download failed: $f"; exit 1; }
done
mv -f "$tmpd/capture.swift" "$INSTALL_DIR/capture.swift"
mv -f "$tmpd/connect.sh"    "$INSTALL_DIR/connect.sh"
chmod +x "$INSTALL_DIR/connect.sh" 2>/dev/null || true

# Link a `berkeley-vpn` command into the first writable bin dir on PATH.
LINKED=""
for bindir in /opt/homebrew/bin /usr/local/bin "$HOME/.local/bin"; do
    if [ -d "$bindir" ] && [ -w "$bindir" ]; then
        ln -sf "$INSTALL_DIR/connect.sh" "$bindir/berkeley-vpn"
        LINKED="$bindir/berkeley-vpn"
        break
    fi
done
if [ -z "$LINKED" ]; then
    mkdir -p "$HOME/.local/bin" 2>/dev/null || true
    if ln -sf "$INSTALL_DIR/connect.sh" "$HOME/.local/bin/berkeley-vpn" 2>/dev/null; then
        LINKED="$HOME/.local/bin/berkeley-vpn"
    fi
fi

say ""
say ">> Installed."
if [ -n "$LINKED" ]; then
    say "   Command: berkeley-vpn  ->  $LINKED"
    bindir="$(dirname "$LINKED")"
    case ":$PATH:" in
        *":$bindir:"*) : ;;
        *) warn "$bindir is not on your PATH, so the 'berkeley-vpn' command won't be found yet."
           warn "Add it (zsh):  echo 'export PATH=\"$bindir:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
           warn "Or just run:   $INSTALL_DIR/connect.sh" ;;
    esac
else
    say "   Run it with: $INSTALL_DIR/connect.sh"
fi

# Dependency hints — don't auto-install, just tell the user what's missing.
command -v openconnect >/dev/null 2>&1 || warn "openconnect is not installed. Install it with:  brew install openconnect"
# Use xcode-select, not `command -v swift`: /usr/bin/swift is a stub present even
# without the Command Line Tools.
xcode-select -p >/dev/null 2>&1 || warn "Xcode Command Line Tools not found (needed for swift). Install:  xcode-select --install"

say ""
say "   Usage:  berkeley-vpn [split | full | restricted]      (-h for help)"
say "     e.g.  berkeley-vpn          # split tunnel (default)"
say "           berkeley-vpn full     # full tunnel (all traffic)"
say "   More:   berkeley-vpn login | logout | update | uninstall"
