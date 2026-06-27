#!/bin/bash
#
# Connect to UC Berkeley VPN (vpn.berkeley.edu) via openconnect + GlobalProtect.
# Opens a native WebKit (Safari engine) window for CalNet + Duo login, captures
# the GlobalProtect auth token, and brings up the VPN tunnel with openconnect.
#
set -euo pipefail

CMD="$(basename "${BASH_SOURCE[0]:-$0}")"   # how the user invoked us (e.g. berkeley-vpn)

usage() {
    # Unquoted heredoc so "$CMD" reflects how you invoked this (e.g. berkeley-vpn).
    cat <<EOF
Berkeley VPN — connect via openconnect + GlobalProtect (no GlobalProtect app needed).
Opens a WebKit CalNet + Duo login, captures the auth token, and starts the tunnel.

Usage:
  $CMD [split | full | restricted]   connect (default: split)
  $CMD login                         refresh the CalNet session (no connect)
  $CMD logout                        clear the saved CalNet session
  $CMD update                        update berkeley-vpn to the latest version
  $CMD uninstall                     remove berkeley-vpn (asks to confirm)

Tunnels:
  split        Split Tunnel (DEFAULT) — only campus/Berkeley traffic goes through
               the VPN; the rest of your internet uses your normal connection.
  full         Full Tunnel — ALL of your internet traffic goes through the VPN
               (use this for licensed library / journal access).
  restricted   Restricted Tunnel — a limited subset of campus resources.

Examples:
  $CMD             # split tunnel (default)
  $CMD full        # full tunnel (all traffic)

Advanced (environment variables):
  GP_GATEWAY=<host>   use a specific gateway host (overrides the tunnel choice)
  GP_TIMEOUT=<secs>   how long to wait for the login window (default 240)

Run from a terminal — sudo needs a tty to prompt for your password.
EOF
}

# Resolve our own directory, following symlinks, so an installed `berkeley-vpn`
# symlink in PATH still finds capture.swift next to the real connect.sh.
SOURCE="${BASH_SOURCE[0]:-$0}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
HERE="$(cd -P "$(dirname "$SOURCE")" && pwd)"

# Require the Command Line Tools (xcode-select, NOT `command -v swift`: /usr/bin/swift
# is a stub that exists even without the CLT and would pop the GUI installer).
require_swift() {
    xcode-select -p >/dev/null 2>&1 || {
        echo "!! Xcode Command Line Tools not found (needed for swift). Install: xcode-select --install" >&2
        exit 1
    }
}

do_uninstall() {
    local link selfdir="$HERE"
    link="$(command -v berkeley-vpn 2>/dev/null || true)"
    echo "This will remove berkeley-vpn:"
    if [ -d "$selfdir/.git" ]; then
        echo "  - files:    (kept — $selfdir is a git checkout)"
    else
        echo "  - files:    $selfdir/{capture.swift,connect.sh}"
    fi
    [ -n "$link" ] && [ -L "$link" ] && echo "  - command:  $link"
    echo "  - the saved CalNet session (Keychain item + WebKit data)"
    printf "Are you sure? [y/N] "
    local ans=""
    # Read the answer from the terminal (only if one is actually openable, so a
    # non-interactive run cancels cleanly instead of erroring).
    if { : </dev/tty; } 2>/dev/null; then
        read -r ans </dev/tty || true
    fi
    case "$ans" in
        y|Y|yes|YES|Yes) ;;
        *) echo; echo "Cancelled."; exit 0 ;;
    esac
    # Clear the saved session. The Keychain item we can delete directly (works even
    # without swift); --logout additionally clears WebKit's data store if swift is present.
    security delete-generic-password -s berkeley-vpn -a calnet-session >/dev/null 2>&1 || true
    if xcode-select -p >/dev/null 2>&1 && [ -f "$selfdir/capture.swift" ]; then
        swift "$selfdir/capture.swift" --logout 2>/dev/null || true
    fi
    # Remove the command symlink (only if it really is a symlink).
    if [ -n "$link" ] && [ -L "$link" ]; then rm -f "$link" && echo "Removed $link"; fi
    # Remove our files. A git checkout is left in place (it's a source clone). We
    # delete ONLY our two files and then rmdir the directory, which removes it only
    # if it's now empty — so dropping the scripts into a shared dir (or installing
    # to a non-dedicated one) can't take unrelated files down with them.
    if [ -d "$selfdir/.git" ]; then
        echo "Left $selfdir in place (it's a git checkout). Delete it yourself if you want it gone."
    elif [ -n "$selfdir" ] && [ -f "$selfdir/capture.swift" ] && [ -f "$selfdir/connect.sh" ]; then
        rm -f "$selfdir/capture.swift" "$selfdir/connect.sh"
        if rmdir "$selfdir" 2>/dev/null; then
            echo "Removed $selfdir"
        else
            echo "Removed the berkeley-vpn files from $selfdir (kept the directory — it has other files)."
        fi
    fi
    echo "Done. (openconnect was left installed — 'brew uninstall openconnect' if you don't need it.)"
    exit 0
}

# Pull the latest version. A git checkout updates with `git pull`; an installed
# copy re-downloads the two scripts from the repo (matching how install.sh fetches).
do_update() {
    local repo_raw="https://raw.githubusercontent.com/shahaadi/berkeley-vpn/main"
    if [ -d "$HERE/.git" ]; then
        command -v git >/dev/null 2>&1 || { echo "!! git not found." >&2; exit 1; }
        echo ">> Updating $HERE (git pull) ..."
        exec git -C "$HERE" pull --ff-only
    fi
    command -v curl >/dev/null 2>&1 || { echo "!! curl not found." >&2; exit 1; }
    [ -f "$HERE/capture.swift" ] || { echo "!! $HERE doesn't look like a berkeley-vpn install." >&2; exit 1; }
    echo ">> Downloading the latest berkeley-vpn into $HERE ..."
    local tmp; tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT   # clean the temp dir even on Ctrl-C mid-download
    # Download both to temp first, so a dropped connection can't leave a truncated
    # script. (The two moves below are sequential rename(2)s on the same volume, so
    # a partial swap is essentially impossible in practice; a failure is reported.)
    local f ok=1
    for f in connect.sh capture.swift; do
        if ! curl -fsSL "$repo_raw/$f" -o "$tmp/$f"; then echo "!! Failed to download $f." >&2; ok=0; break; fi
    done
    if [ "$ok" = 1 ]; then
        # Move BOTH or report failure honestly (don't couple chmod with && — under
        # set -e a left-of-&& failure is exempt and would falsely report success).
        if mv -f "$tmp/capture.swift" "$HERE/capture.swift" \
           && mv -f "$tmp/connect.sh" "$HERE/connect.sh"; then
            chmod +x "$HERE/connect.sh" 2>/dev/null || true
            rm -rf "$tmp"
            echo "Updated. Run '$CMD' to use the new version."
            exit 0
        fi
        echo "!! Update failed while installing files (the install may be half-updated)." >&2
    fi
    rm -rf "$tmp"
    exit 1
}

# --- Parse the argument: help, a subcommand, or a tunnel name -----------------
for a in "$@"; do
    case "$a" in -h|--help) usage; exit 0 ;; esac
done
if [[ $# -gt 1 ]]; then
    echo "!! Too many arguments." >&2; usage >&2; exit 2
fi

# `${1-split}` (no colon): unset -> split; an explicitly-passed empty arg errors.
ACTION="${1-split}"

# Subcommands that don't bring up the VPN:
case "$ACTION" in
    login)     require_swift; echo ">> Opening CalNet login to refresh your session (no VPN connection)…"
               exec swift "$HERE/capture.swift" --login ;;
    logout)    require_swift; exec swift "$HERE/capture.swift" --logout ;;
    update)    do_update ;;
    uninstall) do_uninstall ;;
esac

# Otherwise it's a tunnel selection.
case "$ACTION" in
    split)      GW="campus-split.vpn.berkeley.edu"; DESC="Split Tunnel — only campus traffic goes through the VPN" ;;
    full)       GW="campus.vpn.berkeley.edu";       DESC="Full Tunnel — ALL traffic goes through the VPN" ;;
    restricted) GW="restricted.vpn.berkeley.edu";   DESC="Restricted Tunnel — limited campus resources" ;;
    *) echo "!! Unknown command/tunnel '$ACTION'." >&2
       echo "   Use: split | full | restricted | login | logout | update | uninstall" >&2; usage >&2; exit 2 ;;
esac
# An explicit GP_GATEWAY env var overrides the friendly choice (advanced/custom use).
if [[ -n "${GP_GATEWAY:-}" ]]; then
    [[ $# -ge 1 ]] && echo "note: GP_GATEWAY is set — using it instead of the '$ACTION' tunnel." >&2
    GW="$GP_GATEWAY"; DESC="custom gateway (GP_GATEWAY)"
fi
GP_GATEWAY="$GW"; export GP_GATEWAY
if [[ -n "${GP_TIMEOUT:-}" ]]; then export GP_TIMEOUT; fi

# --- Startup banner (prints what it's doing and how to change it) -------------
echo "=================================================================="
echo "  Berkeley VPN"
echo "    tunnel : $DESC"
echo "    gateway: $GP_GATEWAY"
echo "    switch : $CMD [split | full | restricted]   ($CMD -h for help)"
echo "=================================================================="

# --- Pre-flight: fail early (before opening the login window) ------------------
# Need a controlling terminal for sudo's password prompt. /dev/tty always *exists*,
# so test that it can actually be OPENED.
if ! { : </dev/tty; } 2>/dev/null; then
    echo "!! Run from a terminal — sudo needs a tty for your password." >&2; exit 1
fi
require_swift
command -v openconnect >/dev/null 2>&1 || {
    echo "!! openconnect not found. Install it with: brew install openconnect" >&2
    exit 1
}
command -v sudo >/dev/null 2>&1 || { echo "!! sudo not found." >&2; exit 1; }

# --- Login + capture ----------------------------------------------------------
# Run the capture tool straight from source via the Swift toolchain — nothing to
# build, manage, or leave stale (adds a few seconds of compile-on-run startup).
echo ">> Opening CalNet login for $GP_GATEWAY ..."
if ! RESULT="$(swift "$HERE/capture.swift")"; then
    echo "!! Login/capture failed (see message above)." >&2
    exit 1
fi
COOKIE="$(printf '%s' "$RESULT" | sed -n 's/.*"prelogin-cookie":"\([^"]*\)".*/\1/p')"
GP_USER="$(printf '%s' "$RESULT" | sed -n 's/.*"saml-username":"\([^"]*\)".*/\1/p')"

if [[ -z "$COOKIE" || -z "$GP_USER" ]]; then
    echo "!! Failed to capture auth token (cookie or username missing)." >&2
    exit 1
fi

# --- Connect ------------------------------------------------------------------
echo ">> Got auth token for user '$GP_USER'. Starting VPN (sudo password needed)..."
# exec so sudo (and openconnect under it) replaces this shell — no lingering bash
# layer, clean Ctrl-C / signals. The here-string feeds the cookie to
# --passwd-on-stdin with a trailing newline; sudo still reads its password from the tty.
exec sudo openconnect \
    --protocol=gp \
    --user="$GP_USER" \
    --usergroup gateway:prelogin-cookie \
    --passwd-on-stdin \
    "$GP_GATEWAY" <<<"$COOKIE"
