# berkeley-vpn

A macOS command-line wrapper around [openconnect](https://www.infradead.org/openconnect/)
for the UC Berkeley VPN (`vpn.berkeley.edu`), so you don't need the GlobalProtect app.

Berkeley's VPN is GlobalProtect with CalNet + Duo (SAML) login. openconnect can speak
GlobalProtect but can't do the CalNet/Duo login handshake. This tool does that handshake
in a small WebKit login window, hands the resulting token to openconnect, and connects,
with split, full, and restricted tunnel options from the command line.

It's a **lightweight command-line tool**: just two files (`connect.sh` and `capture.swift`),
with no app to install and nothing running in the background. The restricted tunnel adds
one optional helper, downloaded only if you ask for it.

## Requirements

- macOS with the Xcode Command Line Tools (`xcode-select --install`, which provides `swift`).
- openconnect (`brew install openconnect`).
- A CalNet account with Duo.

If openconnect or the Swift toolchain isn't installed, the script tells you the exact
command to install it and stops before doing anything else.

## Install

One line:

```
curl -fsSL https://raw.githubusercontent.com/shahaadi/berkeley-vpn/main/install.sh | bash
```

This downloads the two scripts and links a `berkeley-vpn` command, and tells you if its
directory isn't already on your `PATH`.

Or manually:

```
git clone https://github.com/shahaadi/berkeley-vpn.git
cd berkeley-vpn
./connect.sh
```

If you run it from a clone, use `./connect.sh` wherever this README says `berkeley-vpn`
(for example `./connect.sh full` or `./connect.sh logout`). The one-line install gives you
the `berkeley-vpn` command on your `PATH` instead.

## Usage

```
berkeley-vpn              # split tunnel (default): only campus traffic via the VPN
berkeley-vpn split        # the same, written out
berkeley-vpn full         # full tunnel: all traffic via the VPN (library/journal access)
berkeley-vpn restricted   # optional add-on; asks to install on first use (see below)
berkeley-vpn help
```

### Manage your session and install

```
berkeley-vpn set [split | full | restricted]  # make that your default for plain `berkeley-vpn`
berkeley-vpn set                              # show the current default (split unless changed)
berkeley-vpn login                            # open the CalNet login to refresh your session (no connect)
berkeley-vpn logout                           # clear the saved CalNet session
berkeley-vpn update                           # update to the latest version (only downloads if newer)
berkeley-vpn version                          # print the installed version
berkeley-vpn uninstall                        # remove berkeley-vpn (asks to confirm first)
```

`set` saves your choice under `~/Library/Application Support/berkeley-vpn/`, so running
`berkeley-vpn` with no argument uses it. Pass a tunnel explicitly (for example
`berkeley-vpn split`) to override it for one run. `update` checks the repo's `VERSION` (a
few bytes) first and only re-downloads the scripts when a newer version exists.

Running it prints a banner showing what it's doing and how to switch:

```
==================================================================
  Berkeley VPN
    tunnel : Split tunnel (only campus/Berkeley traffic goes through the VPN)
    gateway: campus-split.vpn.berkeley.edu
    switch : berkeley-vpn [split | full | restricted]   (run 'berkeley-vpn help' for help)
==================================================================
```

A small login window opens -> sign in with CalNet and approve Duo -> enter your Mac
password for `sudo` when prompted -> connected. Press Ctrl-C in the terminal to disconnect.

### Tunnels

| Option | Gateway | What goes through the VPN |
|---|---|---|
| `split` (default) | `campus-split.vpn.berkeley.edu` | Only campus/Berkeley traffic |
| `full` | `campus.vpn.berkeley.edu` | All of your internet traffic (use for licensed library/journal access) |
| `restricted` (opt-in) | `restricted.vpn.berkeley.edu` | Berkeley's most-sensitive data tier ("P4"), see below |

**Not sure which to pick?** Use `split` (the default). It's faster and leaves your everyday
traffic alone. Choose `full` only when you need off-campus access to licensed resources
(library databases, journals, software) and `split` isn't routing them. Both are equally
secure for campus access; they differ only in how much of your traffic goes through the VPN.

#### Restricted tunnel (optional add-on)

The Restricted VPN is for staff who access or administer systems holding large amounts of
restricted (P4) data or key IT infrastructure. It needs prior approval from the Information
Security Office (`rvpn@berkeley.edu`) and a device that meets stricter security
requirements, so it's kept out of the core tool. The first time you run
`berkeley-vpn restricted` it shows who it's for and asks to download a small helper
(`restricted.sh`); once installed, `restricted` works like the other tunnels. Remove it
with `berkeley-vpn uninstall`. See Berkeley's
[Restricted VPN page](https://security.berkeley.edu/services/bsecure/restricted-vpn).

### Environment variables

- `GP_GATEWAY=<host> berkeley-vpn` connects to a specific gateway host (overrides the tunnel choice).
- `GP_TIMEOUT=<seconds> berkeley-vpn` sets how long to wait for the login window (default `240`).

## How it works

1. `connect.sh` is a bash wrapper. It picks the gateway from your tunnel choice, prints the
   banner, checks that `swift` and `openconnect` are installed, then runs the login helper
   and `openconnect`.
2. `capture.swift` opens a WebKit (the system Safari engine) window at Berkeley's CalNet
   SAML login. You authenticate with CalNet and Duo, and it reads the GlobalProtect
   `prelogin-cookie` from the gateway's SAML response headers.
3. That short-lived token is handed to
   `openconnect --protocol=gp --usergroup gateway:prelogin-cookie <gateway>` to bring up the tunnel.

Your password never touches this tool; you type it into the CalNet window and Duo approves.
To save logging in again on every connect, your CalNet session cookies are saved in your
login Keychain (encrypted at rest) and replayed without the window while they're still
valid. Berkeley's sessions are short-lived, so you'll often still log in. Clear the saved
session anytime with `berkeley-vpn logout`. The VPN token is short-lived, handed straight to
openconnect, and not persisted. Nothing runs in the background.

> Autofill and passkeys: the window can't use macOS's built-in saved-password autofill or
> passkeys. Embedded WKWebViews have no web-form autofill surface, and passkeys/WebAuthn
> need an associated-domains entitlement that only Berkeley or Duo could grant. Two things
> do work: paste (⌘V or right-click), and a system-wide password manager (for example
> 1Password's universal autofill, ⌘\) that fills the window through macOS accessibility
> like any other app.

## Troubleshooting

- `openconnect not found` -> `brew install openconnect`
- `Xcode Command Line Tools not found` -> `xcode-select --install`
- Login window opens but no token captured -> it prints the reason to the terminal; re-run.
- `Run from a terminal...` -> run it in a real terminal (it needs a tty for the `sudo`
  password prompt), not piped or automated.
- First connect feels slow -> the Swift helper compiles on each run (a few seconds) before
  the login window appears. That's expected.
- Disconnecting -> there's no disconnect command; press Ctrl-C in the terminal where it's running.
- HIP report and routing warnings on connect -> messages like `Server asked us to submit HIP
  report...` or `route: writing to routing socket: Can't assign requested address` are
  expected on macOS and harmless. The tunnel still comes up and the campus routes are added.

## License

[MIT](LICENSE).
