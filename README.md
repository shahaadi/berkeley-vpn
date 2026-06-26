# berkeley-vpn

A tiny **CLI wrapper around [openconnect](https://www.infradead.org/openconnect/)**
for connecting to the **UC Berkeley VPN** (`vpn.berkeley.edu`) — without installing
Palo Alto's GlobalProtect app.

Berkeley's VPN is GlobalProtect with CalNet + Duo (SAML) login. `openconnect` can
speak GlobalProtect, but the CalNet/Duo SAML handshake is the fiddly part. This
tool does just that handshake in a small WebKit login window, hands the resulting
token to `openconnect`, and connects — with simple **split / full / restricted**
tunnel options right from the command line.

It's deliberately lightweight: two small files (`connect.sh` + `capture.swift`),
no app to install, nothing running in the background. It's basically a thin,
convenient layer on top of `openconnect`.

## Requirements

- **macOS** with the **Xcode Command Line Tools** — `xcode-select --install` (provides `swift`).
- **[openconnect](https://www.infradead.org/openconnect/)** — `brew install openconnect`.
- A **CalNet** account with Duo.

> If `openconnect` (or the Swift toolchain) isn't installed, the script tells you
> the exact command to install it and stops before doing anything else.

## Install

One line:

```sh
curl -fsSL https://raw.githubusercontent.com/shahaadi/berkeley-vpn/main/install.sh | bash
```

This downloads the two scripts and links a `berkeley-vpn` command (and tells you
if its directory isn't already on your `PATH`).

Or manually:

```sh
git clone https://github.com/shahaadi/berkeley-vpn.git
cd berkeley-vpn
./connect.sh
```

## Usage

```sh
berkeley-vpn              # Split Tunnel (default) — only campus traffic via the VPN
berkeley-vpn full        # Full Tunnel — ALL traffic via the VPN (library/journal access)
berkeley-vpn split
berkeley-vpn restricted
berkeley-vpn --help
```

### Manage your session / install

```sh
berkeley-vpn login       # open the CalNet login to refresh your session (no connect)
berkeley-vpn logout      # clear the saved CalNet session (forces a fresh login)
berkeley-vpn uninstall   # remove berkeley-vpn (asks to confirm first)
```

Running it prints a banner showing exactly what it's doing and how to switch:

```
==================================================================
  Berkeley VPN
    tunnel : Split Tunnel — only campus traffic goes through the VPN
    gateway: campus-split.vpn.berkeley.edu
    switch : berkeley-vpn [split | full | restricted]   (berkeley-vpn -h for help)
==================================================================
```

Then: a small login window opens → sign in with **CalNet** and approve **Duo** →
enter your **Mac password** for `sudo` when prompted → connected.
Press **Ctrl-C** in the terminal to disconnect.

### Tunnels

| Option | Gateway | What goes through the VPN |
|---|---|---|
| `split` *(default)* | `campus-split.vpn.berkeley.edu` | Only campus/Berkeley traffic |
| `full` | `campus.vpn.berkeley.edu` | All of your internet traffic (use for licensed library/journal access) |
| `restricted` | `restricted.vpn.berkeley.edu` | Restricted tunnel |

### Advanced (environment variables)

- `GP_GATEWAY=<host> berkeley-vpn` — connect to a specific gateway host (overrides the tunnel choice).
- `GP_TIMEOUT=<seconds> berkeley-vpn` — how long to wait for the login window (default `240`).

## How it works

1. **`connect.sh`** — a small bash wrapper. Picks the gateway from your tunnel
   choice, prints the banner, checks that `swift` and `openconnect` are installed,
   then runs the login helper and finally `openconnect`.
2. **`capture.swift`** — opens a WebKit (the system Safari engine) window at
   Berkeley's CalNet SAML login. You authenticate with CalNet + Duo, and it reads
   the GlobalProtect `prelogin-cookie` from the gateway's SAML response headers.
3. That short-lived token is handed to
   `openconnect --protocol=gp --usergroup gateway:prelogin-cookie …` to bring up
   the tunnel.

Your password never touches this tool — you type it into the CalNet window, Duo
approves, and only a short-lived VPN token is used. Nothing is stored or runs in
the background.

> **Autofill / passkeys:** the login window can't offer saved-password autofill or
> passkeys. macOS WKWebView has no web-form autofill surface, and passkeys would
> require an Apple entitlement only Berkeley/Duo could grant. So type your CalNet
> password and approve Duo by push or passcode — the persistent session means
> you usually won't be asked again for a while.

## Troubleshooting

- **`openconnect not found`** → `brew install openconnect`
- **`Swift toolchain not found`** → `xcode-select --install`
- **Login window opens but no token captured** → it prints the reason to the
  terminal; just re-run.
- **`Run from a terminal …`** → run it in a real terminal (it needs a tty for the
  `sudo` password prompt), not piped/automated.
- Some resources may note a missing HIP report; the tunnel still comes up.

## License

[MIT](LICENSE).
