# berkeley-vpn

A tiny **macOS CLI wrapper around [openconnect](https://www.infradead.org/openconnect/)**
for connecting to the **UC Berkeley VPN** (`vpn.berkeley.edu`) — without installing
Palo Alto's GlobalProtect app.

Berkeley's VPN is GlobalProtect with CalNet + Duo login. `openconnect` can
speak GlobalProtect, but the CalNet/Duo login handshake is the fiddly part. This
tool does just that handshake in a small WebKit login window, hands the resulting
token to `openconnect`, and connects — with simple **split / full / restricted**
tunnel options right from the command line.

It's deliberately lightweight: the core is two small files (`connect.sh` +
`capture.swift`) — no app to install, nothing running in the background. (The
restricted tunnel adds one optional helper, downloaded only if you ask for it.)
It's basically a thin, convenient layer on top of `openconnect`.

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

> Running from a clone? Use `./connect.sh` wherever this README says `berkeley-vpn`
> (e.g. `./connect.sh full`, `./connect.sh logout`). Installing via the one-liner
> above gives you the `berkeley-vpn` command on your `PATH` instead.

## Usage

```sh
berkeley-vpn              # Split Tunnel (default) — only campus traffic via the VPN
berkeley-vpn split        # the same, written out explicitly
berkeley-vpn full        # Full Tunnel — ALL traffic via the VPN (library/journal access)
berkeley-vpn restricted  # optional add-on — asks to install on first use (see below)
berkeley-vpn help
```

### Manage your session / install

```sh
berkeley-vpn version     # print the installed version
berkeley-vpn set full    # make 'full' your default, so plain `berkeley-vpn` uses it
berkeley-vpn set         # show the current default (split unless you've changed it)
berkeley-vpn login       # open the CalNet login to refresh your session (no connect)
berkeley-vpn logout      # clear the saved CalNet session (forces a fresh login)
berkeley-vpn update      # update to the latest version (only downloads if newer)
berkeley-vpn uninstall   # remove berkeley-vpn (asks to confirm first)
```

`set` saves your choice to `~/Library/Application Support/berkeley-vpn/` so running
`berkeley-vpn` with no argument uses it; pass a tunnel explicitly (e.g. `berkeley-vpn
split`) to override it for one run. `update` first checks the repo's `VERSION` (a few
bytes) and only re-downloads the scripts when a newer version exists — otherwise it
just says you're up to date.

Running it prints a banner showing exactly what it's doing and how to switch:

```
==================================================================
  Berkeley VPN
    tunnel : Split Tunnel — only campus traffic goes through the VPN
    gateway: campus-split.vpn.berkeley.edu
    switch : berkeley-vpn [split | full | restricted]   (run 'berkeley-vpn help')
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
| `restricted` *(opt-in)* | `restricted.vpn.berkeley.edu` | Berkeley's most-sensitive data tier ("P4") — see below |

> **Not sure which to pick?** Use **`split`** (the default) — it's faster and leaves
> your everyday traffic alone. Choose **`full`** only when you need off-campus access
> to licensed resources (library databases, journals, software) and `split` isn't
> routing them. Both are equally secure for campus access; they differ only in *how
> much* of your traffic goes through the VPN.

#### Restricted tunnel (optional add-on)

The **Restricted VPN** is only for staff who access or administer systems holding
large amounts of restricted (P4) data or key IT infrastructure. It needs prior
approval from the Information Security Office (`rvpn@berkeley.edu`) and a device
that meets stricter security requirements — **most people don't need it**, so it's
kept out of the core tool. The first time you run `berkeley-vpn restricted`, it
shows who it's for and asks to download a small helper (`restricted.sh`); once
installed, `restricted` works like the other tunnels. Remove it with
`berkeley-vpn uninstall`. See Berkeley's [Restricted VPN page](https://security.berkeley.edu/services/bsecure/restricted-vpn).

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

Your password never touches this tool — you type it into the CalNet window and Duo
approves. To skip re-login on every connect, your CalNet **session cookies** are
saved in your **login Keychain** (encrypted at rest) and replayed headlessly until
the session expires; clear them anytime with `berkeley-vpn logout`. The VPN token
itself is short-lived — handed straight to `openconnect`, never persisted. Nothing
runs in the background.

> **Autofill / passkeys:** the window can't use macOS's *built-in* saved-password
> autofill or passkeys — embedded WKWebViews have no web-form autofill surface, and
> passkeys/WebAuthn need an associated-domains entitlement only Berkeley/Duo could
> grant. Workarounds that do work: **paste** (⌘V or right-click), and a **system-wide
> password manager** (e.g. 1Password's universal autofill, ⌘\) fills the window via
> macOS accessibility just like any other app. With the saved session you rarely log
> in anyway.

## Troubleshooting

- **`openconnect not found`** → `brew install openconnect`
- **`Xcode Command Line Tools not found`** → `xcode-select --install`
- **Login window opens but no token captured** → it prints the reason to the
  terminal; just re-run.
- **`Run from a terminal …`** → run it in a real terminal (it needs a tty for the
  `sudo` password prompt), not piped/automated.
- **First connect feels slow** → the Swift helper compiles on each run (a few
  seconds) before the login window appears; that's expected.
- **Disconnecting** → there's no disconnect command — press **Ctrl-C** in the
  terminal where it's running.
- **HIP report / routing warnings on connect** → messages like `Server asked us to
  submit HIP report …` or `route: … Can't assign requested address` are expected on
  macOS and harmless; the tunnel still comes up and the campus routes are added.

## License

[MIT](LICENSE).
