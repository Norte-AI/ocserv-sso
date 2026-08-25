# Client Connection Guide

How to connect to an ocserv-sso VPN gateway. Two flows, both end at GitHub OAuth.

## Prerequisites

You must be an **active member** of one of the GitHub organizations configured on the server. Ask your administrator which orgs are allowed. If you left the org, access is revoked — no client-side fix exists.

---

## A. AnyConnect / Secure Client (browser leg)

1. Open AnyConnect / Cisco Secure Client.
2. Server: `https://<your-vpn-domain>`.
3. Click **Connect**. A browser window opens automatically.
4. Sign in with GitHub → click **Authorize**.
5. The VPN connects. No username/password is typed in the client.

The token is single-use and expires after ~120 s. If it expires mid-flow, disconnect and reconnect.

## B. vpn-cli (Device Flow, headless / CLI)

`vpn-cli` is a single stdlib Python script — no `pip install` needed. It drives GitHub Device Flow and hands the resulting token to openconnect via stdin.

### Install openconnect

- **macOS**: `brew install openconnect`
- **Debian/Ubuntu**: `sudo apt install openconnect`
- **Fedora**: `sudo dnf install openconnect`

### Connect

```bash
sudo ./vpn-cli/vpn-cli connect <your-vpn-domain>
```

You'll see a verification URL and a user code:

```
请打开 https://<your-vpn-domain>/device 并输入验证码: FAKE-CODE
(GitHub 会话有效期内静默, 无需每次授权)
```

Open that URL in **any browser** (phone, another machine — it doesn't have to be on the VPN host), sign in to GitHub, enter the code, authorize. `vpn-cli` polls until authorized, then execs:

```
sudo openconnect <your-vpn-domain> --user=<your-github-login> --passwd-on-stdin
```

The access token is injected via stdin — it never appears in `argv` (which is visible to all local processes via `ps`). GitHub sessions stay valid for a while, so reconnections are silent until the token expires.

### Why Device Flow?

Device Flow is the only GitHub OAuth flow that works without a browser on the connecting host. AnyConnect's embedded browser is unavailable on headless servers / WSL / minimal Linux; Device Flow lets you authorize on your phone while the tunnel comes up on the box.

---

## Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| AnyConnect opens browser but "invalid_sid" | Restart the connection — the session ID was malformed (rare; usually a client clock/cookie issue). |
| AnyConnect stays on "sign in" forever | GitHub OAuth leg timed out (server `auth-timeout = 300`). Reconnect. |
| vpn-cli: `expired_token` | The user code expired (default 15 min). Re-run `vpn-cli`. |
| vpn-cli: `authorization_pending` | Normal — you haven't entered the code in the browser yet. |
| `access_denied` after authorize | You are not an active member of any allowed org. |
| `/verify` returns 403 | Called from a non-loopback host; `/verify` is loopback-only by design. |
| Connection drops on restart | In-memory state was reset (browser flows only); the tunnel re-establishes on retry. |
