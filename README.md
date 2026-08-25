# ocserv-sso

GitHub OAuth 2.0 single sign-on for [ocserv](https://www.infradead.org/ocserv/) (OpenConnect / Cisco AnyConnect server), in a single container.

Replaces password / TOTP / PAT authentication with **"sign in with GitHub"**: a user is allowed to connect iff they are an active member of one of your configured GitHub organizations. Authentication decisions converge on one small FastAPI portal; ocserv delegates to it via PAM (`pam_exec`).

## Architecture

```
                       ┌─────────────────────────────────────────┐
                       │  single container (ocserv-sso)           │
  AnyConnect ─── 443 ─►│  ocserv (TLS, patched sso-v2)           │
  vpn-cli     ─── 443 ─►│    │ pam_exec helper                    │
                       │    └─► POST /introspect  (127.0.0.1:8443) │
                       │  vpn-portal (uvicorn, loopback only)     │
                       │    ├─ /+CSCOE+/sso/*   browser leg       │
                       │    ├─ /device/*        Device Flow       │
                       │    ├─ /introspect      PAM helper         │
                       │    └─ /healthz                            │
                       └─────────────────────────────────────────┘
                                        │
                                        ▼
                          api.github.com (org membership check)
```

Two client flows, one authz decision:

- **AnyConnect embedded browser** — ocserv's sso-v2 patch proxies `/+CSCOE+/sso/*` to the portal; the user completes GitHub OAuth in the AnyConnect window, gets a composite cookie (`acSamlv2Token`), and ocserv splits it into `username` + `password="sid.ticket"` for the PAM helper.
- **vpn-cli (Device Flow)** — headless / CLI clients. `vpn-cli` posts to `/device/code`, polls `/device/token`, and feeds the resulting GitHub `access_token` to openconnect via stdin. The PAM helper introspects that token.

Both paths terminate at **`POST /introspect`** (loopback only): `{token}` → `{"active": bool, "username": login}`. `pam_exec` returns accept/reject based on `active`.

## Repository layout

```
ocserv/patches/   ocserv 1.5.0 sso-v2 patch (browser leg + cookie split)
ocserv/pam/       PAM config (ocserv) + pam_exec helper (ocserv_portal_auth.py)
portal/           FastAPI app (app.py, vpn_authz.py, requirements.txt)
single/           Multi-stage Dockerfile + entrypoint.sh (one image)
vpn-cli/          stdlib-only Device Flow client → openconnect
examples/         ocserv.conf.example, docker-compose.yml.example
tests/            test_portal.py (unit), sso_protocol_sim.py + run_integration.sh (integration)
```

## Quick start

1. **Prerequisites (host)**: Docker, a domain with DNS pointing here, ports 443/udp+tcp open, `net.ipv4.ip_forward=1`, a Let's Encrypt cert for your domain, and a GitHub OAuth App (Authorization callback URL = `https://<your-domain>/+CSCOE+/sso/callback`).

2. **Secrets** (read-only files under `/run/secrets/` — never env, `docker inspect` leaks `Config.Env`):
   - `github_oauth_client_id`, `github_oauth_client_secret` — from the GitHub OAuth App
   - `verifier_token` — a GitHub PAT with `read:org` (used for the org-membership API call)
   - `sso_hmac_key` — `openssl rand -hex 32`

3. **Copy the examples** and edit:
   ```
   cp examples/ocserv.conf.example ocserv.conf        # set your domain, routes
   cp examples/docker-compose.yml.example docker-compose.yml
   ```
   Set `GITHUB_ORGS` to your org list and `SSO_BASE_URL`/`OCSERV_SSO_BASE_URL` to your domain.

4. **Build & run**:
   ```
   docker compose build
   docker compose up -d
   docker logs -f ocserv-sso
   ```

5. **Connect**:
   - AnyConnect: server = `https://<your-domain>`, username arbitrary → browser opens for GitHub sign-in.
   - CLI: `sudo ./vpn-cli/vpn-cli connect <your-domain>`

## Configuration

### Environment (container)

| Var | Default | Purpose |
|-----|---------|---------|
| `SSO_BASE_URL` | `https://localhost` | Public URL of this VPN gateway (GitHub OAuth redirect target) |
| `SSO_BIND` / `SSO_PORT` | `127.0.0.1` / `8443` | Portal bind address (loopback — ocserv proxies the browser leg) |
| `GITHUB_ORGS` | `example-org` | Comma-separated org list; any active membership = allow |
| `OCSERV_SSO_ENABLE` | `1` | Enable sso-v2 patch in ocserv |
| `OCSERV_SSO_BASE_URL` | `https://localhost` | ocserv-side base URL (browser-leg proxy target) |
| `SSO_VERIFY_ALLOWED_HOSTS` | `127.0.0.1,::1` | IPs allowed to call `/verify` (loopback) |
| `SSO_SECRETS_DIR` | `/run/secrets` | Where the portal reads secret files |

Secrets are **files**, not env. The compose example mounts the four files above as read-only volumes.

### ocserv.conf

See `examples/ocserv.conf.example`. Key settings: `auth = "pam[service=ocserv]"`, certs from Let's Encrypt mount, `ipv4-network` (must not overlap your LAN), `device = vpns`, `auth-timeout = 300` (must cover the full GitHub OAuth leg).

## Testing

```
# unit (fake-GitHub, no network)
pip install -r portal/requirements.txt
pip install pytest httpx
pytest tests/test_portal.py -q

# integration (builds the single image, runs the full SSO protocol on 127.0.0.1)
tests/run_integration.sh
```

The integration gate exercises three client modes against the real single container: AnyConnect embedded, STRAP external-browser, and CLI Device Flow.

## Security notes

- `/introspect` and `/verify` are loopback-only. The portal binds to `127.0.0.1` inside the container; the browser leg is reached via ocserv's `/+CSCOE+/sso/` reverse proxy, not directly.
- `access_token` is never passed on `argv` (visible to all local processes). `vpn-cli` injects it via openconnect stdin.
- Tickets are single-use, TTL-bounded. State is in-memory; a restart invalidates in-flight browser flows only (clients retry).
- `fail2ban`-style ban is handled by ocserv itself (`max-ban-score` / `ban-time`).

## License

MIT — see [LICENSE](LICENSE).
