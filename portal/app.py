"""vpn-portal — GitHub OAuth 2.0 portal for ocserv sso-v2 authentication.

Flow (see docs/sso-v2-github-oauth-spec.md):
  AnyConnect embedded browser
    -> GET /+CSCOE+/sso/start?sid={sid}      (302 -> github authorize)
    -> GET /+CSCOE+/sso/callback?code&state  (exchange code, org check,
                                              mint ticket, set acSamlv2Token)
    -> GET /+CSCOE+/sso/done                 ("success" final page)
  FreeRADIUS script (loopback only)
    -> GET /verify?sid&ticket                (200 + X-SSO-User, or 403)

Token cookie (see docs/refactor-single-container-spec.md):
  acSamlv2Token = b32(login) || sid || ticket   (composite; the ocserv
                  patch splits it into username=b32(login) and
                  password="sid.ticket"; pam_exec posts the password to
                  POST /introspect)
  sid    = 26 hex chars, ticket = 32 chars [0-9a-z] (alphanumeric: the
           AnyConnect client validates cookie values as alphanumeric).

Backends:
  POST /introspect  {token: "sid.ticket"} -> {"active":bool,"username":login}
                    (loopback only; called by the PAM pam_exec helper)
  GET  /verify?sid&ticket -> 200 + X-SSO-User (migration period; deleted in P4)

All state is in-memory; a restart invalidates in-flight browser flows only
(clients retry the connection).
"""
import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import struct
import sys
import threading
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vpn_authz  # noqa: E402

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

log = logging.getLogger("vpn-portal")
logging.basicConfig(level=os.environ.get("SSO_LOG_LEVEL", "INFO"))

# --- configuration -----------------------------------------------------------

BASE_URL = os.environ.get("SSO_BASE_URL", "https://localhost").rstrip("/")
# 授权 org 列表(逗号分隔, 任一 active 成员即放行). GITHUB_ORG 为旧单值兼容.
GITHUB_ORGS = vpn_authz.parse_orgs(
    os.environ.get("GITHUB_ORGS", os.environ.get("GITHUB_ORG", "example-org")))
TICKET_TTL = int(os.environ.get("TICKET_TTL", "120"))
PENDING_TTL = int(os.environ.get("PENDING_TTL", "300"))
PENDING_MAX = int(os.environ.get("PENDING_MAX", "1024"))
MEMBER_CACHE_TTL = 300
API_TIMEOUT = 5
VERIFY_ALLOWED_HOSTS = set(
    os.environ.get("SSO_VERIFY_ALLOWED_HOSTS", "127.0.0.1,::1").split(",")
)

# Test-only mode: serve a local fake GitHub authorize endpoint and skip the
# code exchange + org API call (SSO_FAKE_LOGIN / SSO_FAKE_MEMBER apply).
# Never enable in production (deploy.sh does not set it).
FAKE_GITHUB = os.environ.get("SSO_FAKE_GITHUB") == "1"
FAKE_LOGIN = os.environ.get("SSO_FAKE_LOGIN", "testuser")
FAKE_MEMBER = os.environ.get("SSO_FAKE_MEMBER", "1") == "1"

# Browser leg: the user's browser hits github.com directly (the user is
# outside the blocked region or has their own proxy), so this stays fixed.
GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
# Server-side calls (token exchange, device/code). Override these to point at
# a reverse proxy (e.g. a Cloudflare Worker) when the host cannot reach
# github.com directly. Defaults are the real github.com endpoints.
GITHUB_TOKEN_URL = os.environ.get(
    "GITHUB_TOKEN_URL", "https://github.com/login/oauth/access_token"
)
# api.github.com is reachable from the host even when github.com is blocked,
# so no proxy is needed for the /user lookup.
GITHUB_USER_URL = "https://api.github.com/user"

SID_RE = re.compile(r"^[0-9a-f]{26}$")
LOGIN_RE = vpn_authz.LOGIN_RE
DH_RE = re.compile(r"^[A-Za-z0-9_-]{20,180}$")
TICKET_RE = re.compile(r"^[0-9a-z]{32}$")
TICKET_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"
PREFIX = "/+CSCOE+/sso"
DONE_URL = f"{BASE_URL}{PREFIX}/done"

# introspect 输入形态: "sid.ticket" (26 hex + '.' + 32 [0-9a-z]); 其它串视为
# GitHub access_token (Device Flow 产物, P1), 经 GitHub /user + org 校验放行.
INTROSPECT_TOKEN_RE = re.compile(r"^([0-9a-f]{26})\.([0-9a-z]{32})$")

# Device Flow 轮询暂存: device_code -> {"t": float, "interval": int}
DEVICE_PENDING = {}
DEVICE_PENDING_TTL = 900


def _read_secret(name: str) -> str:
    """Secrets come from read-only file mounts (SSO_SECRETS_DIR overrides
    the directory for tests). Missing file -> empty string: the app starts
    and reports a config error on use instead of crashing the container."""
    path = os.path.join(os.environ.get("SSO_SECRETS_DIR", "/run/secrets"), name)
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


CLIENT_ID = _read_secret("github_oauth_client_id")
CLIENT_SECRET = _read_secret("github_oauth_client_secret")
VERIFIER_TOKEN = _read_secret("verifier_token")
STATE_KEY = bytes.fromhex(_read_secret("sso_hmac_key") or "00" * 32)
# --- state -------------------------------------------------------------------

LOCK = threading.Lock()
PENDING = {}  # state -> {"sid": str, "t": float}
ISSUED = {}  # sid  -> {"ticket_hash": str, "login": str, "t": float, "used": bool}
_AUTHZ = vpn_authz.AuthorizedMember(GITHUB_ORGS, VERIFIER_TOKEN, lock=LOCK)
MEMBER_CACHE = _AUTHZ.cache  # 兼容别名 (测试/排错); 权威持有者为 _AUTHZ


def _purge_locked(now: float) -> None:
    for state in [k for k, v in PENDING.items() if now - v["t"] > PENDING_TTL]:
        del PENDING[state]
    for sid in [k for k, v in ISSUED.items() if now - v["t"] > TICKET_TTL]:
        del ISSUED[sid]
    while len(PENDING) > PENDING_MAX:
        PENDING.pop(next(iter(PENDING)))


def _b32_login(login: str) -> str:
    return vpn_authz.b32_login(login)


def _gen_ticket() -> str:
    return "".join(secrets.choice(TICKET_ALPHABET) for _ in range(32))


def _gen_state(sid: str) -> str:
    nonce = secrets.token_bytes(16)
    mac = hmac.new(STATE_KEY, sid.encode() + nonce, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(nonce + mac).decode().rstrip("=")


def _state_mac_ok(state: str, sid: str) -> bool:
    try:
        raw = base64.urlsafe_b64decode(state + "=" * (-len(state) % 4))
        nonce, mac = raw[:16], raw[16:]
    except Exception:
        return False
    want = hmac.new(STATE_KEY, sid.encode() + nonce, hashlib.sha256).digest()[:16]
    return hmac.compare_digest(mac, want)


def _member_of(login: str, org: str) -> bool:
    """Delegated to vpn_authz (tests patch this symbol directly)."""
    return _AUTHZ.member_of(login, org)


def _authorized_member(login: str) -> bool:
    """Same policy as freeradius/scripts/github_vpn_auth.py: active
    membership in ANY of GITHUB_ORGS (cached per login+org)."""
    ok = _AUTHZ.is_authorized(login)
    if ok:
        log.info("sso: %s authorized via orgs %s", login, GITHUB_ORGS)
    return ok


def _github_login(code: str) -> str:
    r = requests.post(
        GITHUB_TOKEN_URL,
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "redirect_uri": f"{BASE_URL}{PREFIX}/callback",
        },
        headers={"Accept": "application/json"},
        timeout=API_TIMEOUT,
    )
    token = r.json().get("access_token")
    if not token:
        raise RuntimeError("code exchange failed")
    r = requests.get(
        GITHUB_USER_URL,
        headers={"Authorization": f"Bearer {token}"},
        timeout=API_TIMEOUT,
    )
    login = r.json().get("login")
    if not login:
        raise RuntimeError("no login in /user")
    return login


def _strap_blob(token: str, dh_b64url: str) -> str:
    """STRAP (external-browser) token envelope, per openconnect hpke.c.

    `token` is the composite b32(login)||sid||ticket — the client submits
    it directly as <sso-token>; the ocserv patch splits it into
    username=b32(login) / password="sid.ticket" for the PAM pam_exec helper.

      blob = 0x0001 || TLV(1, server SPKI pubkey) || TLV(2, 12B GCM tag)
                  || TLV(3, ciphertext) || TLV(4, 12B IV)

    key = HKDF-SHA256(extract&expand, IKM=ECDH(server_ephemeral,
    client DH pubkey), salt=zeros, info="AC_ECIES", L=32); AES-256-GCM.
    The client decrypts it in its localhost:29786 handler.
    """
    pub_der = base64.urlsafe_b64decode(
        dh_b64url + "=" * (-len(dh_b64url) % 4))
    client_pub = serialization.load_der_public_key(pub_der)
    if not isinstance(client_pub, ec.EllipticCurvePublicKey) or \
            not isinstance(client_pub.curve, ec.SECP256R1):
        raise ValueError("not a P-256 public key")
    server_priv = ec.generate_private_key(ec.SECP256R1())
    shared = server_priv.exchange(ec.ECDH(), client_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"AC_ECIES").derive(shared)
    iv = secrets.token_bytes(12)
    sealed = AESGCM(key).encrypt(iv, token.encode(), None)
    # openconnect hpke.c expects a 12-byte AEAD tag: GCM truncated tag
    # (first 12 bytes of the 16-byte tag), matching OpenSSL SET_TAG(12)
    ciphertext, tag = sealed[:-16], sealed[-16:][:12]
    server_pub_der = server_priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)

    def tlv(t: int, v: bytes) -> bytes:
        return struct.pack(">HH", t, len(v)) + v

    blob = (b"\x00\x01" + tlv(1, server_pub_der) + tlv(2, tag)
            + tlv(3, ciphertext) + tlv(4, iv))
    return base64.b64encode(blob).decode()


def _error_redirect(reason: str) -> RedirectResponse:
    resp = RedirectResponse(DONE_URL, status_code=303)
    resp.set_cookie(
        "acSamlv2Error", reason, max_age=TICKET_TTL, path="/",
        secure=True, httponly=True, samesite="lax",
    )
    return resp


def _success_redirect(sid: str, login: str, dh: str = "") -> RedirectResponse:
    ticket = _gen_ticket()
    with LOCK:
        _purge_locked(time.time())
        ISSUED[sid] = {
            "ticket_hash": hashlib.sha256(ticket.encode()).hexdigest(),
            "login": login,
            "t": time.time(),
            "used": False,
        }
    token = _b32_login(login) + sid + ticket  # legacy composite cookie
    log.info("sso: issued ticket for sid=%s login=%s", sid, login)
    if DH_RE.match(dh or ""):
        # STRAP external-browser mode: hand the composite token to the
        # client's localhost listener (it submits it as the sso-token).
        try:
            blob = _strap_blob(token, dh)
        except Exception as e:
            log.warning("sso: STRAP blob failed: %s", e)
            return _error_redirect("strap_error")
        log.info("sso: STRAP redirect for sid=%s login=%s", sid, login)
        return RedirectResponse(
            "http://localhost:29786/api/sso/" + quote(blob, safe="")
            + "?return=" + quote(DONE_URL, safe=""),
            status_code=303,
        )
    resp = RedirectResponse(DONE_URL, status_code=303)
    resp.set_cookie(
        "acSamlv2Token", token, max_age=TICKET_TTL, path="/",
        secure=True, httponly=True, samesite="lax",
    )
    return resp


app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


# --- browser-leg endpoints (served through the ocserv /+CSCOE+/sso proxy) ----

@app.get(f"{PREFIX}/start")
def sso_start(sid: str = "", dh: str = ""):
    if not SID_RE.match(sid):
        log.warning("sso: start with invalid sid")
        return _error_redirect("invalid_sid")
    if not FAKE_GITHUB and not CLIENT_ID:
        log.error("sso: github OAuth app not configured")
        return _error_redirect("config_error")
    if dh and not DH_RE.match(dh):
        dh = ""
    state = _gen_state(sid)
    with LOCK:
        _purge_locked(time.time())
        PENDING[state] = {"sid": sid, "t": time.time(), "dh": dh}
    if FAKE_GITHUB:
        return RedirectResponse(f"{PREFIX}/fake/authorize?state={state}", status_code=303)
    from urllib.parse import quote

    return RedirectResponse(
        GITHUB_AUTHORIZE_URL
        + f"?client_id={CLIENT_ID}"
        + f"&redirect_uri={quote(f'{BASE_URL}{PREFIX}/callback', safe='')}"
        + f"&state={state}&allow_signup=false",
        status_code=303,
    )


@app.get(f"{PREFIX}/fake/authorize")
def fake_authorize(state: str = ""):
    """Test-only stand-in for github.com/login/oauth/authorize."""
    if not FAKE_GITHUB:
        return PlainTextResponse("not found", status_code=404)
    return RedirectResponse(f"{PREFIX}/callback?code=fake-code&state={state}", status_code=303)


@app.get(f"{PREFIX}/callback")
def sso_callback(code: str = "", state: str = "", error: str = ""):
    if error:
        log.info("sso: authorization denied (%s)", error)
        return _error_redirect("denied")
    with LOCK:
        pending = PENDING.pop(state, None)
    if pending is None or time.time() - pending["t"] > PENDING_TTL:
        log.warning("sso: unknown or expired state")
        return _error_redirect("invalid_state")
    if not _state_mac_ok(state, pending["sid"]):
        log.warning("sso: state HMAC mismatch")
        return _error_redirect("invalid_state")

    try:
        login = FAKE_LOGIN if FAKE_GITHUB else _github_login(code)
    except Exception as e:
        log.warning("sso: github exchange failed: %s", e)
        return _error_redirect("github_error")
    if not LOGIN_RE.match(login):
        return _error_redirect("bad_login")
    member = FAKE_MEMBER if FAKE_GITHUB else _authorized_member(login)
    if not member:
        log.warning("sso: %s is not an active member of %s", login, GITHUB_ORGS)
        return _error_redirect("not_member")
    return _success_redirect(pending["sid"], login, pending.get("dh", ""))


@app.get(f"{PREFIX}/logout")
def sso_logout():
    return RedirectResponse(DONE_URL, status_code=303)


DONE_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>VPN authentication</title></head>
<body style="font-family:sans-serif;text-align:center;padding-top:3em">
<h2 id="msg">Checking result&hellip;</h2>
<script>
var ok = /(?:^|;\s*)acSamlv2Token=/.test(document.cookie);
var err = document.cookie.match(/(?:^|;\\s*)acSamlv2Error=([^;]+)/);
var msg = document.getElementById('msg');
if (ok) { msg.textContent = 'Authentication successful. You may close this window.'; }
else if (err) { msg.textContent = 'Authentication failed (' + decodeURIComponent(err[1]) + '). Close this window and retry.'; }
else { msg.textContent = 'No result. Close this window and retry.'; }
</script>
</body></html>
"""


@app.get(f"{PREFIX}/done")
def sso_done():
    return HTMLResponse(DONE_HTML)


def _github_login_from_token(access_token: str) -> str:
    """Bearer token -> GitHub login (Device Flow 产物 / 任意 access_token)."""
    try:
        r = requests.get(
            GITHUB_USER_URL,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=API_TIMEOUT,
        )
    except requests.RequestException as e:
        log.warning("introspect: github /user transport error: %s", e)
        return ""
    if r.status_code != 200:
        return ""
    login = r.json().get("login", "")
    return login if LOGIN_RE.match(login or "") else ""


def _introspect_github_token(token: str) -> str:
    """GitHub access_token 形态校验: /user -> login -> org active 成员."""
    if not vpn_authz.github_token_ok_shape(token):
        return ""
    if FAKE_GITHUB:
        if not FAKE_MEMBER:
            return ""
        log.info("introspect: fake github token active login=%s", FAKE_LOGIN)
        return FAKE_LOGIN
    login = _github_login_from_token(token)
    if not login:
        return ""
    if not _authorized_member(login):
        log.warning("introspect: %s not an active member of %s", login, GITHUB_ORGS)
        return ""
    log.info("introspect: github token active login=%s", login)
    return login


# --- verify (legacy, deleted in P4) + introspect (PAM pam_exec helper) -------

@app.get("/verify")
def verify(sid: str = "", ticket: str = "", request: Request = None):
    host = request.client.host if request.client else ""
    if "*" not in VERIFY_ALLOWED_HOSTS and host not in VERIFY_ALLOWED_HOSTS:
        return PlainTextResponse("forbidden", status_code=403)
    if not SID_RE.match(sid) or not re.match(r"^[0-9a-z]{32}$", ticket or ""):
        return PlainTextResponse("bad_params", status_code=403)
    with LOCK:
        rec = ISSUED.get(sid)
        if rec is None:
            return PlainTextResponse("unknown_sid", status_code=403)
        if rec["used"]:
            return PlainTextResponse("replayed", status_code=403)
        if time.time() - rec["t"] > TICKET_TTL:
            del ISSUED[sid]
            return PlainTextResponse("expired", status_code=403)
        if hashlib.sha256(ticket.encode()).hexdigest() != rec["ticket_hash"]:
            return PlainTextResponse("ticket_mismatch", status_code=403)
        rec["used"] = True
        login = rec["login"]
    log.info("sso: verified ticket sid=%s login=%s", sid, login)
    return PlainTextResponse("ok", headers={"X-SSO-User": login})


@app.post("/introspect")
async def introspect(request: Request):
    """RFC 7662-shaped token introspection for the PAM pam_exec helper.

    Input (form or JSON): token = "sid.ticket" — the ocserv sso patch
    derives this from the raw ticket the AnyConnect client submits.
    Always HTTP 200; {active:false} on any failure (including GitHub
    access_token input until P1 adds that branch)."""
    host = request.client.host if request.client else ""
    if "*" not in VERIFY_ALLOWED_HOSTS and host not in VERIFY_ALLOWED_HOSTS:
        return {"active": False}

    token = ""
    ctype = request.headers.get("content-type", "")
    try:
        if "application/json" in ctype:
            token = str((await request.json()).get("token", ""))
        else:
            token = str((await request.form()).get("token", ""))
    except Exception:
        return {"active": False}

    m = INTROSPECT_TOKEN_RE.match(token)
    if not m:
        # 分支 2 (P1): GitHub access_token (vpn-cli Device Flow 产物).
        # 用户名(ticket 复合串里的 b32(login))校验由 patch 拆串保证; CLI 走
        # username/password 表单时 username 即 GitHub login, 此处独立以
        # /user + org 校验为准.
        login = _introspect_github_token(token)
        if not login:
            return {"active": False}
        return {"active": True, "username": login}
    sid, ticket = m.groups()

    with LOCK:
        rec = ISSUED.get(sid)
        if rec is None or rec["used"] or time.time() - rec["t"] > TICKET_TTL:
            return {"active": False}
        if hashlib.sha256(ticket.encode()).hexdigest() != rec["ticket_hash"]:
            return {"active": False}
        rec["used"] = True
        login = rec["login"]
    log.info("introspect: active sid=%s login=%s", sid, login)
    return {"active": True, "username": login}


# --- Device Flow (vpn-cli; 代理 GitHub, 不暂存 access_token) -----------------

# Server-side Device Flow call; override with GITHUB_DEVICE_CODE_URL to point
# at a reverse proxy (e.g. a Cloudflare Worker) when github.com is unreachable.
DEVICE_CODE_URL = os.environ.get(
    "GITHUB_DEVICE_CODE_URL", "https://github.com/login/device/code"
)
DEVICE_SCOPE = "read:org read:user"


@app.post("/device/code")
def device_code():
    """Device Flow 发起 (RFC 8628). 转发 GitHub device/code 并透传响应."""
    if not CLIENT_ID:
        return PlainTextResponse("config_error", status_code=500)
    if FAKE_GITHUB:
        dc = secrets.token_urlsafe(24)
        with LOCK:
            DEVICE_PENDING[dc] = {"t": time.time(), "interval": 1}
        return {
            "device_code": dc,
            "user_code": "FAKE-CODE",
            "verification_uri": f"{BASE_URL}/fake/device",
            "interval": 1,
            "expires_in": DEVICE_PENDING_TTL,
        }
    try:
        r = requests.post(
            DEVICE_CODE_URL,
            data={"client_id": CLIENT_ID, "scope": DEVICE_SCOPE},
            headers={"Accept": "application/json"},
            timeout=API_TIMEOUT,
        )
    except requests.RequestException as e:
        log.warning("device/code transport error: %s", e)
        return PlainTextResponse("upstream_error", status_code=502)
    return r.json()


@app.post("/device/token")
async def device_token(request: Request):
    """Device Flow 轮询. pending/slow_down 透传; 成功附带 org 校验 login."""
    if FAKE_GITHUB:
        dc = ""
        ctype = request.headers.get("content-type", "")
        try:
            if "application/json" in ctype:
                dc = str((await request.json()).get("device_code", ""))
            else:
                dc = str((await request.form()).get("device_code", ""))
        except Exception:
            pass
        with LOCK:
            rec = DEVICE_PENDING.get(dc)
            if rec is None or time.time() - rec["t"] > DEVICE_PENDING_TTL:
                return {"error": "expired_token"}
            if not rec.get("granted"):
                # 首次轮询即视为授权完成 (fake 模式无真实浏览器腿)
                rec["granted"] = True
                return {"error": "authorization_pending"}
            del DEVICE_PENDING[dc]
        if not FAKE_MEMBER:
            return {"error": "access_denied"}
        return {"access_token": f"fake-token-{dc[:8]}", "login": FAKE_LOGIN,
                "token_type": "bearer", "scope": DEVICE_SCOPE}

    ctype = request.headers.get("content-type", "")
    try:
        if "application/json" in ctype:
            dc = str((await request.json()).get("device_code", ""))
        else:
            dc = str((await request.form()).get("device_code", ""))
    except Exception:
        return {"error": "invalid_request"}
    try:
        r = requests.post(
            GITHUB_TOKEN_URL,
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "device_code": dc,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
            headers={"Accept": "application/json"},
            timeout=API_TIMEOUT,
        )
    except requests.RequestException as e:
        log.warning("device/token transport error: %s", e)
        return PlainTextResponse("upstream_error", status_code=502)
    data = r.json()
    token = data.get("access_token")
    if not token:
        return data  # authorization_pending / slow_down / expired_token 透传
    login = _github_login_from_token(token)
    if not login or not _authorized_member(login):
        log.warning("device/token: user not authorized (login=%s)", login)
        return {"error": "access_denied"}
    data["login"] = login
    return data


@app.get("/healthz")
def healthz():
    return PlainTextResponse("ok")
