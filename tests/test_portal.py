"""vpn-portal unit tests (fake-GitHub mode, no network).

Module env is set before importing portal/app.py (it reads env at import).
The TestClient host is "testclient"; it is added to the allowed /verify
hosts via SSO_VERIFY_ALLOWED_HOSTS in the test env only — the production
default stays 127.0.0.1,::1.
"""
import base64
import importlib.util
import os
import re
import sys
import tempfile
from http.cookies import SimpleCookie
from pathlib import Path

import pytest

PORTAL_DIR = Path(__file__).resolve().parent.parent / "portal"

_secrets = Path(tempfile.mkdtemp(prefix="portal_test_secrets_"))
(_secrets / "github_oauth_client_id").write_text("test-client-id")
(_secrets / "github_oauth_client_secret").write_text("test-secret")
(_secrets / "verifier_token").write_text("ghp_test_verifier")
(_secrets / "sso_hmac_key").write_text("ab" * 32)

os.environ.update(
    SSO_SECRETS_DIR=str(_secrets),
    SSO_BASE_URL="https://vpn.test",
    SSO_FAKE_GITHUB="1",
    SSO_FAKE_LOGIN="octo-cat",
    SSO_FAKE_MEMBER="1",
    SSO_VERIFY_ALLOWED_HOSTS="127.0.0.1,::1,testclient",
    SSO_GITHUB_PROXY_MONITOR="0",
)

_spec = importlib.util.spec_from_file_location("vpn_portal_app", PORTAL_DIR / "app.py")
portal = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(portal)

from fastapi.testclient import TestClient  # noqa: E402

TOKEN_RE = re.compile(r"^[a-z2-7]+[0-9a-f]{26}[0-9a-z]{32}$")
SID = "ab" * 13  # 26 hex chars, matches ocserv patch sso sid format


@pytest.fixture
def client():
    return TestClient(portal.app, follow_redirects=False)


def _cookiejar_of(resp):
    jar = {}
    for raw in resp.headers.get_list("set-cookie"):
        c = SimpleCookie()
        c.load(raw)
        for k, v in c.items():
            jar[k] = v.value
    return jar


def _fake_flow(client, sid=SID):
    """start -> fake authorize -> callback; returns final redirect response."""
    r1 = client.get(f"{portal.PREFIX}/start", params={"sid": sid})
    assert r1.status_code == 303
    assert "/fake/authorize?state=" in r1.headers["location"]

    state = r1.headers["location"].split("state=")[1]
    r2 = client.get(r1.headers["location"])
    assert r2.status_code == 303
    assert "/callback?code=fake-code" in r2.headers["location"]

    return client.get(r2.headers["location"])


def _split_token(token):
    ticket = token[-32:]
    sid = token[-58:-32]
    user = token[:-58]
    login = base64.b32decode(user.upper() + "=" * (-len(user) % 8)).decode()
    return login, sid, ticket


# --- start ---

def test_start_invalid_sid(client):
    r = client.get(f"{portal.PREFIX}/start", params={"sid": "short"})
    assert r.status_code == 303
    jar = _cookiejar_of(r)
    assert jar.get("acSamlv2Error") == "invalid_sid"


def test_start_valid_sid_fake_mode(client):
    r = client.get(f"{portal.PREFIX}/start", params={"sid": SID})
    assert r.status_code == 303
    assert "/fake/authorize?state=" in r.headers["location"]


# --- full fake flow -> token cookie -> verify ---

def test_fake_flow_issues_and_verifies_token(client):
    r3 = _fake_flow(client)
    assert r3.status_code == 303
    jar = _cookiejar_of(r3)
    token = jar.get("acSamlv2Token")
    assert token and TOKEN_RE.match(token), token

    login, sid, ticket = _split_token(token)
    assert login == "octo-cat"
    assert sid == SID

    v = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v.status_code == 200
    assert v.headers.get("X-SSO-User") == "octo-cat"

    # single use
    v2 = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v2.status_code == 403


def test_verify_wrong_ticket(client):
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, _ = _split_token(token)
    v = client.get("/verify", params={"sid": sid, "ticket": "c" * 32})
    assert v.status_code == 403


def test_verify_unknown_sid(client):
    v = client.get("/verify", params={"sid": SID, "ticket": "c" * 32})
    assert v.status_code == 403


def test_verify_expired_ticket(client):
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, ticket = _split_token(token)
    with portal.LOCK:
        portal.ISSUED[sid]["t"] -= portal.TICKET_TTL + 1
    v = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v.status_code == 403


def test_verify_bad_params(client):
    for sid, ticket in [("", "c" * 32), (SID, "short"), (SID, "ABC" * 10)]:
        r = client.get("/verify", params={"sid": sid, "ticket": ticket})
        assert r.status_code == 403


def test_verify_wildcard_allowed_hosts(monkeypatch, client):
    """Integration topology: RADIUS arrives from a non-loopback source IP."""
    monkeypatch.setattr(portal, "VERIFY_ALLOWED_HOSTS", {"*"})
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, ticket = _split_token(token)
    v = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v.status_code == 200


def test_verify_host_not_allowed(monkeypatch, client):
    monkeypatch.setattr(portal, "VERIFY_ALLOWED_HOSTS", {"10.0.0.1"})
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, ticket = _split_token(token)
    v = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v.status_code == 403
    assert v.text == "forbidden"


# --- callback edge cases ---

def test_callback_unknown_state(client):
    r = client.get(f"{portal.PREFIX}/callback",
                   params={"code": "x", "state": "no-such-state"})
    assert r.status_code == 303
    assert _cookiejar_of(r).get("acSamlv2Error") == "invalid_state"


def test_callback_denied(client):
    r = client.get(f"{portal.PREFIX}/callback", params={"error": "access_denied"})
    assert r.status_code == 303
    assert _cookiejar_of(r).get("acSamlv2Error") == "denied"


def test_callback_state_single_use(client):
    r1 = client.get(f"{portal.PREFIX}/start", params={"sid": SID})
    state = r1.headers["location"].split("state=")[1]
    url = f"{portal.PREFIX}/callback?code=fake-code&state={state}"
    assert client.get(url).status_code == 303
    # replay of the same state
    r2 = client.get(url)
    assert _cookiejar_of(r2).get("acSamlv2Error") == "invalid_state"


def test_callback_non_member(monkeypatch, client):
    monkeypatch.setattr(portal, "FAKE_MEMBER", False)
    r3 = _fake_flow(client)
    assert r3.status_code == 303
    assert _cookiejar_of(r3).get("acSamlv2Error") == "not_member"
    # no ticket issued -> verify fails
    v = client.get("/verify", params={"sid": SID, "ticket": "c" * 32})
    assert v.status_code == 403


def test_state_hmac_tamper(client):
    r1 = client.get(f"{portal.PREFIX}/start", params={"sid": SID})
    loc = r1.headers["location"]
    state = loc.split("state=")[1]
    tampered = ("A" if state[0] != "A" else "B") + state[1:]
    r = client.get(f"{portal.PREFIX}/callback",
                   params={"code": "fake-code", "state": tampered})
    # tampered state is not in PENDING -> rejected
    assert _cookiejar_of(r).get("acSamlv2Error") == "invalid_state"


# --- done / healthz ---

def test_strap_flow_roundtrip(client):
    """STRAP external-browser mode: dh param -> localhost:29786 redirect
    with ECIES blob that decrypts back to the same token."""
    import base64 as b64mod
    import struct as structmod
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    dh = b64mod.b64encode(spki).decode().replace("+", "-").replace("/", "_").rstrip("=")

    r1 = client.get(f"{portal.PREFIX}/start", params={"sid": SID, "dh": dh})
    assert r1.status_code == 303
    state = r1.headers["location"].split("state=")[1]
    r2 = client.get(r1.headers["location"])
    r3 = client.get(r2.headers["location"])  # callback
    assert r3.status_code == 303
    loc = r3.headers["location"]
    assert loc.startswith("http://localhost:29786/api/sso/"), loc
    assert "return=" in loc

    import urllib.parse as up
    blob = b64mod.b64decode(up.unquote(loc.split("/api/sso/", 1)[1].split("?")[0]))
    assert blob[:2] == b"\x00\x01"
    pos, tlv = 2, {}
    while pos < len(blob):
        tag, ln = structmod.unpack(">HH", blob[pos:pos + 4])
        tlv[tag] = blob[pos + 4:pos + 4 + ln]
        pos += 4 + ln
    assert set(tlv) == {1, 2, 3, 4}
    shared = priv.exchange(ec.ECDH(), serialization.load_der_public_key(tlv[1]))
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"AC_ECIES").derive(shared)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key),
                 modes.GCM(tlv[4], tlv[2], min_tag_length=12)).decryptor()
    token = (dec.update(tlv[3]) + dec.finalize()).decode()
    assert TOKEN_RE.match(token)

    _, sid, ticket = _split_token(token)
    assert sid == SID
    v = client.get("/verify", params={"sid": sid, "ticket": ticket})
    assert v.status_code == 200


def test_authorized_member_multi_org(monkeypatch):
    """任一 org active 即放行; 全部 404 拒绝."""
    from unittest.mock import patch

    monkeypatch.setattr(portal, "GITHUB_ORGS", ["org-a", "org-b"])
    monkeypatch.setattr(portal._AUTHZ, "orgs", ["org-a", "org-b"])

    class R:
        def __init__(self, code):
            self.status_code = code

        def json(self):
            return {"state": "active"}

    with patch("requests.get", side_effect=lambda url, **kw: R(200 if "org-b" in url else 404)):
        assert portal._authorized_member("octo-cat") is True

    with portal.LOCK:
        portal.MEMBER_CACHE.clear()
    with patch("requests.get", side_effect=lambda url, **kw: R(404)):
        assert portal._authorized_member("octo-cat") is False


# --- /introspect (PAM pam_exec helper; RFC 7662-shaped) ---

def test_introspect_active_json(client):
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    login, sid, ticket = _split_token(token)
    r = client.post("/introspect", json={"token": f"{sid}.{ticket}"})
    assert r.status_code == 200
    assert r.json() == {"active": True, "username": login}
    # single use
    r2 = client.post("/introspect", json={"token": f"{sid}.{ticket}"})
    assert r2.status_code == 200 and r2.json() == {"active": False}


def test_introspect_wrong_ticket(client):
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, _ = _split_token(token)
    r = client.post("/introspect", json={"token": f"{sid}.{'c' * 32}"})
    assert r.json() == {"active": False}


def test_introspect_expired(client):
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, ticket = _split_token(token)
    with portal.LOCK:
        portal.ISSUED[sid]["t"] -= portal.TICKET_TTL + 1
    r = client.post("/introspect", json={"token": f"{sid}.{ticket}"})
    assert r.json() == {"active": False}


def test_introspect_malformed(client):
    for tok in ["", "a b", "short", "x" * 300]:
        r = client.post("/introspect", json={"token": tok})
        assert r.status_code == 200 and r.json() == {"active": False}


def test_introspect_host_not_allowed(monkeypatch, client):
    monkeypatch.setattr(portal, "VERIFY_ALLOWED_HOSTS", {"10.0.0.1"})
    r3 = _fake_flow(client)
    token = _cookiejar_of(r3)["acSamlv2Token"]
    _, sid, ticket = _split_token(token)
    r = client.post("/introspect", json={"token": f"{sid}.{ticket}"})
    assert r.status_code == 200 and r.json() == {"active": False}


def test_introspect_github_token_active(client):
    """非 ticket 形态 -> GitHub access_token 分支: fake 模式直接放行."""
    r = client.post("/introspect", json={"token": "ghu_anything-not-a-ticket"})
    assert r.status_code == 200
    assert r.json() == {"active": True, "username": "octo-cat"}


def test_introspect_github_token_non_member(monkeypatch, client):
    monkeypatch.setattr(portal, "FAKE_MEMBER", False)
    r = client.post("/introspect", json={"token": "ghu_anything"})
    assert r.json() == {"active": False}


def test_introspect_github_token_invalid_shape(client):
    for tok in ["", " ", "a b c", "x" * 300]:
        r = client.post("/introspect", json={"token": tok})
        assert r.json() == {"active": False}


# --- Device Flow ---

def test_device_flow_fake_roundtrip(client):
    r = client.post("/device/code")
    assert r.status_code == 200
    d = r.json()
    assert d["user_code"] == "FAKE-CODE"
    assert "/fake/device" in d["verification_uri"]

    # 首次轮询: pending
    t1 = client.post("/device/token", json={"device_code": d["device_code"]})
    assert t1.json() == {"error": "authorization_pending"}
    # 二次轮询: 授权完成
    t2 = client.post("/device/token", json={"device_code": d["device_code"]})
    assert t2.status_code == 200
    tok = t2.json()
    assert tok["access_token"].startswith("fake-token-")
    assert tok["login"] == "octo-cat"
    # access_token 随后可直接走 /introspect CLI 路径
    v = client.post("/introspect", json={"token": tok["access_token"]})
    assert v.json() == {"active": True, "username": "octo-cat"}


def test_device_token_unknown_code(client):
    r = client.post("/device/token", json={"device_code": "no-such-code"})
    assert r.json() == {"error": "expired_token"}


def test_device_token_non_member_denied(monkeypatch, client):
    monkeypatch.setattr(portal, "FAKE_MEMBER", False)
    d = client.post("/device/code").json()
    client.post("/device/token", json={"device_code": d["device_code"]})
    t2 = client.post("/device/token", json={"device_code": d["device_code"]})
    assert t2.json() == {"error": "access_denied"}


def test_done_page(client):
    r = client.get(f"{portal.PREFIX}/done")
    assert r.status_code == 200
    assert "acSamlv2Token" in r.text


def test_github_proxy_monitor_success(monkeypatch):
    class Response:
        status_code = 404

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.example")
    monkeypatch.setenv("SSO_GITHUB_PROXY_MONITOR_URL", "https://github-proxy.test")
    monkeypatch.setattr(
        portal.requests, "get", lambda *args, **kwargs: Response()
    )
    result = portal._github_proxy_monitor_once()
    assert result["configured"] is True
    assert result["status"] == 404
    assert "latency_ms" in result


def test_github_proxy_monitor_failure(monkeypatch):
    def get(*args, **kwargs):
        raise portal.requests.ConnectionError("unreachable")

    monkeypatch.delenv("HTTPS_PROXY", raising=False)
    monkeypatch.setattr(portal.requests, "get", get)
    result = portal._github_proxy_monitor_once()
    assert result == {
        "configured": False,
        "error": "ConnectionError",
        "latency_ms": result["latency_ms"],
    }


def test_healthz(client):
    assert client.get("/healthz").text == "ok"
