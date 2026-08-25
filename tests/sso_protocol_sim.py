#!/usr/bin/env python3
"""AnyConnect sso-v2 protocol simulator (stdlib + cryptography for STRAP).

Drives a live patched ocserv over TLS exactly like the official client:

  1. POST /+webvpn+/index.html  type=init, capabilities: single-sign-on-v2
     -> expect auth-request XML with <sso-v2-login> (not a username form)
  2. embedded-browser leg (separate connections, cookie jar, manual
     redirects) through the ocserv /+CSCOE+/sso/ proxy
     -> expect final URL .../+CSCOE+/sso/done and acSamlv2Token cookie
  3. POST type=auth-reply with <sso-token> on the SAME TLS connection
     -> expect type="complete" (success) + webvpn session cookie
  4. negative: init without capabilities -> username/password form
  5. negative: malformed sso-token -> fallback password form (not complete)

SSO_STRAP=1 emulates the Secure Client 5.x external-browser (STRAP) path:
init carries X-AnyConnect-STRAP-*-Pubkey headers; the form must contain
<sso-v2-browser-mode>external; the browser leg ends in a redirect to
http://localhost:29786/api/sso/<blob>, which is decrypted with the client
private key (ECDH P-256 + HKDF(AC_ECIES) + AES-256-GCM) to recover the
token. Env: SSO_HOST (127.0.0.1), SSO_PORT (9443). Exit 0 iff all pass.
"""
import base64
import http.client
import os
import re
import ssl
import struct
import sys
import urllib.parse

HOST = os.environ.get("SSO_HOST", "127.0.0.1")
PORT = int(os.environ.get("SSO_PORT", "9443"))
BASE = f"https://{HOST}:{PORT}"
STRAP = os.environ.get("SSO_STRAP") == "1"
# CLI 路径 (P1): openconnect/vpn-cli 走 username/password 表单, password 为
# GitHub access_token (Device Flow 产物). CLI_TOKEN 非空即切该路径.
CLI_TOKEN = os.environ.get("CLI_TOKEN", "")

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

UA = "Cisco AnyConnect VPN Agent for Windows 4.10.06079"
TOKEN_RE = re.compile(r"^[a-z2-7]+[0-9a-f]{26}[0-9a-z]{32}$")

INIT_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="init" aggregate-auth-version="2">
<version who="vpn">v4.10.06079</version>
<device-id>win</device-id>
<group-access>{base}/+webvpn+/index.html</group-access>{caps}
</config-auth>"""

CAPS_SSO = "\n<capabilities>\n<auth-method>single-sign-on-v2</auth-method>\n</capabilities>"

AUTH_REPLY = """<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
<version who="vpn">v4.10.06079</version>
<session-token></session-token><session-id></session-id>
<auth id="main">
<opaque is-for="sg"><tunnel-group>standard-group</tunnel-group></opaque>
<sso-token>{token}</sso-token>
</auth>
</config-auth>"""

AUTH_REPLY_FORM = """<?xml version="1.0" encoding="UTF-8"?>
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
<version who="vpn">v4.10.06079</version>
<session-token></session-token><session-id></session-id>
<auth id="main">
<opaque is-for="sg"><tunnel-group>standard-group</tunnel-group></opaque>
<username>{username}</username>
<password>{password}</password>
</auth>
</config-auth>"""


class Conn:
    """Keep-alive HTTPS connection (the VPN control channel)."""

    def __init__(self):
        self.c = http.client.HTTPSConnection(HOST, PORT, context=CTX, timeout=30)

    def post_xml(self, url, body, extra_headers=None):
        headers = {
            "User-Agent": UA,
            "Content-Type": "text/xml",
            "X-Transcend-Version": "1",
            "X-Aggregate-Auth": "1",
            "Connection": "keep-alive",
        }
        headers.update(extra_headers or {})
        self.c.request("POST", url, body=body.encode(), headers=headers)
        r = self.c.getresponse()
        headers = {}
        for k, v in r.getheaders():
            headers.setdefault(k, []).append(v)
        flat = {}
        for k, v in headers.items():
            flat[k] = v if len(v) > 1 else v[0]
        return (r.status, flat, r.read().decode("utf-8", "replace"),
                r.msg.get_all("Set-Cookie") or [])

    def close(self):
        self.c.close()


# --- STRAP (external-browser) client emulation -------------------------------

STRAP_KEYS = None


def strap_init():
    global STRAP_KEYS
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    b64 = base64.b64encode(spki).decode()
    STRAP_KEYS = {"priv": priv, "b64": b64, "b64url": b64.replace("+", "-").replace("/", "_").rstrip("=")}
    return {
        "X-AnyConnect-STRAP-Pubkey": b64,
        "X-AnyConnect-STRAP-DH-Pubkey": b64,
    }


def strap_decrypt(location):
    """Decrypt the token from a localhost:29786 redirect Location."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    assert location.startswith("http://localhost:29786/api/sso/"), location
    path, _, query = location[len("http://localhost:29786"):].partition("?")
    blob_b64 = urllib.parse.unquote(path[len("/api/sso/"):])
    blob = base64.b64decode(blob_b64)

    assert blob[:2] == b"\x00\x01"
    pos, tlv = 2, {}
    while pos < len(blob):
        tag, ln = struct.unpack(">HH", blob[pos:pos + 4])
        tlv[tag] = blob[pos + 4:pos + 4 + ln]
        pos += 4 + ln
    assert set(tlv) == {1, 2, 3, 4} and len(tlv[2]) == 12 and len(tlv[4]) == 12

    server_pub = serialization.load_der_public_key(tlv[1])
    shared = STRAP_KEYS["priv"].exchange(ec.ECDH(), server_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"AC_ECIES").derive(shared)
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    dec = Cipher(algorithms.AES(key),
                 modes.GCM(tlv[4], tlv[2], min_tag_length=12)).decryptor()
    return (dec.update(tlv[3]) + dec.finalize()).decode()


def browser_flow(start_url, strap=False):
    """Embedded-browser simulation: manual redirects + cookie jar.

    strap=True: stop at the localhost:29786 redirect and return its
    Location (the STRAP token handoff) instead of a done page."""
    if os.environ.get("SSO_DEBUG"):
        print(f"  [dbg] browser: {start_url}", file=sys.stderr)
    cookies = {}
    url = start_url
    for _ in range(10):
        u = urllib.parse.urlparse(url)
        conn = http.client.HTTPSConnection(
            u.hostname, u.port or PORT, context=CTX, timeout=30)
        conn.request(
            "GET", u.path + (("?" + u.query) if u.query else ""),
            headers={
                "User-Agent": "Mozilla/5.0 (simulated-embedded-browser)",
                "Cookie": "; ".join(f"{k}={v}" for k, v in cookies.items()),
                "Connection": "close",
            },
        )
        r = conn.getresponse()
        body = r.read()
        set_cookies = r.msg.get_all("Set-Cookie") or []
        if os.environ.get("SSO_DEBUG"):
            print(f"  [dbg] {r.status} {url} set-cookie={set_cookies} loc={r.getheader('Location')}", file=sys.stderr)
        for sc in set_cookies:
            kv = sc.split(";", 1)[0]
            attrs = sc.split(";")
            k, _, v = kv.partition("=")
            v = v.strip().strip('"')
            if "max-age=0" in sc.lower():
                cookies.pop(k.strip(), None)
                continue
            if v:
                cookies[k.strip()] = v
        loc = r.getheader("Location")
        conn.close()
        if r.status in (301, 302, 303, 307) and loc:
            url = urllib.parse.urljoin(url, loc)
            if strap and url.startswith("http://localhost:29786/"):
                return r.status, url, cookies, ""
            continue
        return r.status, url, cookies, body.decode("utf-8", "replace")
    raise RuntimeError("too many redirects in browser leg")


def cli_flow():
    """CLI (openconnect/vpn-cli) path: username/password form, password is a
    GitHub access_token from Device Flow. init carries NO sso capability."""
    failures = []

    def check(name, cond, detail=""):
        print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if not cond else ""))
        if not cond:
            failures.append(name)

    c = Conn()
    st, _, body, _sc = c.post_xml("/+webvpn+/index.html",
                                  INIT_TMPL.format(base=BASE, caps=""))
    check("c1 no-capability -> username/password form",
          st == 200 and 'name="username"' in body and "<sso-v2-login>" not in body,
          body[:300])
    st, hdrs, body, set_cookies = c.post_xml(
        "/+webvpn+/index.html",
        AUTH_REPLY_FORM.format(username="cli-user", password=CLI_TOKEN))
    check("c2 auth-reply -> complete (access_token introspected)",
          st == 200 and 'type="complete"' in body and 'id="success"' in body,
          f"status={st} body={body[:300]}")
    check("c2b webvpn session cookie set",
          any(sc.startswith("webvpn=") for sc in set_cookies), str(set_cookies))
    c.close()
    summary(failures)


def main():
    failures = []

    def check(name, cond, detail=""):
        print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f" :: {detail}" if not cond else ""))
        if not cond:
            failures.append(name)

    # --- 1. init with sso capability -> sso form -------------------------
    extra = strap_init() if STRAP else None
    c = Conn()
    st, hdrs, body, _sc = c.post_xml("/+webvpn+/index.html",
                                     INIT_TMPL.format(base=BASE, caps=CAPS_SSO),
                                     extra_headers=extra)
    m = re.search(r"<sso-v2-login>([^<]+)</sso-v2-login>", body)
    check("1 init->sso form (200 + sso-v2-login)", st == 200 and m is not None, body[:300])
    if not m:
        c.close()
        summary(failures)
    # XML text content arrives with entities escaped (&amp; for &dh=)
    sso_url = m.group(1).replace("&amp;", "&")
    check("1b form has token-cookie-name acSamlv2Token",
          "acSamlv2Token" in body and 'type="sso"' in body)
    if STRAP:
        check("1c strap: browser-mode external + dh in URL",
              "<sso-v2-browser-mode>external" in body
              and f"dh={STRAP_KEYS['b64url']}" in sso_url
              and "&amp;dh=" in m.group(1), sso_url)
    else:
        check("1c embedded: no browser-mode element",
              "<sso-v2-browser-mode" not in body, body[:300])

    # --- 2. browser leg ---------------------------------------------------
    st, final_url, cookies, _done = browser_flow(sso_url, strap=STRAP)
    if STRAP:
        check("2 strap: browser leg ends at localhost:29786",
              final_url.startswith("http://localhost:29786/api/sso/"), final_url)
        try:
            token = strap_decrypt(final_url)
        except Exception as e:
            token = ""
            check("2b strap: blob decrypts", False, repr(e))
        check("2b strap: token charset/length", bool(TOKEN_RE.match(token)), token)
        check("2c strap: return param points to done page",
              "return=" in final_url and "%2Fsso%2Fdone" in final_url,
              final_url)
    else:
        check("2 browser leg reaches done page",
              st == 200 and final_url.endswith("/+CSCOE+/sso/done"),
              f"status={st} url={final_url}")
        token = cookies.get("acSamlv2Token", "")
        check("2b token cookie charset/length", bool(TOKEN_RE.match(token)), token)
        check("2c no error cookie", "acSamlv2Error" not in cookies, str(cookies.keys()))

    # --- 3. auth-reply with sso-token on same connection ------------------
    # ocserv 1.5.0 delivers the session token via the webvpn= Set-Cookie
    # (the complete XML carries <auth id="success">, not <session-token>).
    st, hdrs, body, set_cookies = c.post_xml("/+webvpn+/index.html",
                                             AUTH_REPLY.format(token=token))
    check("3 auth-reply -> complete (success auth)",
          st == 200 and 'type="complete"' in body and 'id="success"' in body,
          f"status={st} body={body[:300]}")
    check("3b webvpn session cookie set", any(
        sc.startswith("webvpn=") for sc in set_cookies), str(set_cookies))
    c.close()

    # --- 4. negative: no capability -> username form ----------------------
    c2 = Conn()
    st, _, body, _sc = c2.post_xml("/+webvpn+/index.html",
                                   INIT_TMPL.format(base=BASE, caps=""))
    check("4 no-capability -> username/password form",
          st == 200 and 'name="username"' in body and "<sso-v2-login>" not in body,
          body[:300])
    c2.close()

    # --- 5. negative: malformed sso-token -> fallback password form -------
    c3 = Conn()
    st, _, body, _sc = c3.post_xml("/+webvpn+/index.html",
                                   INIT_TMPL.format(base=BASE, caps=CAPS_SSO))
    check("5a sso form served again", "<sso-v2-login>" in body)
    st, _, body, _sc = c3.post_xml("/+webvpn+/index.html", AUTH_REPLY.format(token="ab"))
    check("5b malformed token -> fallback form (not complete)",
          'type="complete"' not in body and 'name="username"' in body, body[:300])
    c3.close()

    summary(failures)


def summary(failures):
    print("=" * 40)
    if failures:
        print(f"FAILED: {len(failures)}: {failures}")
        sys.exit(1)
    print("ALL PASS")
    sys.exit(0)


if __name__ == "__main__":
    cli_flow() if CLI_TOKEN else main()
