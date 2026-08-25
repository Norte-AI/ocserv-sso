#!/usr/bin/env python3
"""pam_exec helper: validate the VPN credential against the portal.

ocserv runs with auth="pam[service=ocserv]"; this script is the PAM
`auth` stack (see pam/ocserv). For every authentication attempt libpam
spawns it with:

  stdin:   the password, NUL-terminated (pam_exec expose_authtok)
  env:     PAM_USER = the username ocserv resolved (sso patch:
           base32 of the submitted ticket)

The password is "sid.ticket" (the patch splits the composite sso-token
b32(login)||sid||ticket that AnyConnect submits). We POST it as RFC
7662-style JSON introspection to the portal (JSON: no python-multipart
dependency); the portal checks single-use / TTL / sid binding and answers
{"active":true,"username":login}.

Exit status (any non-zero = PAM auth failure):
  0  portal answered active=true
  1  active=false / malformed reply / transport or timeout error

Security: the credential never appears in argv or the environment.
The URL defaults to the loopback portal (single-container / host-network
layout). Precedence: argv[1] > PORTAL_INTROSPECT_URL env > loopback
default. argv[1] is the reliable channel under pam_exec: libpam spawns
the helper with the PAM environment only (pam_getenvlist), so a URL
injected via the container's environment never reaches us — but
pam_exec passes trailing module args from /etc/pam.d/ocserv through
as argv.
"""
import json
import os
import sys
import urllib.request

if len(sys.argv) > 1:
    INTROSPECT_URL = sys.argv[1]
else:
    INTROSPECT_URL = os.environ.get(
        "PORTAL_INTROSPECT_URL", "http://127.0.0.1:8443/introspect")
# Generous ceiling: ocserv auth-timeout is 300s and a slow GitHub API leg
# (P1 token introspection) may take seconds. The helper holds one PAM
# conversation, not a shared resource, so a long tail only delays a reject.
TIMEOUT = float(os.environ.get("PORTAL_INTROSPECT_TIMEOUT", "120"))


def main() -> int:
    raw = sys.stdin.buffer.read().split(b"\0", 1)[0]
    try:
        password = raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return 1

    body = json.dumps({"token": password}).encode()
    req = urllib.request.Request(
        INTROSPECT_URL, data=body,
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8", "strict"))
    except Exception:
        return 1

    if data.get("active") is True and data.get("username"):
        user = os.environ.get("PAM_USER", "?")
        print(f"ocserv-pam: active user={user} as {data['username']}",
              file=sys.stderr)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
