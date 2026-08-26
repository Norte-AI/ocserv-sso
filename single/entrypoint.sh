#!/bin/sh
# Single-container entrypoint (spec §3.4).
# Runs under tini (PID1). Starts the portal on loopback, then execs ocserv
# in the foreground as the main process. If ocserv exits, the script exits
# and tini tears the container down (portal included) — docker restart
# policy brings the pair back together.
#
# Portal bind/port are env-overridable (SSO_BIND/SSO_PORT) for integration
# tests; production keeps the loopback default so only ocserv's TLS leg is
# public.
set -eu

SSO_BIND="${SSO_BIND:-127.0.0.1}"
SSO_PORT="${SSO_PORT:-8443}"

# Optional forward HTTPS proxy (e.g. gost on a host outside a region that
# blocks github.com). Mounted as a read-only secret file so the proxy URL
# (which contains credentials) never lands in docker inspect Config.Env.
# requests/urllib3 honor HTTPS_PROXY for the portal's server-side calls to
# github.com (Device Flow + token exchange); api.github.com stays direct
# via NO_PROXY.
if [ -f /run/secrets/https_proxy ]; then
    export HTTPS_PROXY="$(cat /run/secrets/https_proxy)"
fi

cd /opt/vpn-portal
uvicorn app:app --host "$SSO_BIND" --port "$SSO_PORT" --no-access-log &
PORTAL_PID=$!

# Wait for the portal to accept connections before ocserv starts routing
# auth to it; otherwise early logins hit connection-refused and bounce.
i=0
while [ "$i" -lt 30 ]; do
    if curl -fsS "http://${SSO_BIND}:${SSO_PORT}/healthz" >/dev/null 2>&1; then
        break
    fi
    i=$((i + 1))
    sleep 0.2
done
if [ "$i" -ge 30 ]; then
    echo "entrypoint: portal did not become healthy on ${SSO_BIND}:${SSO_PORT}" >&2
    kill "$PORTAL_PID" 2>/dev/null || true
    exit 1
fi

# --log-stderr long form required (Correction 9): short -e is broken in
# ocserv 1.5.0 getopt.
exec ocserv -f --log-stderr -c /usr/local/etc/ocserv/ocserv.conf
