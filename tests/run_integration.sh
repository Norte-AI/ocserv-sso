#!/usr/bin/env bash
# SSO integration test: single-container ocserv-sso (ocserv + vpn-portal in
# one image, portal on loopback). Runs on macOS / any docker host.
#
# Flow under test (fake-GitHub mode, no external network):
#   simulator -> ocserv(443/tcp TLS, sso patch) -> PAM pam_exec helper
#   -> portal POST /introspect (127.0.0.1:8443, same container) -> complete XML
#   browser leg: simulator -> ocserv /+CSCOE+/sso/* proxy -> 127.0.0.1:8443
#
# Usage: tests/run_integration.sh [port]   (default 9443)
set -uo pipefail
# 不启用 set -e: 任一腿失败也要打日志再退出.

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${1:-9443}"
NET=ocserv-sso-int-net
# WORK 必须位于 Docker Desktop 文件共享路径内 (/tmp 不共享, 挂载会变成空目录)
mkdir -p "$HOME/.cache"
WORK="$(mktemp -d "$HOME/.cache/sso-int-XXXXXX")"
BASE="https://127.0.0.1:${PORT}"

cleanup() {
  docker rm -f ocserv-sso >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

echo "=== integration workdir: $WORK ==="
mkdir -p "$WORK/certs" "$WORK/secrets"

# --- self-signed cert ---
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" \
  -subj "/CN=127.0.0.1" -addext "subjectAltName=IP:127.0.0.1,DNS:localhost" 2>/dev/null

# --- dummy secrets ---
echo "ghp_int_verifier"       > "$WORK/secrets/verifier_token"
echo "dummy-client-id"        > "$WORK/secrets/github_oauth_client_id"
echo "dummy-client-secret"    > "$WORK/secrets/github_oauth_client_secret"
openssl rand -hex 32          > "$WORK/secrets/sso_hmac_key"
openssl rand -hex 16          > "$WORK/secrets/totp_enc_key"

# --- ocserv config (auth=pam; helper posts to the loopback portal) ---
cat > "$WORK/ocserv.conf" <<EOF
tcp-port = ${PORT}
udp-port = ${PORT}
server-cert = /etc/test-certs/cert.pem
server-key = /etc/test-certs/key.pem
auth = "pam[service=ocserv]"
ipv4-network = 10.99.0.0
ipv4-netmask = 255.255.255.0
device = vpns
dns = 1.1.1.1
max-clients = 16
max-same-clients = 2
isolate-workers = true
auth-timeout = 300
use-occtl = true
socket-file = /var/run/occtl.socket
log-level = 2
EOF

dump_fail_logs() {
  echo "=== single-container logs ==="; docker logs ocserv-sso 2>&1 | tail -60 || true
}

# Single image build (repo-root context; ocserv/ + portal/ + single/).
echo "=== build single image ==="
docker build -f "$HERE/single/Dockerfile" -t ocserv-sso \
  --build-arg APT_MIRROR=mirrors.aliyun.com "$HERE" \
  || { echo "single build FAILED"; exit 1; }
echo "single image ok"

docker network create "$NET" >/dev/null

echo "=== start single container (ocserv + portal) ==="
# Portal env (SSO_*) and ocserv env (OCSERV_SSO_*) share the container.
# OCSERV_SSO_PROXY stays at its compiled-in default 127.0.0.1:8443 (loopback).
# The helper's default URL is the loopback portal; no pam.d override needed.
docker run -d --name ocserv-sso --network "$NET" \
  -e SSO_BASE_URL="${BASE}" \
  -e SSO_BIND=127.0.0.1 -e SSO_PORT=8443 \
  -e SSO_FAKE_GITHUB=1 -e SSO_FAKE_LOGIN=octocat -e SSO_FAKE_MEMBER=1 \
  -e SSO_VERIFY_ALLOWED_HOSTS="*" \
  -e SSO_SECRETS_DIR=/run/secrets \
  -e OCSERV_SSO_ENABLE=1 \
  -e OCSERV_SSO_BASE_URL="${BASE}" \
  -p "127.0.0.1:${PORT}:${PORT}" -p "127.0.0.1:${PORT}:${PORT}/udp" \
  --cap-add NET_ADMIN \
  -v "$WORK/ocserv.conf:/usr/local/etc/ocserv/ocserv.conf:ro" \
  -v "$WORK/certs:/etc/test-certs:ro" \
  -v "$WORK/secrets:/run/secrets:ro" \
  ocserv-sso >/dev/null || { echo "single run failed"; exit 1; }

echo "=== wait for services ==="
ok=0
for i in $(seq 1 40); do
  if docker logs ocserv-sso 2>&1 | grep -q "listening\|worker-sockets\|initialized" \
     && nc -z 127.0.0.1 "$PORT" 2>/dev/null; then ok=1; break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then
  echo "single container did not come up"
  docker logs ocserv-sso
  exit 1
fi

sleep 2
state="$(docker inspect -f '{{.State.Status}}' ocserv-sso)"
if [ "$state" != "running" ]; then
  echo "ocserv-sso not running (state=$state)"
  docker logs ocserv-sso
  exit 1
fi

PY="${PYTHON:-python3}"
echo "=== run protocol simulator (embedded mode) ==="
SSO_DEBUG="${SSO_DEBUG:-1}" SSO_HOST=127.0.0.1 SSO_PORT="$PORT" "$PY" "$HERE/tests/sso_protocol_sim.py"
RC1=$?
echo "=== run protocol simulator (STRAP external-browser mode) ==="
SSO_STRAP=1 SSO_DEBUG="${SSO_DEBUG:-1}" SSO_HOST=127.0.0.1 SSO_PORT="$PORT" "$PY" "$HERE/tests/sso_protocol_sim.py"
RC2=$?
echo "=== run protocol simulator (CLI device-flow mode) ==="
# fake 模式: /device/code -> /device/token 第一跳 pending 第二跳发
# fake-token-*, 该 token 经 /introspect github-token 分支放行.
CLI_TOKEN="$(
  docker exec ocserv-sso python3 - <<'PYEOF'
import json, urllib.request
d = json.load(urllib.request.urlopen(
    urllib.request.Request("http://127.0.0.1:8443/device/code", data=b"{}")))
urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8443/device/token",
    data=json.dumps({"device_code": d["device_code"]}).encode(),
    headers={"Content-Type": "application/json"}))
t = json.load(urllib.request.urlopen(urllib.request.Request(
    "http://127.0.0.1:8443/device/token",
    data=json.dumps({"device_code": d["device_code"]}).encode(),
    headers={"Content-Type": "application/json"})))
print(t["access_token"])
PYEOF
)"
echo "  cli device token: ${CLI_TOKEN:0:12}..."
CLI_TOKEN="$CLI_TOKEN" SSO_DEBUG="${SSO_DEBUG:-1}" SSO_HOST=127.0.0.1 SSO_PORT="$PORT" \
  "$PY" "$HERE/tests/sso_protocol_sim.py"
RC3=$?

echo "=== results: embedded=$RC1 strap=$RC2 cli-device=$RC3 ==="
RC=$(( RC1 != 0 || RC2 != 0 || RC3 != 0 ))

if [ "$RC" != 0 ]; then
  dump_fail_logs
fi
exit $RC
