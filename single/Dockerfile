# syntax=docker/dockerfile:1
# Single-container build: ocserv (compiled) + vpn-portal (uvicorn) + pam_exec
# helper, one debian:12-slim runtime. Replaces the two-container
# ocserv+portal pair (P2 of docs/refactor-single-container-spec.md).
#
# Build context MUST be the repo root (needs ocserv/ + portal/):
#   docker build -f single/Dockerfile -t ocserv-sso .
# Local (China network): --build-arg APT_MIRROR=mirrors.aliyun.com

# ---------- builder: compile ocserv 1.5.0 + sso patch ----------
FROM debian:12-slim AS builder
ARG APT_MIRROR=
RUN if [ -n "$APT_MIRROR" ]; then sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential pkg-config meson ninja-build \
    libgnutls28-dev libev-dev libreadline-dev libtasn1-bin \
    libpam0g-dev libprotobuf-c-dev protobuf-c-compiler \
    libtalloc-dev libseccomp-dev \
    gnutls-bin ca-certificates wget netbase \
    && rm -rf /var/lib/apt/lists/*
COPY ocserv/patches/ocserv-1.5.0-sso.patch /tmp/ocserv-sso.patch
RUN wget -q https://www.infradead.org/ocserv/download/ocserv-1.5.0.tar.xz \
    && tar xf ocserv-1.5.0.tar.xz && cd ocserv-1.5.0 \
    && patch -p1 < /tmp/ocserv-sso.patch \
    && meson setup build -Dseccomp=enabled \
    && ninja -C build && meson install -C build \
    && cd .. && rm -rf ocserv-1.5.0* /tmp/ocserv-sso.patch

# ---------- runtime: ocserv + portal + helper ----------
FROM debian:12-slim
ARG APT_MIRROR=
ARG PIP_INDEX_URL=
RUN if [ -n "$APT_MIRROR" ]; then sed -i "s|deb.debian.org|$APT_MIRROR|g" /etc/apt/sources.list.d/debian.sources; fi

# Runtime deps:
#   python3+pip     portal (uvicorn) + pam_exec helper (stdlib only)
#   tini            PID1: reap zombies, forward signals (spec §3.4)
#   curl            healthz probe (curl 127.0.0.1:8443/healthz)
#   libgnutls30 etc. ocserv runtime shared libs (subset of builder's -dev set)
#   libpam0g        pam_exec.so lives in libpam-modules; libpam0g is libpam
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip tini curl ca-certificates \
    libgnutls30 libev4 libreadline8 libtasn1-6 \
    libpam0g libpam-modules libprotobuf-c1 libtalloc2 libseccomp2 \
    libaudit1 libcap-ng0 libcrypt1 libffi8 libgmp10 \
    libhogweed6 libidn2-0 libnettle8 libp11-kit0 libunistring2 \
    netbase \
    && rm -rf /var/lib/apt/lists/*

# ocserv install (meson install from builder: /usr/local/sbin/ocserv,
# /usr/local/lib/*/ocserv*, occtl, man pages, pam modules it links).
COPY --from=builder /usr/local/ /usr/local/
RUN ldconfig

# portal python deps (uvicorn/fastapi/requests/cryptography/python-multipart).
COPY portal/requirements.txt /tmp/requirements.txt
RUN pip3 install --break-system-packages ${PIP_INDEX_URL:+--index-url "$PIP_INDEX_URL"} -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt

# ocserv run user (ocserv.conf run-as-user = ocserv).
RUN useradd -r -s /usr/sbin/nologin ocserv

# ocserv PAM stack + pam_exec helper. pam.d/ocserv keeps the
# loopback default (no URL argv) — single-container = loopback portal.
# ocserv.conf is NOT baked — mount it at runtime (see examples/).
COPY ocserv/pam/ocserv /etc/pam.d/ocserv
COPY ocserv/pam/ocserv_portal_auth.py /usr/local/libexec/ocserv_portal_auth.py

# portal code.
COPY portal/app.py portal/vpn_authz.py /opt/vpn-portal/

# entrypoint: uvicorn (loopback) & -> exec ocserv foreground.
COPY single/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SSO_BIND=127.0.0.1 SSO_PORT=8443
EXPOSE 443/tcp 443/udp

# tini as PID1 (-g: forward signals to the process group so ocserv and
# uvicorn both get SIGTERM on docker stop).
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/entrypoint.sh"]
