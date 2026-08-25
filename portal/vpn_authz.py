"""vpn_authz — GitHub 授权判定单模块 (portal 唯一持有者).

收敛自 refactor spec §3.1: org 列表解析、memberships 遍历、缓存、b32 编解码、
token 形态判定. freeradius 删除后, 这里是 VPN 访问决策的唯一实现.

接口:
  parse_orgs(env_value) -> list[str]          # 逗号分隔, 小写, 去空
  b32_login(login) -> str                     # cookie 复合串首段编码
  login_ok_shape(login) -> bool               # GitHub login 形态
  github_token_ok_shape(token) -> bool        # access_token 形态预检
  AuthorizedMember(orgs, verifier_token, *, cache_ttl=300, lock=None)
      .member_of(login, org) -> bool          # 单 org memberships API
      .is_authorized(login) -> bool           # 任一 org active (带缓存)
"""
import base64
import re
import threading
import time

import requests

LOGIN_RE = re.compile(r"^[A-Za-z0-9-]{1,39}$")
GITHUB_MEMBERSHIPS_URL = "https://api.github.com/orgs/{org}/memberships/{login}"
API_TIMEOUT = 5

# 长度锚定 GitHub 现行 token 前缀族 (gho_/ghu_/ghs_/ghr_/github_pat_ ≤ ~93).
TOKEN_MIN_LEN = 8
TOKEN_MAX_LEN = 255


def parse_orgs(env_value: str) -> list:
    """逗号分隔 org 列表 -> 小写去空白 list (空项剔除)."""
    return [o.strip().lower() for o in (env_value or "").split(",") if o.strip()]


def b32_login(login: str) -> str:
    """login -> cookie 复合串首段 (b32 小写无填充, 与 ocserv patch 对齐)."""
    return base64.b32encode(login.encode()).decode().lower().rstrip("=")


def login_ok_shape(login: str) -> bool:
    return bool(LOGIN_RE.match(login or ""))


def github_token_ok_shape(token: str) -> bool:
    """access_token 形态预检: 非空/长度界/无空白/ASCII 可打印.

    拒噪声, 避免把任意串打到 api.github.com; 不做前缀白名单 (GitHub 可新增
    token 前缀)."""
    if not token or len(token) < TOKEN_MIN_LEN or len(token) > TOKEN_MAX_LEN:
        return False
    if any(c.isspace() for c in token):
        return False
    return token.isascii() and token.isprintable()


class AuthorizedMember:
    """active membership in ANY of orgs, 每 (login, org) 缓存 cache_ttl 秒.

    lock 由调用方注入 (portal 用全局 LOCK 与 PENDING/ISSUED 共抢)."""

    def __init__(self, orgs, verifier_token: str, *, cache_ttl: int = 300,
                 lock=None, session=None):
        self.orgs = list(orgs)
        self.verifier_token = verifier_token
        self.cache_ttl = cache_ttl
        self.lock = lock or threading.Lock()
        self.http = session or requests
        self.cache = {}  # (login, org) -> (bool, float)

    def member_of(self, login: str, org: str) -> bool:
        if not self.verifier_token:
            return False
        try:
            r = self.http.get(
                GITHUB_MEMBERSHIPS_URL.format(org=org, login=login),
                headers={"Authorization": f"token {self.verifier_token}"},
                timeout=API_TIMEOUT,
            )
            return r.status_code == 200 and r.json().get("state") == "active"
        except requests.RequestException:
            return False

    def is_authorized(self, login: str) -> bool:
        now = time.time()
        for org in self.orgs:
            with self.lock:
                cached = self.cache.get((login, org))
            if cached and now - cached[1] < self.cache_ttl:
                if cached[0]:
                    return True
                continue
            ok = self.member_of(login, org)
            with self.lock:
                self.cache[(login, org)] = (ok, now)
            if ok:
                return True
        return False
