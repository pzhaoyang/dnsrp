"""从 CGI 环境（浏览器的 Cookie/Header）获取 fnOS 登录凭证。

★ 核心认知：
  之前 fnos-multidomain-cert / fnos-ddns 那两个脚本要用户名密码，
  是因为它们跑在 SSH 里，**没有 Web 会话**。

  但 dnsrp 是正规 fpk，运行在 fnOS 的 CGI 环境里，
  nginx 会把浏览器的 Cookie 通过 HTTP_COOKIE 环境变量传给 CGI。
  用户已经在飞牛 OS 网页登录过，所以这里天然能拿到会话凭证。

  因此：不需要用户再填一次密码。

取到的凭证用于两类调用：
  1. appcenter HTTP API（/app-center/v1/...）
     -> 需要 Authorization: trim <fnos-token>
  2. fnOS WebSocket API（证书签发 / DDNS）
     -> 需要 fnos-Secret 做 HMAC 签名

安全注意：
  * 这些值只在内存里中转，不落盘
  * 日志里绝不打印完整值
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("dnrp.auth")


# ---------------------------------------------------------------- Cookie 解析


def parse_cookie(raw: str) -> dict[str, str]:
    """解析 HTTP_COOKIE 环境变量。

    形如： "a=1; fnos-token=xxx; fnos-Secret=yyy"
    """
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, _, v = part.partition("=")
        out[k.strip()] = v.strip()
    return out


@dataclass
class Credentials:
    """从当前请求上下文拿到的 fnOS 凭证。"""

    # appcenter HTTP API 用
    token: str = ""
    # WebSocket 签名用（base64 或原始字节）
    secret: str = ""
    # 设备标识
    device: str = ""
    # 来源说明（便于排查）
    source: str = ""
    raw_cookies: dict[str, str] = field(default_factory=dict)

    @property
    def has_token(self) -> bool:
        return bool(self.token)

    @property
    def has_secret(self) -> bool:
        return bool(self.secret)

    def secret_bytes(self) -> bytes:
        """把 secret 转成 HMAC 用的原始字节。

        fnos-Secret 在 localStorage 里是 base64 字符串，
        解码后是 16~18 字节的 HMAC key。
        有些场景（比如 WS 登录响应解密出来的）已经是原始字节。
        """
        if not self.secret:
            return b""
        s = self.secret.strip()
        # 先试 base64 解码
        try:
            padded = s + "=" * (-len(s) % 4)
            raw = base64.b64decode(padded, validate=False)
            if 8 <= len(raw) <= 64:
                return raw
        except (binascii.Error, ValueError):
            pass
        # 退化为原始字符串字节
        return s.encode()

    def masked(self) -> dict[str, Any]:
        """脱敏后的描述，用于日志/调试接口。

        ★ 只报「有无 + 长度」，不泄露任何前缀/后缀片段：
          对 base64 编码的短密钥，前 4 后 4 已相当于泄露部分密钥材料。
        """
        def m(v: str) -> str:
            return f"(len={len(v)})" if v else ""

        return {
            "source": self.source,
            "token": m(self.token),
            "secret": m(self.secret),
            "device": m(self.device),
            "cookieKeys": sorted(self.raw_cookies.keys()),
        }


# ---------------------------------------------------------------- 从 CGI 环境


def from_cgi_env() -> Credentials:
    """从 CGI 环境变量读取凭证。

    index.cgi 会把这些环境变量通过 HTTP 头透传给后端，
    见 index.cgi 里的 X-Dnrp-* 头。
    """
    cred = Credentials(source="cgi-env")

    raw_cookie = os.environ.get("HTTP_COOKIE", "")
    cred.raw_cookies = parse_cookie(raw_cookie)

    # 优先从 Cookie 取
    cred.token = cred.raw_cookies.get("fnos-token", "")
    cred.secret = cred.raw_cookies.get("fnos-Secret", "")
    cred.device = cred.raw_cookies.get("fnos-device", "")

    if cred.token or cred.secret:
        cred.source = "cookie"
        return cred

    # 退路：index.cgi 专门透传的 X-Dnrp-* 头
    hdr_token = os.environ.get("HTTP_X_DNRP_FNOS_TOKEN", "")
    hdr_secret = os.environ.get("HTTP_X_DNRP_FNOS_SECRET", "")
    if hdr_token or hdr_secret:
        cred.token = hdr_token
        cred.secret = hdr_secret
        cred.source = "header"
        return cred

    return cred


def parse_credentials_header(value: str) -> Credentials:
    """解析 index.cgi 传来的凭证 JSON。"""
    cred = Credentials(source="cgi-header")
    if not value:
        return cred
    try:
        d = json.loads(value)
    except (ValueError, TypeError):
        return cred
    if not isinstance(d, dict):
        return cred
    cred.token = str(d.get("token") or "")
    cred.secret = str(d.get("secret") or "")
    cred.device = str(d.get("device") or "")
    return cred


# ---------------------------------------------------------------- 校验


def can_use(*, need_token: bool = False, need_secret: bool = False) -> tuple[bool, str]:
    """检查当前环境是否具备所需凭证。返回 (是否可用, 说明)。"""
    cred = from_cgi_env()

    if need_token and not cred.has_token:
        return False, "当前请求里没有 fnos-token"
    if need_secret and not cred.has_secret:
        return False, "当前请求里没有 fnos-Secret"

    return True, f"来源={cred.source}"
