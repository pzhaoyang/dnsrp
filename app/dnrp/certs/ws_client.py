"""fnOS WebSocket 客户端。

用于调用 fnOS 的证书 API（cert.apply / cert.upload / cert.replace / cert.renew）。
不依赖第三方库：WebSocket 帧、AES 加解密、HMAC 签名全部用标准库 + openssl 命令行。

协议要点（详见 docs/PROTOCOL.md）：
  * 传输：wss://<host>:<webui_https_port>/websocket?type=main
  * 认证：密码登录 → RSA-OAEP 换 AES → AES-256-CBC 加密登录帧
  * 签名：base64(HMAC-SHA256(json, secret)) + json

★ 设计约束：
  本模块**只在用户主动签发证书时**才建立连接。
  证书续签由 fnOS 自己完成（renewal=1），不需要这里定时跑。
  2FA 验证码 30 秒过期，不适合无人值守，所以必须由用户在 UI 现输。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from typing import Any
from urllib.parse import urlparse

log = logging.getLogger("dnrp.certs.ws")


class FnosWsError(RuntimeError):
    """fnOS WebSocket 调用的通用错误。"""


class AccessCodeRequired(FnosWsError):
    """NAS 开启了「访问码 / 访问保护」。"""


class TwofaRequired(FnosWsError):
    """账号开启了双重验证，需要验证码。"""

    def __init__(self, resp: dict[str, Any]) -> None:
        self.resp = resp
        self.access_token = str(resp.get("accessToken") or "")
        super().__init__("该 fnOS 账号开启了双重验证（2FA），需要 6 位验证码")


# ---------------------------------------------------------------- WebSocket


class WebSocket:
    """极简 WebSocket 客户端（仅文本帧 + ping/pong）。"""

    def __init__(self, url: str, cookie: str = "", access_code: str = "") -> None:
        u = urlparse(url)
        host = u.hostname or "127.0.0.1"
        port = u.port or (443 if u.scheme == "wss" else 80)
        path = u.path + (("?" + u.query) if u.query else "")

        try:
            raw = socket.create_connection((host, port), timeout=15)
        except OSError as exc:
            raise FnosWsError(f"无法连接 {host}:{port} —— {exc}") from exc

        if u.scheme == "wss":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE       # 本机自签证书
            raw = ctx.wrap_socket(raw, server_hostname=host)

        self.sock = raw
        self.buf = b""

        key = base64.b64encode(os.urandom(16)).decode()
        cookie_hdr = f"Cookie: {cookie}\r\n" if cookie else ""
        ac_hdr = ""
        if access_code:
            ac_b64 = base64.b64encode(access_code.encode()).decode()
            ac_hdr = f"x-access-code: {ac_b64}\r\nx-access-source: web\r\n"

        raw.sendall((
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            f"{cookie_hdr}{ac_hdr}"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = raw.recv(4096)
            if not chunk:
                raise FnosWsError("WS 握手：连接被关闭")
            resp += chunk
            if len(resp) > 65536:
                raise FnosWsError("WS 握手：响应过大")

        first_line = resp.split(b"\r\n", 1)[0].decode(errors="replace")
        if "101" not in first_line:
            head = resp[:4096].decode(errors="replace")
            if "X-Trim-Safe-Code-Challenge" in head:
                if not access_code:
                    raise AccessCodeRequired(first_line)
                raise FnosWsError(
                    f"WS 握手失败（已提供访问码）: {first_line}\n"
                    "  通常是访问码不正确"
                )
            raise FnosWsError(f"WS 握手失败: {first_line}")

        self.buf = resp.split(b"\r\n\r\n", 1)[1]

    def send(self, text: str) -> None:
        payload = text.encode()
        mask = os.urandom(4)
        hdr = bytearray([0x81])
        n = len(payload)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        hdr += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr))

    def _need(self, n: int) -> None:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise FnosWsError("WS 连接已关闭")
            self.buf += chunk

    def recv_text(self, timeout: float = 15) -> str:
        self.sock.settimeout(timeout)
        while True:
            self._need(2)
            b0, b1 = self.buf[0], self.buf[1]
            opcode, ln = b0 & 0x0F, b1 & 0x7F
            off = 2
            if ln == 126:
                self._need(off + 2)
                ln = struct.unpack(">H", self.buf[off:off + 2])[0]
                off += 2
            elif ln == 127:
                self._need(off + 8)
                ln = struct.unpack(">Q", self.buf[off:off + 8])[0]
                off += 8
            self._need(off + ln)
            data = self.buf[off:off + ln]
            self.buf = self.buf[off + ln:]

            if opcode == 0x9:                       # ping -> pong
                mask = os.urandom(4)
                self.sock.sendall(
                    bytes([0x8A, 0x80 | len(data)]) + mask
                    + bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                )
                continue
            if opcode == 0x8:
                raise FnosWsError("WS 被服务端关闭")
            if opcode == 0x1:
                return data.decode()

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------- API 客户端


class FnosClient:
    """fnOS 证书 API 客户端。

    典型用法：
        cli = FnosClient(host, port, username, password, access_code="")
        cli.connect()            # 可能抛 TwofaRequired
        cli.twofa_verify("123456")
        cli.call("cert.list")
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 16667,
        username: str = "",
        password: str = "",
        access_code: str = "",
        cookie: str = "",
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.access_code = access_code
        self.cookie = cookie

        self._ws: WebSocket | None = None
        self._counter = random.randint(0x1000, 0xEFFFFF)
        self.secret = b""
        self.did = ""
        self.device_name = "Linux-DNSRP"
        self.access_token = ""
        self.uid: Any = None
        self.admin: Any = None
        # 预置会话密钥（来自浏览器 Cookie，走 use_secret() 注入）
        self._preset_secret: bytes = b""
        self._preset_token: str = ""

    # --------------------------------------------------------- 连接与认证

    def connect(self) -> dict[str, Any]:
        """建立连接并登录。

        有 cookie 时走 cookie 认证（可绕开 2FA）；
        否则走密码登录，2FA 账号会抛 TwofaRequired。
        """
        url = f"wss://{self.host}:{self.port}/websocket?type=main"
        self._ws = WebSocket(url, cookie=self.cookie, access_code=self.access_code)

        if self._preset_secret:
            # 已有会话密钥（来自浏览器 Cookie），不需要登录
            log.info("使用预置会话密钥，跳过登录流程")
            return {"result": "succ", "token": self._preset_token}

        if self.cookie:
            return self._cookie_login()

        if not self.username or not self.password:
            raise FnosWsError("缺少用户名或密码")

        self.did = "d" + "".join(
            random.choice("0123456789abcdef") for _ in range(20)
        )
        return self.login(self.username, self.password)

    def use_secret(self, secret: bytes, token: str = "") -> None:
        """直接注入会话密钥，跳过密码登录。

        ★ 这是正规 fpk 的正确用法：
          用户已在飞牛 OS 网页登录，前端 JS 从 localStorage 读到
          fnos-Secret，通过请求头传给后端。
          有了这个密钥就能做 HMAC 签名调所有 API，
          不需要知道用户的密码，也不受 2FA 限制。

        ★ 注意：本方法只**记录**密钥，不建立连接。
          连接会在第一次 call() 时惰性建立 —— 因为下游可能
          同时创建多个客户端，立即连接会造成无谓开销。
        """
        if not secret:
            raise FnosWsError("会话密钥为空")
        self._preset_secret = secret
        self._preset_token = token
        self.secret = secret
        log.info("已注入会话密钥（%d 字节）", len(secret))

    def _ensure_connected(self) -> None:
        """确保连接已建立（惰性连接）。

        所有 call() 之前都会走这里，避免「注入了密钥但没连」
        导致 'NoneType' object has no attribute 'send'。
        """
        if self._ws is not None:
            return

        url = f"wss://{self.host}:{self.port}/websocket?type=main"
        self._ws = WebSocket(url, cookie=self.cookie,
                             access_code=self.access_code)

        if not self._preset_secret and self.username and self.password:
            # 没有预置密钥时，用密码登录补齐会话
            self.did = "d" + "".join(
                random.choice("0123456789abcdef") for _ in range(20)
            )
            self.login(self.username, self.password)
            return

        log.debug("连接已建立（使用预置会话密钥）")

    def _cookie_login(self) -> dict[str, Any]:
        """Cookie 方式：getSI → authToken（签名帧依然需要）。"""
        obj = {"reqid": self._reqid(), "req": "util.getSI"}
        self._ws.send(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        r = self._wait(obj["reqid"])
        si = str(r.get("si") or "")
        if not si:
            raise FnosWsError(f"getSI 失败: {r}")

        # 没有 secret 时无法签名，fnOS 允许明文 authToken？实测需要签名。
        # 所以 cookie 方式仍需要 secret —— 从登录接口拿不到了。
        raise FnosWsError(
            "当前版本不支持纯 Cookie 认证。\n"
            "请使用用户名 + 密码（2FA 账号在界面上输入验证码）。"
        )

    def login(self, username: str, password: str) -> dict[str, Any]:
        payload = {
            "user": username,
            "password": password,
            "deviceName": self.device_name,
            "deviceType": "Browser",
            "stay": True,
            "did": self.did,
        }
        r, key, iv = self._encrypted_call("user.login", payload)

        if r.get("result") != "succ":
            errno = r.get("errno")
            if errno == 131072:
                raise FnosWsError("用户名或密码错误（131072）")
            if errno == 131073:
                raise FnosWsError("用户名不存在（131073）")
            raise FnosWsError(f"登录失败: errno={errno} {r.get('errmsg')}")

        raw_secret = self._unwrap_secret(r, key, iv)
        if not raw_secret:
            if r.get("accessToken"):
                self.access_token = str(r["accessToken"])
                raise TwofaRequired(r)
            raise FnosWsError("登录响应缺少 secret")

        self.secret = raw_secret
        self.uid = r.get("uid")
        self.admin = r.get("admin")
        log.info("fnOS 登录成功 uid=%s", self.uid)
        return r

    def twofa_verify(self, code: str, trusted: bool = True) -> dict[str, Any]:
        """提交 2FA 验证码换取 secret。"""
        if not self.access_token:
            raise FnosWsError("缺少 accessToken，请先调用 connect()")

        base = {
            "accessToken": self.access_token,
            "code": str(code).strip(),
            "isTrustedDevice": bool(trusted),
            "stay": 1,
            "deviceName": self.device_name,
            "deviceType": "Browser",
            "did": self.did,
        }
        r, key, iv = self._encrypted_call("user.2fa.loginVerify", base)
        if r.get("errno") in (8192, 3000001):
            r, key, iv = self._encrypted_call(
                "user.2fa.loginVerify", {"data": base}
            )

        if r.get("result") != "succ":
            errno = r.get("errno")
            if errno == 135168:
                raise FnosWsError("验证码不正确或已过期（135168）")
            raise FnosWsError(f"2FA 验证失败: errno={errno} {r.get('errmsg')}")

        raw_secret = self._unwrap_secret(r, key, iv)
        if not raw_secret:
            raise FnosWsError("2FA 响应缺少 secret")

        self.secret = raw_secret
        self.uid = r.get("uid") or self.uid
        log.info("2FA 验证成功 uid=%s", self.uid)
        return r

    # --------------------------------------------------------- 加密帧

    def _encrypted_call(
        self, req: str, flat: dict[str, Any], timeout: float = 20
    ) -> tuple[dict[str, Any], bytes, bytes]:
        """发一条加密帧，返回 (响应, aes_key, iv)。"""
        obj = {"reqid": self._reqid(), "req": "util.crypto.getRSAPub"}
        self._ws.send(json.dumps(obj, separators=(",", ":"), ensure_ascii=False))
        r0 = self._wait(obj["reqid"])
        pub = r0.get("pub") or ""
        si = str(r0.get("si") or "")
        if not pub:
            raise FnosWsError(f"getRSAPub 失败: {r0}")

        work = tempfile.mkdtemp(prefix="dnrp-enc-")
        try:
            pubf = os.path.join(work, "pub.pem")
            with open(pubf, "w", encoding="utf-8") as fh:
                fh.write(pub)

            aes_key = os.urandom(32)
            iv = os.urandom(16)
            keyf = os.path.join(work, "key.bin")
            encf = os.path.join(work, "key.enc")
            with open(keyf, "wb") as fh:
                fh.write(aes_key)

            subprocess.run(
                ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pubf,
                 "-pkeyopt", "rsa_padding_mode:oaep",
                 "-pkeyopt", "rsa_oaep_md:sha256",
                 "-pkeyopt", "rsa_mgf1_md:sha256",
                 "-in", keyf, "-out", encf],
                check=True, capture_output=True, timeout=20,
            )
            with open(encf, "rb") as fh:
                rsa_b64 = base64.b64encode(fh.read()).decode()

            inner = {"reqid": self._reqid(), "req": req}
            inner.update(flat)
            inner["si"] = si
            ij = json.dumps(inner, separators=(",", ":"), ensure_ascii=False)

            enc = subprocess.run(
                ["openssl", "enc", "-aes-256-cbc",
                 "-K", aes_key.hex(), "-iv", iv.hex(),
                 "-base64", "-A"],
                input=ij.encode(), capture_output=True, check=True, timeout=20,
            )

            frame = {
                "req": "encrypted",
                "iv": base64.b64encode(iv).decode(),
                "rsa": rsa_b64,
                "aes": enc.stdout.decode().strip(),
                "v": 1,
            }
            self._ws.send(json.dumps(frame, separators=(",", ":"), ensure_ascii=False))
            return self._wait(inner["reqid"], timeout=timeout), aes_key, iv
        finally:
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _unwrap_secret(
        r: dict[str, Any], aes_key: bytes, iv: bytes
    ) -> bytes | None:
        """解密响应里的 secret（AES-256-CBC + PKCS7）。"""
        secret_b64 = r.get("secret") or ""
        if not secret_b64:
            return None
        dec = subprocess.run(
            ["openssl", "enc", "-d", "-aes-256-cbc",
             "-K", aes_key.hex(), "-iv", iv.hex()],
            input=base64.b64decode(secret_b64),
            capture_output=True, timeout=20,
        )
        raw = dec.stdout
        padlen = raw[-1] if raw else 0
        if 0 < padlen <= 16:
            raw = raw[:-padlen]
        return raw

    # --------------------------------------------------------- 签名调用

    def _reqid(self) -> str:
        self._counter += 1
        return (
            f"{int(time.time()):08x}"
            f"{random.getrandbits(32):08x}"
            f"{self._counter:012x}"
        )

    def _sign(self, obj: dict[str, Any]) -> str:
        j = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        mac = hmac.new(self.secret, j.encode(), hashlib.sha256).digest()
        return base64.b64encode(mac).decode() + j

    def _wait(self, reqid: str, timeout: float = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = json.loads(self._ws.recv_text(timeout=max(1, deadline - time.time())))
            if r.get("reqid") == reqid:
                return r
        raise FnosWsError(f"reqid={reqid} 超时无响应")

    def call(
        self, req: str, data: Any = None, flat: dict[str, Any] | None = None,
        timeout: float = 30,
    ) -> Any:
        """发起一次签名调用，返回 data 字段（失败抛异常）。"""
        # 惰性连接：首次调用时建立 WebSocket
        self._ensure_connected()

        obj: dict[str, Any] = {"reqid": self._reqid(), "req": req}
        if data is not None:
            obj["data"] = data
        if flat:
            obj.update(flat)

        self._ws.send(self._sign(obj))
        r = self._wait(obj["reqid"], timeout)

        if r.get("result") != "succ":
            errno = r.get("errno")
            msg = r.get("errmsg") or ""
            hint = _ERRNO_HINT.get(errno or 0, "")
            raise FnosWsError(
                f"{req} 失败: errno={errno} {msg}"
                + (f"\n  {hint}" if hint else "")
            )
        return r.get("data")

    def close(self) -> None:
        if self._ws:
            self._ws.close()
            self._ws = None

    def __enter__(self) -> "FnosClient":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


# ---------------------------------------------------------------- 错误码提示

_ERRNO_HINT: dict[int, str] = {
    8192: "参数错误，检查字段类型",
    131072: "用户名或密码错误",
    131073: "用户名不存在",
    135168: "2FA 验证码不正确或已过期",
    3000001: "参数无效（字段类型错误）",
    3000033: "证书域名与所选 DDNS 记录的 domain 不匹配（cert.apply 只接受单域名）",
    3000034: "所选的 DDNS 记录不存在",
    3000035: "该证书不具备续签资格",
    65534: "验签失败（会话未绑定或 HMAC 不匹配）",
    65535: "未知错误",
}


def detect_webui_port() -> int:
    """探测 fnOS WebUI 的 HTTPS 端口。"""
    from .. import config

    port, _host = config.fnos_webui_https_port()
    return port
