"""通过 fnOS 应用中心 HTTP API 安装 / 升级 fpk。

★ 凭据从环境变量读取，不要写死在代码里：
    export DNRP_HOST=192.168.1.10
    export DNRP_USER=your-user
    export DNRP_PASS=your-password

用法：
    python3 appcenter.py install /path/to/app.fpk
    python3 appcenter.py upgrade /path/to/app.fpk

原理（从前端 JS 逆向 + 实测）：
  1. WebSocket 登录拿 token（login 响应的 token 字段）
  2. POST /app-center/v1/download/task
       {packageSourceType: "file", path: <NAS 上的 fpk 路径>}
       -> data.downloadTaskId
  3. GET  /app-center/v1/download/status?downloadTaskId=xxx
       -> {status:2, message:"success", appName, version, path}
  4. 安装：POST /app-center/v1/install/task  {appName, version, downloadTaskId}
     升级：POST /app-center/v1/update/task   {appName, updateVersion, packageType}
  5. 轮询 status

踩过的坑：
  * download/status 参数名是 downloadTaskId，不是 taskId
  * install/task 已装会返回 10236（ALREADY_INSTALLED），必须走 update/task
  * update/task 的版本字段叫 updateVersion，不是 version
  * 响应可能是 chunked 编码，要手动解码
  * /var/log 是 100MB tmpfs，满了会导致安装静默失败
"""

from __future__ import annotations

import base64
import json
import os
import random
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

HOST = os.environ.get("DNRP_HOST", "127.0.0.1")
WS_PORT = int(os.environ.get("DNRP_WS_PORT", "16667"))
USER = os.environ.get("DNRP_USER", "")
PASS = os.environ.get("DNRP_PASS", "")
APPC_SOCK = os.environ.get("DNRP_APPC_SOCK",
                           "/run/com.trim.app.center.web.sock")
BASE = "/app-center/v1"


# ------------------------------------------------------------ WebSocket 登录


class WS:
    def __init__(self) -> None:
        raw = socket.create_connection((HOST, WS_PORT), timeout=20)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.sock = ctx.wrap_socket(raw, server_hostname=HOST)
        self.buf = b""

        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((
            f"GET /websocket?type=main HTTP/1.1\r\n"
            f"Host: {HOST}:{WS_PORT}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode())

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("WebSocket 握手失败")
            resp += chunk
        self.buf = resp.split(b"\r\n\r\n", 1)[1]

    def send(self, text: str) -> None:
        payload = text.encode()
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header += struct.pack(">H", n)
        else:
            header.append(0x80 | 127)
            header += struct.pack(">Q", n)
        header += mask
        header += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header))

    def recv(self, timeout: float = 30) -> str:
        self.sock.settimeout(timeout)
        while True:
            while len(self.buf) < 2:
                d = self.sock.recv(65536)
                if not d:
                    raise RuntimeError("WebSocket 断开")
                self.buf += d
            b0, b1 = self.buf[0], self.buf[1]
            op, ln = b0 & 0x0F, b1 & 0x7F
            off = 2
            if ln == 126:
                while len(self.buf) < 4:
                    self.buf += self.sock.recv(65536)
                ln = struct.unpack(">H", self.buf[2:4])[0]
                off = 4
            elif ln == 127:
                while len(self.buf) < 10:
                    self.buf += self.sock.recv(65536)
                ln = struct.unpack(">Q", self.buf[2:10])[0]
                off = 10
            while len(self.buf) < off + ln:
                d = self.sock.recv(65536)
                if not d:
                    raise RuntimeError("WebSocket 断开")
                self.buf += d
            data = self.buf[off:off + ln]
            self.buf = self.buf[off + ln:]
            if op == 0x9:                       # ping
                m = os.urandom(4)
                self.sock.sendall(bytes([0x8A, 0x80 | len(data)]) + m
                                  + bytes(b ^ m[i % 4]
                                          for i, b in enumerate(data)))
                continue
            if op == 0x8:                       # close
                raise RuntimeError("WebSocket 关闭")
            if op == 1:
                return data.decode()


def login() -> str:
    """登录 fnOS，返回 token（用于 Authorization: trim <token>）。"""
    if not USER or not PASS:
        raise SystemExit(
            "缺少凭据。请设置环境变量：\n"
            "  export DNRP_USER=你的用户名\n"
            "  export DNRP_PASS=你的密码"
        )

    ws = WS()
    counter = random.randint(0x1000, 0xEFFFFF)

    def rid() -> str:
        nonlocal counter
        counter += 1
        return f"{int(time.time()):08x}{random.getrandbits(32):08x}{counter:012x}"

    # 取 RSA 公钥
    o = {"reqid": rid(), "req": "util.crypto.getRSAPub"}
    ws.send(json.dumps(o))
    r0 = json.loads(ws.recv())
    pub, si = r0.get("pub", ""), str(r0.get("si", ""))

    work = tempfile.mkdtemp()
    try:
        pubfile = os.path.join(work, "pub.pem")
        with open(pubfile, "w") as f:
            f.write(pub)

        aes_key, iv = os.urandom(32), os.urandom(16)
        keyfile = os.path.join(work, "k")
        encfile = os.path.join(work, "e")
        with open(keyfile, "wb") as f:
            f.write(aes_key)

        # RSA-OAEP(SHA256) 加密 AES 密钥
        subprocess.run(
            ["openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey", pubfile,
             "-pkeyopt", "rsa_padding_mode:oaep",
             "-pkeyopt", "rsa_oaep_md:sha256",
             "-pkeyopt", "rsa_mgf1_md:sha256",
             "-in", keyfile, "-out", encfile], check=True, capture_output=True)

        inner = {
            "reqid": rid(), "req": "user.login",
            "user": USER, "password": PASS,
            "deviceName": "dnsrp-Tool", "deviceType": "Browser",
            "stay": True,
            "did": "d" + "".join(random.choice("0123456789abcdef")
                                 for _ in range(20)),
            "si": si,
        }
        enc = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-K", aes_key.hex(),
             "-iv", iv.hex(), "-base64", "-A"],
            input=json.dumps(inner, separators=(",", ":")).encode(),
            capture_output=True, check=True)

        with open(encfile, "rb") as f:
            rsa_b64 = base64.b64encode(f.read()).decode()

        ws.send(json.dumps({
            "req": "encrypted", "iv": base64.b64encode(iv).decode(),
            "rsa": rsa_b64, "aes": enc.stdout.decode().strip(), "v": 1}))
        r = json.loads(ws.recv())
        if r.get("result") != "succ":
            raise SystemExit(f"登录失败: errno={r.get('errno')} "
                             f"{r.get('errmsg')}")
        return str(r.get("token") or "")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ------------------------------------------------------------ AppCenter API


def ac(token: str, method: str, path: str, body: bytes | None = None,
       headers: dict | None = None) -> dict:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(300)
    sock.connect(APPC_SOCK)

    lines = [f"{method} {path} HTTP/1.1", "Host: localhost",
             f"Authorization: trim {token}", "Connection: close"]
    for k, v in (headers or {}).items():
        lines.append(f"{k}: {v}")
    if body is not None:
        lines.append(f"Content-Length: {len(body)}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode() + (body or b""))

    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    sock.close()

    head, _, payload = data.partition(b"\r\n\r\n")
    # 手动解 chunked
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", payload
        while rest:
            ln, _, rest = rest.partition(b"\r\n")
            try:
                size = int(ln.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        payload = out

    try:
        return json.loads(payload.decode())
    except (UnicodeDecodeError, ValueError):
        return {"raw": payload.decode(errors="replace")[:400]}


def jpost(token: str, path: str, payload: dict) -> dict:
    b = json.dumps(payload).encode()
    return ac(token, "POST", path, b,
              {"Content-Type": "application/json",
               "Content-Length": str(len(b))})


def show(d, n: int = 400) -> str:
    return (json.dumps(d, ensure_ascii=False)[:n]
            if isinstance(d, dict) else str(d)[:n])


def wait_download(token: str, dl_id: str, timeout: int = 60) -> dict:
    """等下载任务解析完成，返回包信息。"""
    for _ in range(timeout // 2):
        time.sleep(2)
        s = ac(token, "GET", f"{BASE}/download/status?downloadTaskId={dl_id}")
        data = (s.get("data") or {}) if isinstance(s, dict) else {}
        if data.get("message") == "success" or data.get("status") == 2:
            return data
    raise SystemExit("等待包解析超时")


def do_install(token: str, fpk: str) -> int:
    print("[1] 创建下载任务")
    d = jpost(token, f"{BASE}/download/task",
              {"packageSourceType": "file", "path": fpk})
    if d.get("code") != 0:
        print(f"    失败: {show(d)}")
        return 1
    dl = (d.get("data") or {}).get("downloadTaskId")
    print(f"    downloadTaskId = {dl}")

    print("[2] 等待包解析")
    info = wait_download(token, dl)
    app_name = info.get("appName")
    version = info.get("version")
    print(f"    {app_name} {version}")

    print("[3] 提交安装")
    r = jpost(token, f"{BASE}/install/task",
              {"appName": app_name, "version": version,
               "downloadTaskId": dl})
    code = r.get("code")
    if code == 10236:
        print("    已安装，请改用 upgrade 子命令")
        return 1
    if code != 0:
        print(f"    失败: {show(r)}")
        return 1
    print("    ✓ 已提交，请到应用中心查看进度")
    return 0


def do_upgrade(token: str, fpk: str) -> int:
    print("[1] 创建下载任务")
    d = jpost(token, f"{BASE}/download/task",
              {"packageSourceType": "file", "path": fpk})
    if d.get("code") != 0:
        print(f"    失败: {show(d)}")
        return 1
    dl = (d.get("data") or {}).get("downloadTaskId")

    print("[2] 等待包解析")
    info = wait_download(token, dl)
    app_name = info.get("appName")
    version = info.get("version")
    print(f"    {app_name} {version}")

    print("[3] 提交升级（字段名是 updateVersion）")
    r = jpost(token, f"{BASE}/update/task",
              {"appName": app_name,
               "updateVersion": version,
               "packageType": info.get("packageType") or "path"})
    if r.get("code") != 0:
        print(f"    失败: {show(r)}")
        return 1
    print(f"    ✓ 已提交 taskId={(r.get('data') or {}).get('taskId')}")
    return 0


def main() -> int:
    if len(sys.argv) < 3:
        print(__doc__)
        return 1

    action, fpk = sys.argv[1], sys.argv[2]
    if action not in ("install", "upgrade"):
        print("子命令必须是 install 或 upgrade")
        return 1

    token = login()
    print(f"已登录，token 长度 {len(token)}\n")

    if action == "install":
        return do_install(token, fpk)
    return do_upgrade(token, fpk)


if __name__ == "__main__":
    raise SystemExit(main())
