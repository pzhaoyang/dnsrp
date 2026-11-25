"""dnsrp 配置与路径常量。

所有路径都从环境变量推导，便于本地调试与真机运行共用。
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

log = logging.getLogger("dnrp.config")

# ---------------------------------------------------------------- 应用自身路径

APP_NAME = "dnsrp"

# fnOS 生命周期脚本注入；本地调试时回退到当前目录
TRIM_PKGVAR = os.environ.get("TRIM_PKGVAR")
TRIM_APPDEST = os.environ.get("TRIM_APPDEST")


def _pkgvar() -> Path:
    if TRIM_PKGVAR:
        return Path(TRIM_PKGVAR)
    return Path("/var/apps") / APP_NAME / "var"


def _appdest() -> Path:
    if TRIM_APPDEST:
        return Path(TRIM_APPDEST)
    return Path("/var/apps") / APP_NAME / "target"


PKGVAR = _pkgvar()
APPDEST = _appdest()

# 运行期文件
SOCKET_PATH = PKGVAR / "dnrp.sock"
PID_FILE = PKGVAR / "dnrp.pid"
LOG_FILE = PKGVAR / "dnrp.log"
DB_PATH = PKGVAR / "dnrp.db"

# 应用自身日志/数据目录
WWW_DIR = APPDEST / "www"

# ---------------------------------------------------------------- fnOS 侧路径

# 证书目录：<domain>/<epoch>/ 下放 crt/key
FNOS_SSL_ROOT = Path("/usr/trim/var/trim_connect/ssls")

# 证书登记表：host -> {cert, key}，反代取证书的权威来源
FNOS_CERT_REGISTRY = Path("/usr/trim/etc/network_gateway_cert.conf")

# nginx / 网关设置
FNOS_GATEWAY_SETTING = Path("/usr/trim/etc/network_gateway_setting.conf")

# nginx 配置（读端口用）
FNOS_NGINX_CONF = Path("/usr/trim/nginx/conf/nginx.conf")

# ---------------------------------------------------------------- 数据库

# fnOS 的 PostgreSQL（DDNS / 证书元数据都在这里）
FNOS_PG_DB_DDNS = "trim_connect"
FNOS_PG_USER = "postgres"

# ---------------------------------------------------------------- 运行参数

# 反代默认监听起始端口（刻意避开 80/443）
DEFAULT_LISTEN_PORT = 8080


def read_manifest() -> dict[str, str]:
    """读应用 manifest，拿到版本等元信息。

    ★ 为什么不在代码里硬编码版本号：
      之前 /api/health 返回写死的 "0.1.0"，应用中心显示 0.1.7，
      两边对不上，排查时容易误判。manifest 是唯一真源。

    ★ fnOS 的实际目录布局（实测 2026-11-24）：

        /var/apps/dnsrp/                ← 应用根，manifest 在这里
            ├── manifest
            ├── cmd/  config/  ICON*
            └── target -> /vol1/@appcenter/dnsrp   ← 代码在这（TRIM_APPDEST）

      也就是说 manifest 在 APPDEST 的**上一级**（对于软链布局），
      但 APPDEST 不是软链时 manifest 又可能就在 APPDEST 里。
      所以两个位置都要试。

    ★ 权限：/vol1/@appcenter/dnsrp/manifest 应用用户**读不到**
      （属主 root，0644 但父目录限制），
      而 /var/apps/dnsrp/manifest 可读。这也是必须加候选路径的原因。
    """
    out: dict[str, str] = {}

    candidates: list[Path] = []

    # 1) /var/apps/<appname>/manifest —— 实测最可靠
    candidates.append(Path("/var/apps/dnsrp/manifest"))

    # 2) APPDEST 的上一级（软链布局下这里才是根）
    try:
        candidates.append(APPDEST.parent / "manifest")
    except (AttributeError, ValueError):
        pass

    # 3) APPDEST 本身（非软链布局）
    candidates.append(APPDEST / "manifest")

    # 4) 代码目录往上找
    candidates.append(Path(__file__).resolve().parent.parent.parent / "manifest")

    # 5) 兜底：从 /proc/self/cwd 推
    try:
        candidates.append(Path("/proc/self/cwd/manifest"))
        candidates.append(Path("/proc/self/cwd/../manifest"))
    except OSError:
        pass

    for p in candidates:
        try:
            if not p.is_file():
                continue
            txt = p.read_text(encoding="utf-8", errors="replace")
        except (OSError, PermissionError):
            continue

        for line in txt.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()

        if out:
            log.debug("从 %s 读到 manifest", p)
            break

    return out


def app_version() -> str:
    """当前应用版本（从 manifest 读，读不到则返回 'unknown'）。"""
    return read_manifest().get("version", "unknown")

# UI + API 监听端口。
#
# ★ 为什么要有独立端口：
#   走 fnOS 的 CGI（/cgi/ThirdParty/<app>/）时，调用 fnOS 的内部接口
#   （appcgi.netsvr.cert.* / ddns.*）要求 HMAC 签名，密钥是用户的会话密钥，
#   CGI 环境里拿不到 —— 除非再让用户填一次密码。
#
#   而 fnOS 官方认可的第三方应用（fncleankernel 8097、OpenList 等）
#   都用 ui/config 的 `type: url` 模式，浏览器直连应用自己的端口，
#   完全绕开 fnOS 的 token 校验。本应用采用同样方式。
#
# 必须与 ui/config 里的 "port" 保持一致。
UI_PORT = int(os.environ.get("DNRP_UI_PORT", "8765"))

# 禁止用户配置的低端口（与 fnOS 系统服务冲突）
RESERVED_PORTS = {
    80,
    443,
    5666,
    5667,
    16666,
    16667,
    5432,
    UI_PORT,          # UI 自己占的端口也不允许给反代规则用
}

# API 服务监听（unix socket，不占 TCP 端口）
API_SOCKET = SOCKET_PATH

# 日志保留
LOG_MAX_BYTES = 2 * 1024 * 1024

# ---------------------------------------------------------------- 工具函数


def ensure_dirs() -> None:
    """确保运行期目录存在。"""
    PKGVAR.mkdir(parents=True, exist_ok=True)


def is_reserved_port(port: int) -> bool:
    return port in RESERVED_PORTS or port < 1024


def fnos_webui_https_port() -> tuple[int, str | None]:
    """从 nginx 配置探测 fnOS WebUI 的 HTTPS 端口。

    返回 (port, host_header)。用于证书 API 的 WebSocket 连接。
    """
    # 优先读网关设置里的 https.port
    try:
        import json

        if FNOS_GATEWAY_SETTING.is_file():
            data = json.loads(FNOS_GATEWAY_SETTING.read_text(encoding="utf-8"))
            port = data.get("schema", {}).get("https", {}).get("port")
            if isinstance(port, int) and port > 0:
                return port, None
    except (OSError, ValueError):
        pass

    # 回退：读 nginx 配置里的 ssl listen
    try:
        if FNOS_NGINX_CONF.is_file():
            for raw in FNOS_NGINX_CONF.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = raw.strip()
                if not line.startswith("listen") or "ssl" not in line:
                    continue
                # listen 0.0.0.0:16667 ssl http2 default_server;
                import re

                m = re.search(r":(\d+)", line)
                if m:
                    return int(m.group(1)), None
    except OSError:
        pass

    return 16667, None
