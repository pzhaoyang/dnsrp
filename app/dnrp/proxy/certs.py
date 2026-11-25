"""fnOS 证书系统的只读访问层。

设计要点：
  * 反代取证书**只认网络登记表** network_gateway_cert.conf，
    不遍历目录、不猜文件名（fnOS 的文件名有 4 种且每个版本都可能变）。
  * 证书优先级与 fnOS 一致：精确匹配 > 泛域名 > 父域回退。
  * 只读，绝不修改 fnOS 的证书文件。
"""

from __future__ import annotations

import hashlib
import json
import logging
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .. import config

log = logging.getLogger("dnrp.proxy.certs")


@dataclass
class CertEntry:
    """一张证书在 fnOS 登记表里的条目。"""

    host: str
    cert_path: str
    key_path: str

    def readable(self) -> bool:
        try:
            return Path(self.cert_path).is_file() and Path(self.key_path).is_file()
        except OSError:
            return False


@dataclass
class CertInfo:
    """证书的解析信息（用于 UI 展示与过期判断）。"""

    host: str
    cert_path: str
    key_path: str
    subject: str = ""
    san: list[str] = field(default_factory=list)
    issuer: str = ""
    not_before: float = 0.0
    not_after: float = 0.0
    key_type: str = ""
    error: str = ""

    @property
    def days_left(self) -> int:
        if not self.not_after:
            return 0
        return int((self.not_after - time.time()) // 86400)

    @property
    def expired(self) -> bool:
        return bool(self.not_after) and self.not_after < time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "certPath": self.cert_path,
            "keyPath": self.key_path,
            "subject": self.subject,
            "san": self.san,
            "issuer": self.issuer,
            "notBefore": self.not_before,
            "notAfter": self.not_after,
            "daysLeft": self.days_left,
            "expired": self.expired,
            "keyType": self.key_type,
            "error": self.error,
        }


# ---------------------------------------------------------------- 登记表读取


def load_registry() -> list[CertEntry]:
    """读取 fnOS 证书登记表。

    返回顺序保持 fnOS 的原始顺序，但把 fallback 排到最后 ——
    fallback 是兜底证书，不应抢在域名证书前面。
    """
    path = config.FNOS_CERT_REGISTRY
    raw: Any
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        return []

    if not isinstance(raw, list):
        return []

    entries: list[CertEntry] = []
    fallback: CertEntry | None = None

    for item in raw:
        if not isinstance(item, dict):
            continue
        host = str(item.get("host") or "").strip()
        cert = str(item.get("cert") or "").strip()
        key = str(item.get("key") or "").strip()
        if not host or not cert or not key:
            continue
        entry = CertEntry(host=host, cert_path=cert, key_path=key)
        if host == "fallback":
            fallback = entry
        else:
            entries.append(entry)

    if fallback:
        entries.append(fallback)
    return entries


# ---------------------------------------------------------------- 域名匹配


def _match_priority(entry_host: str, domain: str) -> int:
    """返回匹配优先级，数字越小越优先；0 表示不匹配。

    与 fnOS 的语义保持一致：
      1. 精确匹配         app.example.com == app.example.com
      2. 泛域名匹配       *.example.com 覆盖 app.example.com
      3. fallback         兜底
    """
    if entry_host == "fallback":
        return 9

    if entry_host == domain:
        return 1

    if entry_host.startswith("*."):
        suffix = entry_host[1:]          # ".example.com"
        # 通配符只覆盖一级：a.b.example.com 不匹配 *.example.com 的严格语义，
        # 但 fnOS 实际是「后缀匹配」，这里跟随 fnOS 行为。
        if domain.endswith(suffix) and domain.count(".") >= entry_host.count("."):
            return 2

    return 0


def match_certs(domain: str, entries: list[CertEntry] | None = None) -> list[CertEntry]:
    """按域名找出所有可用的证书，按优先级排序。"""
    if entries is None:
        entries = load_registry()

    scored: list[tuple[int, int, CertEntry]] = []
    for idx, e in enumerate(entries):
        p = _match_priority(e.host, domain)
        if p:
            scored.append((p, idx, e))

    scored.sort(key=lambda t: (t[0], t[1]))
    return [e for _, _, e in scored]


def pick_cert(domain: str, entries: list[CertEntry] | None = None) -> CertEntry | None:
    """挑一张最适合该域名的证书。"""
    found = match_certs(domain, entries)
    for e in found:
        if e.readable():
            return e
    return found[0] if found else None


# ---------------------------------------------------------------- 证书解析


def parse_cert(entry: CertEntry) -> CertInfo:
    """解析证书文件，取 subject / SAN / 有效期 / 签发者。

    fnOS 的 fullchain.crt 是「叶子 + 中间证书」拼接（实测 7 块），
    openssl x509 默认只读第一块，正好是叶子证书，符合预期。
    """
    info = CertInfo(host=entry.host, cert_path=entry.cert_path, key_path=entry.key_path)

    path = Path(entry.cert_path)
    if not path.is_file():
        info.error = "证书文件不存在"
        return info

    # 可读性检查（package 用户需要 www-data 组）
    try:
        with path.open("rb") as fh:
            head = fh.read(64)
    except PermissionError:
        info.error = "无读取权限（需加入 www-data 组）"
        return info
    except OSError as exc:
        info.error = f"读取失败: {exc}"
        return info

    if b"-----BEGIN CERTIFICATE-----" not in head:
        info.error = "不是 PEM 证书"
        return info

    parsed = _parse_with_openssl(entry.cert_path)
    if parsed.get("error"):
        info.error = parsed["error"]
        return info

    info.subject = parsed.get("subject", "")
    info.issuer = parsed.get("issuer", "")
    info.not_before = parsed.get("notBefore", 0.0)
    info.not_after = parsed.get("notAfter", 0.0)
    info.san = parsed.get("san", [])
    info.key_type = parsed.get("keyType", "")
    return info


def _parse_with_openssl(cert_path: str) -> dict[str, Any]:
    """用 openssl 解析证书（fnOS 自带 openssl 3.0）。"""
    import subprocess

    result: dict[str, Any] = {}

    def run(args: list[str]) -> str:
        try:
            p = subprocess.run(
                args, capture_output=True, text=True, timeout=5, check=False
            )
            return p.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    # subject / issuer / 有效期
    text = run(["openssl", "x509", "-in", cert_path, "-noout",
                "-subject", "-issuer", "-dates", "-nameopt", "RFC2253"])
    if not text:
        result["error"] = "openssl 无法读取证书"
        return result

    for line in text.splitlines():
        line = line.strip()
        if line.startswith("subject="):
            result["subject"] = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            result["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("notBefore="):
            result["notBefore"] = _parse_time(line[len("notBefore="):].strip())
        elif line.startswith("notAfter="):
            result["notAfter"] = _parse_time(line[len("notAfter="):].strip())

    # SAN
    san_text = run(["openssl", "x509", "-in", cert_path, "-noout", "-ext", "subjectAltName"])
    sans: list[str] = []
    for line in san_text.splitlines():
        line = line.strip()
        if line.startswith("DNS:"):
            sans.extend(s.strip()[len("DNS:"):] for s in line.split(",") if s.strip().startswith("DNS:"))
        elif "DNS:" in line:
            for part in line.split(","):
                part = part.strip()
                if part.startswith("DNS:"):
                    sans.append(part[len("DNS:"):])
    result["san"] = [s for s in sans if s]

    # 公钥类型
    pkey = run(["openssl", "x509", "-in", cert_path, "-noout", "-text"])
    if "id-ecPublicKey" in pkey or "EC Public Key" in pkey:
        result["keyType"] = "ECC"
    elif "rsaEncryption" in pkey or "Public-Key: (2048 bit)" in pkey or "RSA Public-Key" in pkey:
        result["keyType"] = "RSA"

    return result


def _parse_time(text: str) -> float:
    """解析 openssl 的时间字符串。

    openssl 的 -dates 输出形如：
        Nov  2 07:45:11 2026 GMT
        Jan 31 07:45:10 2027 GMT
    注意日期可能是单数字（"Nov  2"），%d 能接受前导空格，但
    strptime 对双空格敏感，先归一化空白。
    """
    import calendar
    import re
    import time as _time

    s = re.sub(r"\s+", " ", text.strip())
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            return float(calendar.timegm(_time.strptime(s, fmt)))
        except ValueError:
            continue
    return 0.0


# ---------------------------------------------------------------- 对外接口


def _fnos_cert_info() -> dict[str, dict]:
    """从 fnOS 证书库拿「域名 -> 证书信息」映射。

    为什么要这一步：
      network_gateway_cert.conf 是「域名 → 证书文件路径」的映射，
      里面**没有 fnOS 的证书 id**，也没有续签标志。
      而删除/续期接口需要 id，UI 需要 renewal 判断能否续期。

    映射方式：用证书文件所在目录的域名去匹配 cert.list 里的 domain。
      证书路径形如 /usr/trim/var/trim_connect/ssls/<domain>/<ts>/fullchain.crt
                                          └──────┬──────┘
                                            这就是 cert 表的 domain 字段

    ★ 自动续签的三种来源（2026-11-25 实测）：

      | source   | renewal | issuedBy      | 谁来续                  |
      |----------|---------|---------------|-------------------------|
      | upload   | 1       | YE1/YR1 (LE)  | fnOS ACME 定时任务      |
      | trim     | 0       | YR1 (LE)      | FN Connect 服务         |
      | system   | 0       | fnOS          | fnOS 定期重签自签证书   |

      注意 FN Connect 那张（source=trim）**renewal 是 0**，
      自签兜底（source=system）也是 0，它们都不走 cert_renew 表，
      但都会由 fnOS 自动续期。所以判断「会不会自动续」不能只看 renewal。

    拿不到就返回空 dict —— 删除/续期按钮显示为不可用，不影响其他功能。
    """
    out: dict[str, dict] = {}

    cfg = None
    try:
        from ..api import server as api_server
        cfg = api_server._load_fn_cfg()
    except Exception:                      # noqa: BLE001
        return out
    if not cfg:
        return out

    try:
        from ..certs import ws_client
        from ..certs import manager as cert_mgr

        cli = ws_client.FnosClient(
            host="127.0.0.1",
            port=ws_client.detect_webui_port(),
            username=cfg["user"],
            password=cfg["pass"],
            access_code=cfg.get("access_code", ""),
        )
        cli.connect()
        try:
            for row in cert_mgr.list_certs(cli):
                dom = str(row.get("domain") or "")
                cid = row.get("id")
                if not dom or cid is None:
                    continue

                renewal = int(row.get("renewal") or 0)
                source = str(row.get("source") or "")

                # 谁会续这张证书（2026-11-25 实测）：
                #
                #  | source   | renewal | issuedBy | 谁来续                    |
                #  |----------|---------|----------|---------------------------|
                #  | upload   | 1       | YE1 (LE) | fnOS ACME 定时任务        |
                #  | trim     | 0       | YR1 (LE) | FN Connect 服务           |
                #  | system   | 0       | fnOS     | fnOS 定期重签自签证书     |
                #
                # system 那张自签证书 renewal=0、也没有 cert_renew 记录，
                # 但它有 last_renew_time 且 ≈ valid_from（每约 3 个月重签一次），
                # 说明 fnOS 会自动重新生成它 —— 所以也要算自动续签。
                if renewal == 1:
                    renew_by = "acme"       # fnOS 的 ACME 定时任务
                elif source == "trim":
                    renew_by = "fnconnect"  # FN Connect 服务
                elif source == "system":
                    renew_by = "system"     # fnOS 定期重签自签证书
                else:
                    renew_by = ""           # 用户手动导入，不续

                out[dom] = {
                    "id": int(cid),
                    # renewal=1 表示有证书续签配置，可以手动续期
                    "renewal": renewal,
                    "des": str(row.get("des") or ""),
                    "source": source,
                    "issuedBy": str(row.get("issuedBy") or ""),
                    "autoRenew": bool(renew_by),
                    "renewBy": renew_by,
                }
        finally:
            cli.close()
    except Exception as exc:               # noqa: BLE001
        log.info("读取 fnOS 证书信息失败（删除/续期按钮将不可用）: %s", exc)

    return out


def _dom_from_cert_path(path: str) -> str:
    """从证书文件路径里取出域名。

    /usr/trim/var/trim_connect/ssls/nas.example.com/1793609016/fullchain.crt
                                       └────── 第 3 段 ──────┘
    """
    parts = path.split("/")
    try:
        i = parts.index("ssls")
        return parts[i + 1] if i + 1 < len(parts) else ""
    except ValueError:
        return ""


def _looks_like_fnconnect(d: dict[str, Any]) -> bool:
    """判断是不是 FN Connect 专属证书。

    FN Connect 是飞牛官方的远程访问通道，它会给设备分配
    `<设备名>.fnos.net` 这样的域名，并单独签一张证书。

    特征：
      * 覆盖域名以 `.fnos.net` 结尾
      * 或证书目录/主域名本身就是 *.fnos.net
      * 或备注里含 "FN Connect" / "fnos.net"

    这类证书用户一般用不到（除非真的在用 FN Connect 外网访问），
    列在证书页里属于噪音。
    """
    doms = [str(x).lower() for x in (d.get("coveredDomains") or [])]
    prim = str(d.get("primaryDomain") or "").lower()
    cert_dir = str(d.get("certDir") or "").lower()
    desc = str(d.get("desc") or "").lower()

    if any(x.endswith(".fnos.net") or x == "fnos.net" for x in doms):
        return True
    if prim.endswith(".fnos.net") or prim == "fnos.net":
        return True
    if cert_dir.endswith(".fnos.net"):
        return True
    if "fn connect" in desc or "fnos.net" in desc:
        return True

    return False


def list_all_certs() -> list[dict[str, Any]]:
    """列出登记表里所有证书及其解析信息（UI 用）。

    ★ 按「证书实体」聚合，而不是按「域名映射」展开。

    为什么这样改：
      fnOS 的 network_gateway_cert.conf 是**域名 → 证书文件**的映射表。
      一张多 SAN 证书会被 7 个域名同时引用，展开后就会显示 7 条，
      但 fnOS「设置 → 证书管理」里只算 1 张证书 —— 用户会觉得对不上。

      所以这里按证书文件路径去重，一张证书聚合出它覆盖的域名列表，
      与 fnOS 设置页的口径一致（3 张证书）。
    """
    entries = load_registry()

    # 拿 fnOS 证书 id（失败则为空，删除按钮不可用但不影响展示）
    info_map = _fnos_cert_info()

    # 按证书文件路径聚合：cert_path -> {hosts: [...], entry: CertEntry}
    groups: dict[str, dict[str, Any]] = {}
    order: list[str] = []

    for entry in entries:
        key = entry.cert_path
        if key not in groups:
            groups[key] = {"entry": entry, "hosts": []}
            order.append(key)
        groups[key]["hosts"].append(entry.host)

    out: list[dict[str, Any]] = []
    for path in order:
        g = groups[path]
        info = parse_cert(g["entry"])
        d = info.to_dict()

        hosts = g["hosts"]
        # fallback 是兜底证书，单独标记
        is_fallback = any(h == "fallback" for h in hosts)
        d["isFallback"] = is_fallback
        # 覆盖的域名（排除 fallback 占位）
        d["coveredDomains"] = [h for h in hosts if h != "fallback"]
        d["domainCount"] = len(d["coveredDomains"])

        # fnOS 证书信息：用证书目录名去查
        cert_dir = _dom_from_cert_path(path)
        info_row = info_map.get(cert_dir) or {}
        d["certId"] = info_row.get("id")
        d["renewal"] = info_row.get("renewal", 0)
        d["certDir"] = cert_dir
        # ★ 自动续签：不能只看 renewal —— FN Connect 那张 renewal=0
        #   但确实会被 FN Connect 服务自动续期（见 _fnos_cert_info 说明）
        d["autoRenew"] = bool(info_row.get("autoRenew"))
        d["renewBy"] = info_row.get("renewBy", "")
        d["certSource"] = info_row.get("source", "")
        d["issuedBy"] = info_row.get("issuedBy", "") or d.get("issuer", "")

        # ★ 标记「系统内置证书」，默认在 UI 隐藏
        #
        #   两类：
        #     1. fnOS 自签兜底证书（CN=fnOS，fallback 用）
        #     2. FN Connect 专属证书（CN=nas.fnos.net，fnOS 远程访问用）
        #
        #   它们不是用户自己申请的，混在证书列表里只会干扰。
        #   但仍然要保留数据（反代 SNI 需要用它兜底），
        #   所以这里只打标记，由前端决定是否显示。
        d["isSystemCert"] = bool(is_fallback or _looks_like_fnconnect(d))

        # 主域名：从 subject 里取 CN 的值。
        # subject 形如 "CN=nas.example.com" 或
        # "O=fnOS,CN=fnOS"（openssl 的 RFC2253 输出顺序可能把 O 放前面）。
        # 所以不能简单地 replace("CN=")，要按逗号分段找 CN。
        primary = ""
        for part in (info.subject or "").split(","):
            part = part.strip()
            if part.startswith("CN="):
                primary = part[3:].strip()
                break
        if not primary:
            # 退路：第一个覆盖域名，或 "兜底证书"
            primary = d["coveredDomains"][0] if d["coveredDomains"] else "兜底证书"
        d["primaryDomain"] = primary

        out.append(d)

    # 排序：正常证书在前（按域名数降序），fallback 最后
    out.sort(key=lambda x: (x["isFallback"], -x["domainCount"]))
    return out


def _cert_fingerprint(path: str) -> tuple[float, int, str]:
    """证书/密钥文件的轻量指纹：(mtime, size, 前 256 字节 sha256 前 16 位)。

    单纯 mtime 不可靠：秒级精度、原子替换保留 mtime、NTP 回拨
    都可能让续期后的新证书被旧缓存挡住。加 size 和内容前缀后，
    除非攻击者刻意构造，否则内容一变指纹必变。
    """
    try:
        st = Path(path).stat()
        with open(path, "rb") as fh:
            head = fh.read(256)
        digest = hashlib.sha256(head).hexdigest()[:16]
        return (st.st_mtime, st.st_size, digest)
    except OSError:
        return (0.0, 0, "")


def build_ssl_context_loader():
    """构造一个「按 SNI 动态加载证书」的 SSLContext。

    返回 (context, resolve)。

    ★ 关键实现细节（踩过的坑）：
      Python 的 `SSLObject.context` 是**只读属性**，直接在回调里
      `sslobj.context.load_cert_chain(...)` 修改的是**共享上下文**，
      会导致并发连接互相串证书（实测：第一个请求拿到默认证书，
      第二个请求拿到上一个域名的证书）。

      正确做法：在回调里为每个连接**新建一个 SSLContext** 并赋值给
      `sslobj.context`。这样每个连接有独立上下文，互不干扰。
      证书链仍用 (path, mtime) 缓存，避免每次握手都读盘。
    """
    base = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    base.minimum_version = ssl.TLSVersion.TLSv1_2
    base.options |= ssl.OP_NO_COMPRESSION

    # 缓存：servername -> (cert_path, key_path, cert_mtime, key_mtime)
    # servername -> (cert_path, key_path, cert_fp, key_fp)
    cache: dict[str, tuple[str, str, tuple, tuple]] = {}
    # servername -> (SSLContext, cert_fp, key_fp)
    ctx_cache: dict[str, tuple[ssl.SSLContext, tuple, tuple]] = {}

    def resolve(servername: str) -> tuple[str, str] | None:
        entry = pick_cert(servername)
        if not entry:
            return None
        cfp = _cert_fingerprint(entry.cert_path)
        kfp = _cert_fingerprint(entry.key_path)
        if cfp == (0.0, 0, "") or kfp == (0.0, 0, ""):
            return None

        cached = cache.get(servername)
        if cached and cached[2] == cfp and cached[3] == kfp:
            return cached[0], cached[1]

        cache[servername] = (entry.cert_path, entry.key_path, cfp, kfp)
        # 指纹变了，作废该域名的 context（关键：续期后不会再用旧证书）
        ctx_cache.pop(servername, None)
        return entry.cert_path, entry.key_path

    def make_ctx(servername: str, cert_path: str, key_path: str,
                 cfp: tuple, kfp: tuple) -> ssl.SSLContext | None:
        try:
            new_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            new_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            new_ctx.options |= ssl.OP_NO_COMPRESSION
            new_ctx.load_cert_chain(cert_path, key_path)
        except (ssl.SSLError, OSError):
            return None
        ctx_cache[servername] = (new_ctx, cfp, kfp)
        return new_ctx

    def sni_callback(
        sslobj: ssl.SSLObject, servername: str | None, _ctx: ssl.SSLContext
    ) -> None:
        """握手时按 SNI 给这个连接换一份独立上下文。"""
        if not servername:
            return

        pair = resolve(servername)
        if not pair:
            return
        cert_path, key_path = pair

        cfp = _cert_fingerprint(cert_path)
        kfp = _cert_fingerprint(key_path)
        if cfp == (0.0, 0, "") or kfp == (0.0, 0, ""):
            return

        cached = ctx_cache.get(servername)
        if cached and cached[1] == cfp and cached[2] == kfp:
            sslobj.context = cached[0]
            return

        new_ctx = make_ctx(servername, cert_path, key_path, cfp, kfp)
        if new_ctx is not None:
            sslobj.context = new_ctx
        # 失败则保持默认上下文（默认证书），不中断握手

    base.set_servername_callback(sni_callback)
    return base, resolve


def load_default_chain(ctx: ssl.SSLContext) -> bool:
    """给 SSLContext 预载一张默认证书（fallback）。

    TLS 握手在 SNI 回调之前需要一个默认证书，否则直接失败。
    """
    entries = load_registry()
    # 优先用 fallback
    candidates = [e for e in entries if e.host == "fallback"] + entries
    for e in candidates:
        if not e.readable():
            continue
        try:
            ctx.load_cert_chain(e.cert_path, e.key_path)
            return True
        except (ssl.SSLError, OSError):
            continue
    return False
