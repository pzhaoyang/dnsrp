"""能力探测与降级（应对 fnOS 升级导致内部接口失效）。

★ 设计目标：**永不假设内部接口存在**

  本应用依赖 fnOS 的三类资源，稳定性从高到低：
    1. 静态文件（证书登记表 + 证书文件）  —— 标准路径，最稳
    2. 内部 WebSocket API（appcgi.netsvr.*）—— 未公开，可能随版本变化
    3. PostgreSQL 表                       —— 官方未授权，不用

  第 2 类随时可能失效。所以这里不「假设它存在」，而是：
    * 启动时探测一次
    * 结果缓存 + TTL（默认 10 分钟）
    * 每次调用失败时立刻标记失效，并触发热重探
    * 任何能力失效只影响对应功能，不影响其他功能

★ 版本戳

  记录探测时的 fnOS 版本。版本变了就丢弃缓存重新探测，
  这样系统升级后第一次打开界面就能看到最新状态。
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import config

log = logging.getLogger("dnrp.capabilities")

# 探测结果缓存有效期（秒）
CACHE_TTL = int(os.environ.get("DNRP_CAP_TTL", "600"))


@dataclass
class Capability:
    """单个能力的状态。"""

    key: str
    ok: bool = False
    # 失效原因（给用户看的中文说明）
    reason: str = ""
    # 失效时建议用户去哪里操作
    fallback_hint: str = ""
    # 探测时间戳
    checked_at: float = 0.0
    # 是否曾经可用（用于「之前能用，现在坏了」的提示）
    was_ok: bool = False

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if d["checked_at"]:
            d["checked_at_human"] = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(d["checked_at"]))
        return d


@dataclass
class CapabilitySet:
    """当前 fnOS 环境支持哪些能力。"""

    # fnOS 版本（用于检测升级）
    fnos_version: str = ""
    # 上次探测时间
    checked_at: float = 0.0
    # 各项能力
    items: dict[str, Capability] = field(default_factory=dict)

    def get(self, key: str) -> Capability:
        return self.items.get(key, Capability(key=key))

    def ok(self, key: str) -> bool:
        return self.get(key).ok

    def to_dict(self) -> dict[str, Any]:
        return {
            "fnosVersion": self.fnos_version,
            "checkedAt": self.checked_at,
            "checkedAtHuman": (
                time.strftime("%Y-%m-%d %H:%M:%S",
                              time.localtime(self.checked_at))
                if self.checked_at else ""
            ),
            "items": {k: v.to_dict() for k, v in self.items.items()},
        }


# 能力定义：key -> (中文名, 失效时的兜底提示)
CAPABILITY_SPEC: dict[str, tuple[str, str]] = {
    "cert.read": (
        "读取证书",
        "证书文件在 /usr/trim/var/trim_connect/ssls，"
        "若路径变化请反馈。",
    ),
    "cert.issue": (
        "签发证书",
        "请到「系统设置 → 证书管理」手动申请。",
    ),
    "ddns.read": (
        "读取 DDNS",
        "请到「系统设置 → 远程访问 → DDNS」查看。",
    ),
    "ddns.write": (
        "管理 DDNS",
        "请到「系统设置 → 远程访问 → DDNS」增删改。",
    ),
    "fnos.session": (
        "飞牛 OS 会话",
        "请到「设置」里检查用户名和密码是否正确。",
    ),
}


# ---------------------------------------------------------------- 全局缓存

_CACHE: CapabilitySet | None = None
_CACHE_AT: float = 0.0
_CACHE_VERSION: str = ""


def _get_globals() -> tuple[CapabilitySet | None, float, str]:
    return _CACHE, _CACHE_AT, _CACHE_VERSION


def _set_globals(cs: CapabilitySet | None, at: float, ver: str) -> None:
    global _CACHE, _CACHE_AT, _CACHE_VERSION
    _CACHE, _CACHE_AT, _CACHE_VERSION = cs, at, ver


def detect_fnos_version() -> str:
    """读 fnOS 版本。读不到就返回空串（不影响功能）。"""
    # 优先 /etc/trim/version 之类的文件
    for p in (
        "/usr/trim/etc/version",
        "/etc/trim/version",
        "/usr/trim/version",
    ):
        try:
            txt = Path(p).read_text(encoding="utf-8", errors="replace").strip()
            if txt:
                # 文件里可能有多行，取第一行有数字的
                for line in txt.splitlines():
                    line = line.strip()
                    if line and any(c.isdigit() for c in line):
                        return line[:64]
        except OSError:
            continue

    # 退路：内核/发行版标识
    try:
        v = Path("/etc/os-release").read_text(
            encoding="utf-8", errors="replace")
        for line in v.splitlines():
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')[:64]
    except OSError:
        pass

    return ""


def _probe_cert_read() -> tuple[bool, str]:
    """探测证书是否可读（静态文件，最稳的一层）。"""
    reg = Path(config.FNOS_CERT_REGISTRY)
    if not reg.is_file():
        return False, f"证书登记表不存在：{reg}"

    try:
        entries = config_entries_ok(reg)
    except OSError as exc:
        return False, f"读取证书登记表失败：{exc}"

    if not entries:
        return False, "证书登记表为空或格式无法解析"

    root = Path(config.FNOS_SSL_ROOT)
    if not root.is_dir():
        return False, f"证书目录不存在：{root}"

    # 抽查前 3 个证书文件
    from .proxy import certs as cert_mod

    tried = 0
    readable = 0
    for entry in cert_mod.load_registry():
        if tried >= 3:
            break
        tried += 1
        p = Path(entry.cert_path)
        try:
            with p.open("rb") as fh:
                head = fh.read(32)
            if b"BEGIN CERTIFICATE" in head or head:
                readable += 1
        except OSError as exc:
            log.debug("证书不可读 %s: %s", p, exc)

    if tried and readable == 0:
        return False, (
            "证书文件不可读。应用用户需要加入 www-data 组："
            "sudo usermod -aG www-data dnsrp"
        )

    return True, ""


def config_entries_ok(path: Path) -> list[Any]:
    """校验登记表能解析成列表。"""
    import json

    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # 某些版本可能是 {"certs": [...]}
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


def _probe_session() -> tuple[bool, str]:
    """探测 fnOS WebSocket 会话是否可用（用当前请求凭证）。"""
    # 这里只检查 webui 端口可连，真正签名由调用方做
    try:
        from .certs import ws_client

        port = ws_client.detect_webui_port()
        if not port:
            return False, "无法确定 fnOS WebUI 端口"
        import socket as _s

        with _s.create_connection(("127.0.0.1", port), timeout=3):
            return True, ""
    except OSError as exc:
        return False, f"无法连接 fnOS WebUI：{exc}"


def _probe_cert_issue(cred: Any) -> tuple[bool, str]:
    """探测证书签发能力。

    ★ 认证方式：
      fnOS 的 secret 是**连接级绑定**的 —— 从浏览器 localStorage 拿到的
      secret 放到后端新建的连接上用，会报 errno=65534 验签失败。
      所以不能用「借用网页会话」这条路。

      正确做法：用本应用保存的用户名密码新建会话。
      这样 secret 与连接同源，验签必然通过。
    """
    cli = _open_session()
    if cli is None:
        return False, "尚未配置飞牛 OS 账号，请到「设置」里填写用户名和密码"

    try:
        rows = cli.call("appcgi.netsvr.cert.list", timeout=25)
        if not isinstance(rows, list):
            return False, "cert.list 返回格式异常（接口可能已变更）"
        return True, ""
    except Exception as exc:               # noqa: BLE001
        msg = str(exc)
        if "no register handler" in msg or "10000002" in msg:
            return False, "当前 fnOS 版本不再提供 cert.list 接口"
        if "65534" in msg:
            return False, "会话验签失败（凭据可能已失效，请重新保存密码）"
        return False, f"调用 cert.list 失败：{msg[:120]}"
    finally:
        _close(cli)


def _probe_ddns(cred: Any) -> tuple[bool, str]:
    """探测 DDNS 能力（同样用保存的凭据建会话）。"""
    cli = _open_session()
    if cli is None:
        return False, "尚未配置飞牛 OS 账号，请到「设置」里填写用户名和密码"

    try:
        data = cli.call("appcgi.netsvr.ddns.record.list", timeout=25)
        if isinstance(data, dict):
            data = data.get("list")
        if not isinstance(data, list):
            return False, "ddns.record.list 返回格式异常（接口可能已变更）"
        return True, ""
    except Exception as exc:               # noqa: BLE001
        msg = str(exc)
        if "no register handler" in msg or "10000002" in msg:
            return False, "当前 fnOS 版本不再提供 ddns.record.list 接口"
        if "65534" in msg:
            return False, "会话验签失败（凭据可能已失效，请重新保存密码）"
        return False, f"调用 ddns.record.list 失败：{msg[:120]}"
    finally:
        _close(cli)


# ---------------------------------------------------------------- 会话工具


def _open_session() -> Any:
    """用保存的凭据开一个 fnOS 会话。没有凭据返回 None。"""
    from .api import server as api_server

    cfg = api_server._load_fn_cfg()
    if not cfg:
        return None

    try:
        from .certs import ws_client

        cli = ws_client.FnosClient(
            host="127.0.0.1",
            port=ws_client.detect_webui_port(),
            username=cfg["user"],
            password=cfg["pass"],
            access_code=cfg.get("access_code", ""),
        )
        cli.connect()
        return cli
    except Exception as exc:               # noqa: BLE001
        log.warning("建立 fnOS 会话失败: %s", exc)
        return None


def _close(cli: Any) -> None:
    try:
        cli.close()
    except Exception:                      # noqa: BLE001
        pass


def probe(cred: Any = None, force: bool = False) -> CapabilitySet:
    """探测当前环境支持的能力。

    ★ 带缓存：同一 fnOS 版本 + TTL 内直接返回缓存。
      版本变了强制重探（升级后立刻反映真实状态）。
    """
    global _CACHE, _CACHE_AT, _CACHE_VERSION

    ver = detect_fnos_version()
    now = time.time()

    if not force and _CACHE is not None:
        same_ver = (ver == _CACHE_VERSION)
        fresh = (now - _CACHE_AT) < CACHE_TTL
        if same_ver and fresh:
            return _CACHE
        if not same_ver and ver:
            log.info("检测到 fnOS 版本变化 %s -> %s，重新探测能力",
                     _CACHE_VERSION or "(未知)", ver)

    log.info("开始探测 fnOS 能力...")
    cs = CapabilitySet(fnos_version=ver, checked_at=now)

    # --- 1. 证书只读（静态文件，最稳） ---
    ok, why = _probe_cert_read()
    cs.items["cert.read"] = Capability(
        key="cert.read", ok=ok, reason=why,
        fallback_hint="" if ok else CAPABILITY_SPEC["cert.read"][1],
        checked_at=now,
    )

    # --- 2. fnOS 会话（用保存的凭据能否登录）---
    from .api import server as api_server

    has_cfg = bool(api_server._load_fn_cfg())
    session_ok = has_cfg
    session_why = ""
    if not has_cfg:
        session_why = "尚未配置飞牛 OS 账号，请到「设置」填写"

    cs.items["fnos.session"] = Capability(
        key="fnos.session", ok=session_ok,
        reason=session_why,
        fallback_hint="" if session_ok else CAPABILITY_SPEC["fnos.session"][1],
        checked_at=now,
    )

    # --- 3. 证书签发 ---
    ok_i, why_i = _probe_cert_issue(cred)
    cs.items["cert.issue"] = Capability(
        key="cert.issue", ok=ok_i, reason=why_i,
        fallback_hint="" if ok_i else CAPABILITY_SPEC["cert.issue"][1],
        checked_at=now,
    )

    # --- 4. DDNS 读取 ---
    ok_d, why_d = _probe_ddns(cred)
    cs.items["ddns.read"] = Capability(
        key="ddns.read", ok=ok_d, reason=why_d,
        fallback_hint="" if ok_d else CAPABILITY_SPEC["ddns.read"][1],
        checked_at=now,
    )
    # 写入能力与读取同源
    cs.items["ddns.write"] = Capability(
        key="ddns.write", ok=ok_d,
        reason=why_d,
        fallback_hint="" if ok_d else CAPABILITY_SPEC["ddns.write"][1],
        checked_at=now,
    )

    # 保留「曾经可用」标记，便于提示「升级后失效」
    if _CACHE is not None:
        for k, cap in cs.items.items():
            old = _CACHE.items.get(k)
            if old is not None and old.ok:
                cap.was_ok = True

    _CACHE = cs
    # ★ 用「探测完成时刻」而非开始时刻写回缓存。
    #   探测可能耗时 25s（如 cert.issue 登录超时），若用旧的 now，
    #   期间 invalidate() 把 _CACHE_AT 置 0 后会被这里覆盖成旧值，
    #   导致失效状态被错误地当成"仍然新鲜"持续整个 TTL。
    _CACHE_AT = time.time()
    _CACHE_VERSION = ver

    log.info(
        "能力探测完成：%s",
        ", ".join(f"{k}={'OK' if v.ok else 'FAIL'}" for k, v in cs.items.items()),
    )
    return cs


def invalidate(key: str = "", reason: str = "") -> None:
    """标记某个能力失效（运行时调用失败时用）。

    下次 probe() 会重新探测。这里不直接改缓存，
    而是缩短缓存有效期，让下一个请求触发重探。
    """
    global _CACHE_AT

    if key and _CACHE is not None:
        cap = _CACHE.items.get(key)
        if cap is not None:
            # ★ 只有"之前确实可用过"才标记 was_ok。
            #   原写法 `cap.was_ok or True` 恒为 True，会让从未成功的
            #   能力也被误报成"升级后失效"。
            if cap.ok:
                cap.was_ok = True
            cap.ok = False
            cap.reason = reason or cap.reason
            log.warning("能力 %s 标记为失效: %s", key, reason)

    # 让缓存立即过期
    _CACHE_AT = 0.0


def reset() -> None:
    """清空缓存（测试或升级后手动调用）。"""
    _set_globals(None, 0.0, "")


def summary() -> dict[str, Any]:
    """给 /api/health 之类的轻量摘要。"""
    cs, _, _ = _get_globals()
    if cs is None:
        return {"probed": False}
    return {
        "probed": True,
        "fnosVersion": cs.fnos_version,
        "ok": {k: v.ok for k, v in cs.items.items()},
    }
