"""dnsrp 的 HTTP API（跑在 unix socket 上）。

刻意不用第三方框架：只依赖标准库，用 asyncio 手写一个极简路由器。
理由：
  * 依赖为零，fnOS 自带 Python 即可运行
  * 路由数量可控（< 20 个）
  * 便于和反代引擎共用同一个事件循环
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Awaitable, Callable

from .. import auth, capabilities, config, store
from ..auth import Credentials
from ..proxy import certs as cert_mod
from ..proxy import engine as engine_mod
from ..proxy.engine import Rule

log = logging.getLogger("dnrp.api")

Handler = Callable[["Request"], Awaitable["Response"]]

# ---------------------------------------------------------------- 凭据存储
#
# fnOS 的登录凭据（用户名/密码/访问码）存在 PKGVAR/fnos.json，
# 权限 0600，只有本应用用户可读。
#
# ★ 为什么不存密码明文到数据库：
#   SQLite 里有规则、DDNS 映射等业务数据，密码单独放文件更便于
#   单独设置权限、单独删除、单独审计。
#
# ★ 为什么必须存密码：
#   证书签发和 DDNS 管理都要调 fnOS 的 WebSocket API，
#   而 fnOS 的会话是「连接级」的（实测：secret/token 拿到新连接上
#   都报 errno 65534），所以每次调用都要重新登录。
#   2FA 验证码 30 秒过期，不能存，只能在签证书时现输。

_FNOS_CFG_CACHE: dict[str, Any] | None = None


def _fn_cfg_path():
    return config.PKGVAR / "fnos.json"


def _load_fn_cfg() -> dict[str, str] | None:
    """读取 fnOS 登录凭据。"""
    global _FNOS_CFG_CACHE
    if _FNOS_CFG_CACHE is not None:
        return _FNOS_CFG_CACHE or None

    p = _fn_cfg_path()
    if not p.is_file():
        _FNOS_CFG_CACHE = {}
        return None

    try:
        import json as _json

        data = _json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _FNOS_CFG_CACHE = {}
        return None

    if not isinstance(data, dict) or not data.get("user") or not data.get("pass"):
        _FNOS_CFG_CACHE = {}
        return None

    _FNOS_CFG_CACHE = {
        "user": str(data["user"]),
        "pass": str(data["pass"]),
        "access_code": str(data.get("access_code") or ""),
    }
    return _FNOS_CFG_CACHE


def _save_fn_cfg(user: str, password: str, access_code: str = "") -> None:
    """保存 fnOS 登录凭据（0600）。"""
    global _FNOS_CFG_CACHE
    import json as _json
    import os as _os

    config.ensure_dirs()
    p = _fn_cfg_path()
    tmp = p.with_suffix(".tmp")
    payload = {"user": user, "pass": password}
    if access_code:
        payload["access_code"] = access_code

    tmp.write_text(_json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    try:
        _os.chmod(tmp, 0o600)
    except OSError:
        pass
    tmp.replace(p)
    _FNOS_CFG_CACHE = {
        "user": user, "pass": password, "access_code": access_code,
    }


def _fn_client(cred: "Credentials | None" = None, access_code: str = ""):
    """构造一个已登录的 fnOS 客户端。调用方负责 close()。

    ★ 认证方式：**用本应用保存的用户名密码新建会话**。

    为什么不用浏览器的网页会话（Cookie / localStorage 里的 secret）：
      已实测（2026-11-23），fnOS 的 secret 是**连接级绑定**的 ——
      从浏览器拿到的 secret 放到后端新建的连接上用，
      服务端报 errno=65534「验签失败（会话未绑定）」。
      这是 fnOS 防止跨进程复用会话的设计，绕不过去。

    所以只能用密码登录：secret 与连接同源，验签必然通过。
    代价是用户需要保存一次账号密码（存本机，0600）。
    """
    from ..certs import ws_client

    cfg = _load_fn_cfg()
    if not cfg:
        raise RuntimeError(
            "尚未配置飞牛 OS 账号。\n"
            "请到「设置」里填写用户名和密码（只需一次）。"
        )

    cli = ws_client.FnosClient(
        host="127.0.0.1",
        port=ws_client.detect_webui_port(),
        username=cfg["user"],
        password=cfg["pass"],
        access_code=access_code or cfg.get("access_code", ""),
    )
    cli.connect()
    return cli


def _ddns_err(msg: str) -> str:
    """把 DDNS 底层异常翻译成用户能看懂的说明。"""
    if "no register handler" in msg or "10000002" in msg:
        return (
            "当前飞牛 OS 版本不再提供 DDNS 接口，本应用无法管理 DDNS。\n"
            "请到「系统设置 → 远程访问 → DDNS」操作。\n"
            f"（技术细节: {msg[:100]}）"
        )
    if "timeout" in msg.lower():
        return "调用飞牛 OS 超时，请稍后重试。"
    if "no secret" in msg.lower() or "会话" in msg:
        return (
            "需要飞牛 OS 登录会话才能管理 DDNS。\n"
            "请确认你是在飞牛 OS 网页里打开本应用。"
        )
    return f"DDNS 操作失败: {msg[:180]}"


def seed_validate(domains: list[str]) -> str:
    """域名校验（延迟导入，避免循环依赖）。"""
    from ..certs import seed as seed_mod

    return seed_mod.validate_domains(domains)


class Request:
    """一个已解析的 API 请求。"""

    def __init__(self, method: str, path: str, query: dict[str, str],
                 body: bytes, headers: dict[str, str]) -> None:
        self.method = method
        self.path = path
        self.query = query
        self.body = body
        self.headers = headers
        self.params: dict[str, str] = {}

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except (UnicodeDecodeError, ValueError):
            return {}

    def credentials(self) -> "Credentials":
        """从请求头解析 fnOS 会话凭证。

        ★ 两种来源都要支持（取决于飞牛 OS 的认证模式）：

        1. **X-Dnrp-Token / X-Dnrp-Secret**
           前端 JS 从 localStorage 读出来，主动放进来的。
           这是 legacy 模式下的唯一来源 —— 因为 legacy 模式
           凭证只存在 localStorage，浏览器的 Cookie 里没有。

        2. **Cookie**
           ticket-cookie 模式下浏览器会自动带，CGI 通过
           HTTP_COOKIE 读到，index.cgi 原样转发。

        用户能打开本应用界面，说明必然已经登录过，
        凭证一定存在于上述某个位置。
        """
        # ---- 来源 1：前端主动传的（localStorage）----
        token = self.headers.get("x-dnrp-token", "").strip()
        secret = self.headers.get("x-dnrp-secret", "").strip()
        device = self.headers.get("x-dnrp-device", "").strip()

        if token or secret:
            cred = Credentials(token=token, secret=secret,
                               device=device, source="localStorage")
            return cred

        # ---- 来源 2：Cookie ----
        cookie_raw = self.headers.get("cookie", "")
        if cookie_raw:
            jar = auth.parse_cookie(cookie_raw)
            cred = Credentials(
                token=jar.get("fnos-token", ""),
                secret=jar.get("fnos-Secret", ""),
                device=jar.get("fnos-device", ""),
                source="cookie",
            )
            cred.raw_cookies = jar
            if cred.has_token or cred.has_secret:
                return cred

        # ---- 来源 3：index.cgi 汇总的 JSON 头（兼容旧版）----
        raw = self.headers.get("x-dnrp-creds", "")
        return auth.parse_credentials_header(raw)


class Response:
    """一个 API 响应。"""

    def __init__(self, status: int = 200, body: Any = None,
                 content_type: str = "application/json; charset=utf-8") -> None:
        self.status = status
        self.body = body
        self.content_type = content_type

    def to_bytes(self) -> bytes:
        if self.body is None:
            return b""
        if isinstance(self.body, (dict, list)):
            return json.dumps(self.body, ensure_ascii=False).encode("utf-8")
        if isinstance(self.body, str):
            return self.body.encode("utf-8")
        return bytes(self.body)

    @classmethod
    def ok(cls, data: Any = None) -> "Response":
        return cls(200, {"ok": True, "data": data} if data is not None else {"ok": True})

    @classmethod
    def error(cls, message: str, status: int = 400) -> "Response":
        return cls(status, {"ok": False, "error": message})


class Router:
    """极简路由：支持 /api/xxx/:id 形式的路径参数。"""

    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern[str], Handler]] = []

    def add(self, method: str, pattern: str, handler: Handler) -> None:
        regex = self._compile(pattern)
        self._routes.append((method.upper(), regex, handler))

    @staticmethod
    def _compile(pattern: str) -> re.Pattern[str]:
        # /api/proxies/:id  ->  /api/proxies/(?P<id>[^/]+)
        parts = []
        for seg in pattern.strip("/").split("/"):
            if seg.startswith(":"):
                name = seg[1:]
                parts.append(f"(?P<{name}>[^/]+)")
            else:
                parts.append(re.escape(seg))
        return re.compile("^/" + "/".join(parts) + "$")

    def match(self, method: str, path: str) -> tuple[Handler, dict[str, str]] | None:
        method = method.upper()
        for m, regex, handler in self._routes:
            if m != method and not (m == "GET" and method == "HEAD"):
                continue
            hit = regex.match(path)
            if hit:
                return handler, hit.groupdict()
        return None


class ApiApp:
    """API 应用：持有反代引擎与路由表。"""

    def __init__(self, proxy: engine_mod.ProxyEngine) -> None:
        self.proxy = proxy
        self.router = Router()
        self._register()

    # ------------------------------------------------------------- 路由注册

    def _register(self) -> None:
        r = self.router
        r.add("GET",  "/api/health",            self.h_health)
        r.add("GET",  "/api/overview",          self.h_overview)
        r.add("GET",  "/api/capabilities",      self.h_capabilities)
        r.add("POST", "/api/capabilities/recheck", self.h_capabilities_recheck)

        # fnOS 凭据
        r.add("GET",  "/api/settings/fnos",     self.h_settings_get)
        r.add("PUT",  "/api/settings/fnos",     self.h_settings_put)
        r.add("POST", "/api/settings/fnos/test", self.h_settings_test)

        r.add("GET",  "/api/proxies",           self.h_proxies_list)
        r.add("POST", "/api/proxies",           self.h_proxies_create)
        r.add("PUT",  "/api/proxies/:id",       self.h_proxies_update)
        r.add("POST", "/api/proxies/:id/toggle", self.h_proxies_toggle)
        r.add("DELETE", "/api/proxies/:id",     self.h_proxies_delete)
        r.add("POST", "/api/proxies/reload",    self.h_proxies_reload)

        r.add("GET",  "/api/certs",             self.h_certs_list)
        r.add("GET",  "/api/certs/matched",     self.h_certs_matched)
        r.add("POST", "/api/certs/issue",       self.h_certs_issue)
        r.add("POST", "/api/certs/renew",       self.h_certs_renew)
        r.add("POST", "/api/certs/delete",      self.h_certs_delete)

        r.add("GET",  "/api/ddns",              self.h_ddns_list)
        r.add("GET",  "/api/ddns/fnos",         self.h_ddns_fnos_list)
        r.add("GET",  "/api/ddns/zones",        self.h_ddns_zones)
        r.add("POST", "/api/ddns",              self.h_ddns_create)
        r.add("GET",  "/api/ddns/detail",       self.h_ddns_detail)
        r.add("POST", "/api/ddns/update",       self.h_ddns_update)
        r.add("DELETE", "/api/ddns",            self.h_ddns_delete)

        r.add("GET",  "/api/ports/reserved",    self.h_reserved_ports)

    # ------------------------------------------------------------- 通用

    async def handle(self, req: Request) -> Response:
        hit = self.router.match(req.method, req.path)
        if hit is None:
            return Response.error(f"未知接口: {req.method} {req.path}", 404)
        handler, params = hit
        try:
            # 把路径参数挂到 req 上
            req.params = params            # type: ignore[attr-defined]
            return await handler(req)
        except Exception:                  # noqa: BLE001
            log.exception("API 处理失败 %s %s", req.method, req.path)
            return Response.error("服务器内部错误", 500)

    # ------------------------------------------------------------- 健康/概览

    async def h_health(self, _req: Request) -> Response:
        return Response.ok({
            "version": config.app_version(),
            "proxy": self.proxy.status(),
        })

    async def h_overview(self, req: Request) -> Response:
        try:
            rules = store.list_proxy_rules()
            cert_list = store.list_certs()

            # ★ DDNS 记录数必须取 fnOS 里的真实记录，不是本地 SQLite 的 ddns_link。
            #
            #   store.list_ddns() 读的是本地表，只有通过本应用「添加」过的
            #   才会写进去；用户原本在 fnOS 里就有的记录它完全不知道，
            #   所以概览一直显示 0。
            #
            #   改成用 api_client.list_records() 拿 fnOS 的全部记录。
            #   拿不到（比如没配账号）就退回本地计数，不让整个概览挂掉。
            ddns_count = 0
            ddns_source = "local"
            try:
                cli = _fn_client()
                try:
                    from ..ddns import api_client
                    ddns_count = len(api_client.list_records(cli))
                    ddns_source = "fnos"
                finally:
                    cli.close()
            except Exception as exc:           # noqa: BLE001
                log.info("读取 fnOS DDNS 记录失败，退回本地计数: %s", exc)
                ddns_count = len(store.list_ddns())
            # ★ 按「证书实体」统计，不是按域名映射条数。
            #
            #   load_registry() 返回的是 network_gateway_cert.conf 的
            #   「域名 → 证书文件」映射条目（一张多 SAN 证书会被 7 个域名
            #   各引用一次，于是算成 7 条）。
            #   概览里要的是「有几张证书」，所以必须用去重后的 list_all_certs()。
            #
            #   同时排除 fnOS 系统内置证书（自签兜底 / FN Connect），
            #   与证书页默认隐藏的口径保持一致 —— 否则概览说 5 张、
            #   证书页只显示 3 张，又对不上。
            all_certs = cert_mod.list_all_certs()
            user_certs = [c for c in all_certs if not c.get("isSystemCert")]
        except Exception as exc:           # noqa: BLE001
            return Response.error(f"读取状态失败: {exc}", 500)

        return Response.ok({
            "proxyRules": len(rules),
            "ddnsRecords": ddns_count,
            "ddnsSource": ddns_source,
            "localCerts": len(cert_list),
            # 用户自己的证书张数（去重、排除系统证书）
            "fnosCerts": len(user_certs),
            # 另附明细，便于排查「为什么数字和 fnOS 设置页不一样」
            "fnosCertsTotal": len(all_certs),
            "fnosSystemCerts": len(all_certs) - len(user_certs),
            "fnosCertDomains": sum(c.get("domainCount", 0) for c in user_certs),
            "listeners": self.proxy.status(),
        })

    # ------------------------------------------------------------- 能力探测

    async def h_capabilities(self, req: Request) -> Response:
        """返回当前 fnOS 环境支持哪些能力。

        UI 用这个决定哪些按钮可点、哪些要灰掉并给出跳转提示。
        ★ 这是应对 fnOS 升级的核心机制：
          内部接口失效时，功能降级而不是崩溃。
        """
        cred = req.credentials()

        def _do() -> dict[str, Any]:
            cs = capabilities.probe(cred)
            return cs.to_dict()

        try:
            data = await asyncio.get_running_loop().run_in_executor(None, _do)
            return Response.ok(data)
        except Exception as exc:           # noqa: BLE001
            log.exception("能力探测失败")
            return Response.error(f"能力探测失败: {exc}", 500)

    async def h_capabilities_recheck(self, req: Request) -> Response:
        """强制重新探测（用户点「重新检测」时用）。"""
        cred = req.credentials()

        def _do() -> dict[str, Any]:
            cs = capabilities.probe(cred, force=True)
            return cs.to_dict()

        try:
            data = await asyncio.get_running_loop().run_in_executor(None, _do)
            return Response.ok(data)
        except Exception as exc:           # noqa: BLE001
            log.exception("重新探测失败")
            return Response.error(f"重新探测失败: {exc}", 500)

    # ------------------------------------------------------------- 反代规则

    async def h_proxies_list(self, _req: Request) -> Response:
        rows = store.list_proxy_rules()
        for r in rows:
            r["domains"] = [d for d in (r.get("domains") or "").split(",") if d]
            r["enabled"] = bool(r.get("enabled"))
            r["listen_tls"] = bool(r.get("listen_tls"))
            r["force_https"] = bool(r.get("force_https"))
            r["preserve_host"] = bool(r.get("preserve_host"))
        return Response.ok(rows)

    async def _validate_rule(self, data: dict[str, Any]) -> str:
        """校验规则，返回错误信息（空串表示通过）。"""
        name = (data.get("name") or "").strip()
        if not name:
            return "规则名称不能为空"

        domains = data.get("domains")
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        if not domains:
            return "至少填写一个域名"

        try:
            port = int(data.get("listen_port"))
        except (TypeError, ValueError):
            return "监听端口必须是数字"

        if config.is_reserved_port(port):
            return (f"端口 {port} 属于系统保留端口（80/443/5666/5667/16666/16667 及 <1024），"
                    f"请使用 {config.DEFAULT_LISTEN_PORT} 或更高位端口")

        try:
            tport = int(data.get("target_port"))
        except (TypeError, ValueError):
            return "后端端口必须是数字"
        if not (1 <= tport <= 65535):
            return "后端端口超出范围"

        if not (data.get("target_host") or "").strip():
            return "后端地址不能为空"

        # 同端口的 TLS 设置必须一致（同一端口不能既 HTTP 又 HTTPS）
        tls = bool(data.get("listen_tls"))
        existing = store.list_proxy_rules()
        for r in existing:
            if data.get("id") and int(r["id"]) == int(data["id"]):
                continue
            if int(r["listen_port"]) == port and bool(r["listen_tls"]) != tls:
                proto = "HTTPS" if bool(r["listen_tls"]) else "HTTP"
                return f"端口 {port} 已被一条 {proto} 规则占用，同一端口的协议必须一致"

        return ""

    async def h_proxies_create(self, req: Request) -> Response:
        data = req.json()
        err = await self._validate_rule(data)
        if err:
            return Response.error(err)

        domains = data.get("domains")
        if isinstance(domains, list):
            data["domains"] = ",".join(d.strip() for d in domains if d.strip())

        rule_id = store.upsert_proxy_rule(data)
        await self._reload_proxy()
        return Response.ok({"id": rule_id})

    async def h_proxies_update(self, req: Request) -> Response:
        params = getattr(req, "params", {})
        data = req.json()
        data["id"] = int(params["id"])

        err = await self._validate_rule(data)
        if err:
            return Response.error(err)

        domains = data.get("domains")
        if isinstance(domains, list):
            data["domains"] = ",".join(d.strip() for d in domains if d.strip())

        store.upsert_proxy_rule(data)
        await self._reload_proxy()
        return Response.ok()

    async def h_proxies_toggle(self, req: Request) -> Response:
        """启用 / 禁用一条反代规则。

        ★ 不用 PUT /api/proxies/:id 的原因：
          PUT 会走 _validate_rule（同端口 TLS 一致性、保留端口等），
          而这些校验对「只是开关一下」没有意义，还可能误伤。
          这里直接读原规则、只改 enabled 字段、写回、重载引擎。

        ★ 请求体可选 {"enabled": true|false}；
          不传就按当前值取反（toggle）。
        """
        params = getattr(req, "params", {})
        rule_id = int(params["id"])

        rule = store.get_proxy_rule(rule_id)
        if not rule:
            return Response.error("规则不存在", 404)

        try:
            data = req.json()
        except Exception:                  # noqa: BLE001
            data = {}

        if "enabled" in data:
            new_enabled = bool(data["enabled"])
        else:
            new_enabled = not bool(rule.get("enabled"))

        # 只改 enabled，其他字段原样保留
        rule["enabled"] = new_enabled
        store.upsert_proxy_rule(rule)
        await self._reload_proxy()
        return Response.ok({"id": rule_id, "enabled": new_enabled})

    async def h_proxies_delete(self, req: Request) -> Response:
        params = getattr(req, "params", {})
        ok = store.delete_proxy_rule(int(params["id"]))
        if not ok:
            return Response.error("规则不存在", 404)
        await self._reload_proxy()
        return Response.ok()

    async def h_proxies_reload(self, _req: Request) -> Response:
        await self._reload_proxy()
        return Response.ok(self.proxy.status())

    async def _reload_proxy(self) -> None:
        rows = store.list_proxy_rules()
        rules = [Rule.from_row(r) for r in rows]
        await self.proxy.apply(rules)

    # ------------------------------------------------------------- 证书

    async def h_certs_list(self, _req: Request) -> Response:
        """列出 fnOS 证书（登记表 + 解析信息）。"""
        try:
            items = cert_mod.list_all_certs()
        except Exception as exc:           # noqa: BLE001
            return Response.error(f"读取证书失败: {exc}", 500)
        return Response.ok(items)

    async def h_certs_matched(self, req: Request) -> Response:
        """给定域名，返回匹配到的证书（预览用）。"""
        domain = (req.query.get("domain") or "").strip()
        if not domain:
            return Response.error("缺少 domain 参数")

        entries = cert_mod.load_registry()
        matched = cert_mod.match_certs(domain, entries)
        picked = cert_mod.pick_cert(domain, entries)

        return Response.ok({
            "domain": domain,
            "matched": [e.host for e in matched],
            "picked": picked.host if picked else None,
            "readable": picked.readable() if picked else False,
        })

    async def h_certs_renew(self, req: Request) -> Response:
        """手动续期一张证书（走 fnOS 的 ACME 引擎）。

        ★ 用途：
          fnOS 会在证书快到期时自动续（renewal=1），
          但用户可能想立即换一张新证书，或自动续签失败后手动重试。

        ★ 前置条件：证书必须有续签资格（renewal=1）。
          fnOS 的系统证书（兜底 / FN Connect）没有，会被拒绝。

        ★ 续期要重新走 DNS-01，通常 25~120 秒，所以放线程里跑。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        data = req.json()
        cert_id = data.get("id")
        if cert_id is None:
            return Response.error("缺少证书 id")

        try:
            cert_id = int(cert_id)
        except (TypeError, ValueError):
            return Response.error("证书 id 必须是整数")

        def _do() -> dict[str, Any]:
            from ..certs import manager as cert_mgr

            cli = _fn_client()
            try:
                return cert_mgr.renew_cert(cli, cert_id, wait=True)
            finally:
                cli.close()

        try:
            res = await asyncio.get_running_loop().run_in_executor(None, _do)
            if res.get("ok"):
                capabilities.invalidate("cert.issue", "")
                return Response.ok(res)
            return Response.error(res.get("note") or "续期未完成", 502)
        except Exception as exc:           # noqa: BLE001
            from ..certs import manager as cert_mgr

            if isinstance(exc, cert_mgr.CertError):
                return Response.error(str(exc), 400)
            return Response.error(f"续期失败: {str(exc)[:200]}", 502)

    async def h_certs_delete(self, req: Request) -> Response:
        """删除 fnOS 证书库里的某张证书（走 cert.remove）。

        ★ 参数是证书 id。

        ★★ 重要安全教训（2026-11-24 实测）：
          fnOS 的 cert.remove **不会拦截正在被域名使用的证书** ——
          我测试时删掉了主证书 id=93（被 7 个域名引用），fnOS 直接放行。

          只有兜底证书（id=1，isDefault）会被拦（errno=3000025 Cert Using）。

          所以本应用必须自己加保护：**被登记表引用的证书一律不允许删**。
          否则用户一点就删掉线上证书，所有域名立刻掉到兜底自签证书。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        data = req.json()
        cert_id = data.get("id")
        if cert_id is None:
            return Response.error("缺少证书 id")

        try:
            cert_id = int(cert_id)
        except (TypeError, ValueError):
            return Response.error("证书 id 必须是整数")

        # ★ 第一道保护：区分「证书登记表占用」和「实际在用」
        #
        # 踩过的坑（2026-11-24）：
        #   最初只要证书在 network_gateway_cert.conf 里被任何域名引用，
        #   就判定「使用中」并阻止删除。
        #
        #   但那个登记表只代表「域名 → 用哪张证书」的绑定关系，
        #   并不代表这个域名现在真的在提供服务。
        #
        #   实际场景：用户删掉了 mytest 的反代规则，
        #   但 fnOS 证书登记表里还留着 mytest → 那张证书的映射，
        #   于是界面一直显示「使用中」，永远删不掉。
        #
        # 修正后的判断：
        #   * 只有当证书覆盖的域名中，**至少一个仍被反代规则使用**时，
        #     才算真正「使用中」，予以阻止。
        #   * 否则允许删除（只是 fnOS 会拒绝兜底证书，那是 fnOS 自己的保护）。
        try:
            active_domains: set[str] = set()
            for rule in store.list_proxy_rules():
                if not rule.get("enabled"):
                    continue
                for d in (rule.get("domains") or "").split(","):
                    d = d.strip().lower()
                    if d:
                        active_domains.add(d)

            in_use_by: list[str] = []
            cert_covered: list[str] = []
            for c in cert_mod.list_all_certs():
                if c.get("certId") == cert_id and not c.get("isFallback"):
                    cert_covered = c.get("coveredDomains") or []
                    break

            for d in cert_covered:
                if d.lower() in active_domains:
                    in_use_by.append(d)

            if in_use_by:
                shown = "、".join(in_use_by[:5])
                if len(in_use_by) > 5:
                    shown += f" 等 {len(in_use_by)} 个"
                return Response.error(
                    f"该证书正在为此域名提供 HTTPS，不能删除：\n{shown}\n\n"
                    f"如需删除，请先到「反向代理」页删掉或停用这些域名的规则。",
                    409,
                )

            # 只是 fnOS 登记表里还挂着，但没有任何反代规则在用它 → 允许删
            if cert_covered:
                log.info(
                    "证书 %s 仍登记在 fnOS 证书表中（%s），"
                    "但没有反代规则使用，允许删除",
                    cert_id, "、".join(cert_covered[:3]),
                )
        except Exception as exc:           # noqa: BLE001
            log.warning("检查证书占用失败（继续走 fnOS 侧校验）: %s", exc)

        def _do() -> dict[str, Any]:
            from ..certs import manager as cert_mgr

            cli = _fn_client()
            try:
                target = None
                for r in cert_mgr.list_certs(cli):
                    if r.get("id") == cert_id:
                        target = r
                        break
                if target is None:
                    return {"removed": False,
                            "reason": f"证书不存在: id={cert_id}"}

                # ★ 第二道保护：系统证书一律不给删
                #
                # 实测（2026-11-25）：fnOS 的 cert.remove **不会拦截**
                # FN Connect 专属证书（source=trim）和自签兜底（source=system）。
                # 之前只挡了 isDefault，但 FN Connect 那张 isDefault=0，
                # 会被误删，导致 FN Connect 远程访问失效。
                #
                # 所以按 source 判断：只有 upload（用户自己申请的）才可删。
                src = str(target.get("source") or "")
                if src in ("system", "trim") or target.get("isDefault"):
                    why = {
                        "system": "这是飞牛 OS 自签兜底证书，删除后未匹配域名将无证书可用。",
                        "trim": "这是 FN Connect 专属证书，删除会中断 FN Connect 远程访问。",
                    }.get(src, "这是默认/兜底证书，删除后所有未匹配域名会没有证书可用。")
                    return {"removed": False,
                            "reason": why + " 已阻止。",
                            "blocked": True}

                ok = cert_mgr.delete_cert(cli, cert_id)
                if not ok:
                    return {"removed": False, "reason": "飞牛 OS 拒绝删除"}
                return {
                    "removed": True,
                    "id": cert_id,
                    "domain": target.get("domain", ""),
                }
            finally:
                cli.close()

        try:
            res = await asyncio.get_running_loop().run_in_executor(None, _do)
            if res.get("removed"):
                capabilities.invalidate("cert.issue", "")
                return Response.ok(res)
            return Response.error(res.get("reason") or "删除失败",
                                  409 if res.get("blocked") else 400)
        except Exception as exc:           # noqa: BLE001
            msg = str(exc)
            if "3000025" in msg or "Cert Using" in msg:
                return Response.error(
                    "该证书正在被使用，无法删除。\n"
                    "请先到「系统设置 → 证书管理」把引用它的域名切换到其它证书。",
                    409,
                )
            return Response.error(f"删除证书失败: {msg[:200]}", 502)

    # ------------------------------------------------------------- fnOS 凭据

    async def h_settings_get(self, req: Request) -> Response:
        """返回当前认证状态（**不回传密码**）。"""
        cfg = _load_fn_cfg()

        return Response.ok({
            "mode": "password",
            "session": {
                "available": bool(cfg),
                "source": "本应用保存的飞牛 OS 账号" if cfg else "",
                "hasToken": False,
                "hasSecret": False,
            },
            "fallback": {
                "configured": bool(cfg),
                "user": cfg["user"] if cfg else "",
            },
        })

    async def h_settings_put(self, req: Request) -> Response:
        data = req.json()
        user = (data.get("user") or "").strip()
        password = data.get("pass") or ""
        access_code = (data.get("access_code") or "").strip()

        if not user or not password:
            return Response.error("用户名和密码都必须填写")

        try:
            _save_fn_cfg(user, password, access_code)
        except OSError as exc:
            return Response.error(f"保存凭据失败: {exc}", 500)

        return Response.ok({"saved": True})

    async def h_settings_test(self, req: Request) -> Response:
        """测试凭据是否可用。"""
        from ..certs import ws_client

        try:
            cli = _fn_client()
        except RuntimeError as exc:
            return Response.error(str(exc), 400)
        except ws_client.TwofaRequired:
            return Response.error(
                "凭据有效，但该账号开启了双重验证。签发证书时需输入 2FA 验证码。",
                200,
            )
        except ws_client.AccessCodeRequired:
            return Response.error("该 NAS 开启了访问码，请在设置里填写访问码", 401)
        except ws_client.FnosWsError as exc:
            return Response.error(f"连接失败: {exc}", 502)

        try:
            return Response.ok({
                "ok": True,
                "uid": cli.uid,
                "admin": cli.admin,
            })
        finally:
            cli.close()

    # ------------------------------------------------------------- 证书签发

    async def h_certs_issue(self, req: Request) -> Response:
        """签发证书（多域名 / 通配符 / ECC）。"""
        from ..certs import manager as cert_mgr
        from ..certs import ws_client

        data = req.json()
        domains = data.get("domains")
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        if not domains:
            return Response.error("至少填写一个域名")

        err = seed_validate(domains)
        if err:
            return Response.error(err)

        email = (data.get("email") or "").strip()
        ecc = bool(data.get("ecc"))
        desc = (data.get("desc") or "dnsrp").strip()[:64]
        ddns_id = data.get("ddns_id")
        twofa = (data.get("twofa") or "").strip()

        # 签发是长任务，放到线程里跑，避免阻塞事件循环
        def _do_issue() -> dict[str, Any]:
            cli = _fn_client()
            try:
                if twofa:
                    try:
                        cli.twofa_verify(twofa)
                    except ws_client.FnosWsError as exc:
                        raise cert_mgr.CertError(f"2FA 验证失败: {exc}") from exc
                return cert_mgr.issue_cert(
                    cli, domains,
                    email=email, ecc=ecc, desc=desc,
                    ddns_id=int(ddns_id) if ddns_id else None,
                )
            finally:
                cli.close()

        try:
            result = await asyncio.get_running_loop().run_in_executor(
                None, _do_issue
            )
            return Response.ok(result)
        except ws_client.TwofaRequired:
            return Response.error("需要 2FA 验证码，请填写后重试", 401)
        except cert_mgr.CertError as exc:
            return Response.error(str(exc), 400)
        except ws_client.FnosWsError as exc:
            return Response.error(f"fnOS 调用失败: {exc}", 502)
        except Exception as exc:           # noqa: BLE001
            log.exception("签发证书失败")
            return Response.error(f"签发失败: {exc}", 500)

    # ------------------------------------------------------------- DDNS

    async def h_ddns_list(self, req: Request) -> Response:
        """DDNS 列表。

        ★ 降级策略（应对 fnOS 升级）：
          1. 优先用 fnOS 内部 API（需要网页登录会话）
          2. 失败则返回明确的错误 + 跳转提示，**不崩溃**
          3. 同时把该能力标记为失效，下次探测会重新检查
        """
        if not _load_fn_cfg():
            return Response.error(
                "尚未配置飞牛 OS 账号。\n"
                "请到「设置」里填写用户名和密码（只需一次）。",
                400,
            )

        def _do() -> list[dict[str, Any]]:
            from ..ddns import api_client

            cli = _fn_client()
            try:
                return api_client.list_records(cli)
            finally:
                cli.close()

        try:
            items = await asyncio.get_running_loop().run_in_executor(None, _do)
            return Response.ok(items)
        except Exception as exc:           # noqa: BLE001
            msg = str(exc)
            capabilities.invalidate("ddns.read", msg)

            if "no register handler" in msg or "10000002" in msg:
                return Response.error(
                    "当前飞牛 OS 版本不再提供 DDNS 接口，本应用无法管理 DDNS。\n"
                    "请到「系统设置 → 远程访问 → DDNS」操作。\n"
                    f"（技术细节: {msg[:100]}）",
                    501,
                )
            return Response.error(f"读取 DDNS 失败: {msg[:200]}", 502)

    async def h_ddns_fnos_list(self, req: Request) -> Response:
        """同 h_ddns_list（兼容旧路径）。"""
        return await self.h_ddns_list(req)

    async def h_ddns_zones(self, req: Request) -> Response:
        """可用根域（从 DDNS 记录里按根域去重）。"""
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        def _do() -> list[dict]:
            from ..ddns import api_client
            cli = _fn_client()
            try:
                return api_client.list_zones(cli)
            finally:
                cli.close()

        try:
            return Response.ok(
                await asyncio.get_running_loop().run_in_executor(None, _do))
        except Exception as exc:           # noqa: BLE001
            capabilities.invalidate("ddns.read", str(exc))
            return Response.error(_ddns_err(str(exc)), 502)

    async def h_ddns_create(self, req: Request) -> Response:
        """批量添加 DDNS 记录（走 fnOS 官方 ddns.record.create）。

        ★★ 凭据改为**必填**（2026-11-24 调整）：

           实测确认：不带凭据也能让 create 返回 true，
           但建出来的记录 access_key 为空、状态永远停在 loading ——
           既不会上报公网 IP，证书做 DNS-01 时也会失败。

           也就是说「不填凭据也能添加」只是表面上成功，
           实际是一条死记录，用户还得跑去 fnOS 原生页面补 key。

           所以这里直接拒绝：要么填凭据一次到位，
           要么去 fnOS 原生界面添加（那里也是同样要求）。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        data = req.json()
        domains = data.get("domains")
        if isinstance(domains, str):
            domains = [d.strip() for d in domains.split(",") if d.strip()]
        if not domains:
            return Response.error("至少填写一个域名")

        try:
            interval = int(data.get("update_interval") or 5)
        except (TypeError, ValueError):
            interval = 5
        interval = max(1, min(1440, interval))

        provider = (data.get("provider") or "cloudflare").strip()
        access_key = (data.get("access_key") or "").strip()
        access_secret = (data.get("access_secret") or "").strip()

        # 凭据必填 —— 没凭据建出来的是死记录
        if not access_key:
            return Response.error(
                "必须填写 Access Key / ID。\n\n"
                "飞牛 OS 需要用这个授权去更新 DNS 解析记录；"
                "没有凭据的记录会一直停在 loading，既不上报 IP，"
                "证书也无法用它做 DNS-01 验证。\n\n"
                "如果你想先建记录稍后补凭据，请到「系统设置 → 远程访问 → DDNS」操作。",
                400,
            )

        def _do() -> list[dict[str, Any]]:
            from ..ddns import api_client

            cli = _fn_client()
            try:
                existing = {r["domain"]: r for r in api_client.list_records(cli)}
                out: list[dict[str, Any]] = []

                for d in domains:
                    if d in existing:
                        cur = existing[d]
                        out.append({
                            "domain": d, "ok": True,
                            "note": f"已存在（状态 {cur.get('status')}），跳过",
                        })
                        continue

                    try:
                        api_client.create_record_raw(
                            cli, d, interval,
                            access_key=access_key,
                            access_secret=access_secret,
                            provider=provider,
                        )
                        out.append({"domain": d, "ok": True,
                                    "note": "已添加，等待飞牛 OS 首次上报"})
                    except Exception as exc:      # noqa: BLE001
                        out.append({"domain": d, "ok": False,
                                    "error": str(exc)[:200]})
                return out
            finally:
                cli.close()

        try:
            return Response.ok(
                await asyncio.get_running_loop().run_in_executor(None, _do))
        except Exception as exc:           # noqa: BLE001
            capabilities.invalidate("ddns.write", str(exc))
            return Response.error(_ddns_err(str(exc)), 502)

    async def h_ddns_update(self, req: Request) -> Response:
        """修改 DDNS 记录（检查间隔 / 服务商凭据）。

        ★ 凭据可以改：detail 返回的是**明文**，update 时 fnOS 自己加密。
        ★ 但必须传完整记录（含凭据），否则 update 会把凭据清空 ——
          这个坑详见 api_client.update_record 的说明。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        data = req.json()
        domain = (data.get("domain") or "").strip()
        if not domain:
            return Response.error("缺少 domain 参数")

        try:
            interval = int(data.get("update_interval") or 5)
        except (TypeError, ValueError):
            return Response.error("检查间隔必须是整数")

        if not (1 <= interval <= 1440):
            return Response.error("检查间隔需在 1~1440 分钟之间")

        new_ak = (data.get("access_key") or "").strip()
        new_sk = (data.get("access_secret") or "").strip()

        def _do() -> dict[str, Any]:
            from ..ddns import api_client

            cli = _fn_client()
            try:
                cur = None
                for r in api_client.list_records(cli):
                    if r.get("domain") == domain:
                        cur = r
                        break

                if cur is None:
                    return {"ok": False, "reason": f"记录不存在: {domain}"}

                # fnOS 要求完整记录对象；凭据由 update_record 内部
                # 从 detail 读回，或用用户传的新值覆盖
                payload = {
                    "id": cur.get("id"),
                    "domain": cur.get("domain"),
                    "provider": cur.get("provider"),
                    "ipv4": cur.get("ipv4") or "auto",
                    "ipv6": cur.get("ipv6") or "auto",
                    "updateInterval": interval,
                }
                changed_cred = bool(new_ak or new_sk)
                ok = api_client.update_record(
                    cli, payload,
                    new_access_key=new_ak,
                    new_access_secret=new_sk,
                )
                return {"ok": bool(ok), "domain": domain,
                        "updateInterval": interval,
                        "credChanged": changed_cred}
            finally:
                cli.close()

        try:
            res = await asyncio.get_running_loop().run_in_executor(None, _do)
            if res.get("ok"):
                capabilities.invalidate("ddns.write", "")
                return Response.ok(res)
            return Response.error(res.get("reason") or "修改失败", 400)
        except Exception as exc:           # noqa: BLE001
            capabilities.invalidate("ddns.write", str(exc))
            return Response.error(_ddns_err(str(exc)), 502)

    async def h_ddns_detail(self, req: Request) -> Response:
        """读 DDNS 记录详情（含**明文**凭据，供编辑用）。

        ⚠️ 只在编辑时按需返回，不写日志、不落盘。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        domain = (req.query.get("domain") or "").strip()
        if not domain:
            return Response.error("缺少 domain 参数")

        def _do() -> dict[str, Any]:
            from ..ddns import api_client

            cli = _fn_client()
            try:
                return api_client.get_record_detail(cli, domain)
            finally:
                cli.close()

        try:
            d = await asyncio.get_running_loop().run_in_executor(None, _do)
            if not d:
                return Response.error(f"记录不存在: {domain}", 404)
            return Response.ok({
                "domain": d.get("domain"),
                "provider": d.get("provider"),
                "accessKey": d.get("accessKey") or "",
                "accessSecret": d.get("accessSecret") or "",
                "updateInterval": d.get("updateInterval"),
                "status": d.get("status"),
            })
        except Exception as exc:           # noqa: BLE001
            return Response.error(_ddns_err(str(exc)), 502)

    async def h_ddns_delete(self, req: Request) -> Response:
        """删除 DDNS 记录（走 fnOS 官方 ddns.record.remove）。

        ★ 接口参数是 **domain**，不是 id（实测结论）。
          并且删除可能要等 10~60 秒（fnOS 会去 DNS 服务商那边清理解析），
          所以要放在线程里跑，避免阻塞事件循环，
          前端也要给足等待时间。
        """
        if not _load_fn_cfg():
            return Response.error("尚未配置飞牛 OS 账号，请到「设置」填写。", 400)

        domain = (req.query.get("domain") or "").strip()
        if not domain:
            return Response.error("缺少 domain 参数")

        def _do() -> dict[str, Any]:
            from ..ddns import api_client

            cli = _fn_client()
            try:
                # 确认记录存在（顺便拿到 id 用于返回）
                target = None
                for r in api_client.list_records(cli):
                    if r["domain"] == domain:
                        target = r["id"]
                        break
                if target is None:
                    return {"removed": False, "reason": f"记录不存在: {domain}"}

                ok = api_client.delete_record(cli, domain)
                if not ok:
                    return {"removed": False,
                            "reason": "飞牛 OS 拒绝删除，请到原生 DDNS 页面操作"}
                return {"removed": True, "domain": domain, "id": target}
            finally:
                cli.close()

        try:
            res = await asyncio.get_running_loop().run_in_executor(None, _do)
            if res.get("removed"):
                try:
                    store.delete_ddns(domain)
                except Exception:              # noqa: BLE001
                    pass
                return Response.ok(res)
            return Response.error(res.get("reason") or "删除失败", 404)
        except Exception as exc:           # noqa: BLE001
            capabilities.invalidate("ddns.write", str(exc))
            return Response.error(_ddns_err(str(exc)), 502)

    # ------------------------------------------------------------- 其他
    # ------------------------------------------------------------- 其他

    async def h_reserved_ports(self, _req: Request) -> Response:
        return Response.ok({
            "reserved": sorted(config.RESERVED_PORTS),
            "defaultPort": config.DEFAULT_LISTEN_PORT,
        })


# ---------------------------------------------------------------- HTTP 服务


async def _read_http_request(
    reader: asyncio.StreamReader,
) -> tuple[str, str, dict[str, str], bytes] | None:
    """读一个完整的 HTTP 请求（含 body）。"""
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=30)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError,
            asyncio.LimitOverrunError):
        return None

    text = head.decode("iso-8859-1", "ignore")
    lines = text.split("\r\n")
    if not lines or not lines[0]:
        return None

    parts = lines[0].split(" ")
    if len(parts) < 3:
        return None
    method, target, _version = parts[0], parts[1], parts[2]

    # 拆 query
    path, _, query_str = target.partition("?")
    query: dict[str, str] = {}
    if query_str:
        from urllib.parse import parse_qsl

        for k, v in parse_qsl(query_str, keep_blank_values=True):
            query[k] = v

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or ":" not in line:
            continue
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()

    body = b""
    clen = headers.get("content-length")
    if clen and clen.isdigit() and int(clen) > 0:
        try:
            body = await asyncio.wait_for(
                reader.readexactly(int(clen)), timeout=30
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            return None

    return method, path, query, headers, body       # type: ignore[return-value]


def _build_response(resp: Response, method: str) -> bytes:
    body = resp.to_bytes()
    reason = {
        200: "OK", 201: "Created", 400: "Bad Request", 404: "Not Found",
        405: "Method Not Allowed", 409: "Conflict", 500: "Internal Server Error",
        503: "Service Unavailable",
    }.get(resp.status, "OK")

    head = (
        f"HTTP/1.1 {resp.status} {reason}\r\n"
        f"Content-Type: {resp.content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cache-Control: no-store\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1")

    return head + (b"" if method == "HEAD" else body)


async def serve_api(socket_path, proxy: engine_mod.ProxyEngine) -> None:
    """在 unix socket 上跑 API 服务（内部用，保留兼容）。"""
    app = ApiApp(proxy)

    async def client(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        try:
            parsed = await _read_http_request(reader)
            if not parsed:
                writer.close()
                return
            method, path, query, headers, body = parsed     # type: ignore[misc]

            req = Request(method, path, query, body, headers)
            resp = await app.handle(req)
            writer.write(_build_response(resp, method))
            await writer.drain()
        except Exception:                  # noqa: BLE001
            log.exception("API 连接异常")
        finally:
            try:
                writer.close()
            except Exception:              # noqa: BLE001
                pass

    sp = str(socket_path)
    import os

    try:
        os.unlink(sp)
    except FileNotFoundError:
        pass

    server = await asyncio.start_unix_server(client, path=sp)
    os.chmod(sp, 0o660)
    log.info("API 已监听 unix socket: %s", sp)
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------- HTTP 服务
#
# ★ 为什么要自己起 HTTP 服务（而不是走 fnOS 的 CGI）：
#
#   fnOS 的 CGI 网关（/cgi/ThirdParty/<app>/）在 nginx 后面，
#   但调用 fnOS 的内部接口（appcgi.netsvr.cert.* / ddns.*）时，
#   服务端要求 HMAC 签名，而签名密钥是用户的会话密钥 ——
#   CGI 环境里拿不到，除非用户再填一次密码。
#
#   而 fnOS 官方认可的第三方应用（fncleankernel、OpenList）都用
#   ui/config 的 `type: url` 模式：浏览器**直连应用自己的端口**，
#   完全绕开 fnOS 的 CGI token 校验。
#
#   本应用改成同样的模式：
#     * 自己监听一个高位 HTTP 端口（默认 8765）
#     * 同时提供静态页面和 API
#     * 用户从应用中心点击图标即直达，无需任何登录
#
#   这也符合用户的实际体验：能打开应用，说明已经在 fnOS 里登录过，
#   应用本身不该再要一次认证。


MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
}


def _serve_static(www_dir, rel_path: str) -> tuple[int, str, bytes]:
    """从 www 目录读静态文件。返回 (status, content_type, body)。"""
    import os
    from pathlib import Path

    www = Path(www_dir).resolve()

    rel = rel_path.lstrip("/")
    if not rel:
        rel = "index.html"

    # 路径穿越防护：解析后必须仍在 www 目录内
    target = (www / rel).resolve()
    try:
        target.relative_to(www)
    except ValueError:
        return 404, "text/plain; charset=utf-8", b"404 Not Found"

    if not target.is_file():
        return 404, "text/plain; charset=utf-8", b"404 Not Found"

    ext = os.path.splitext(target.name)[1].lower()
    ctype = MIME_TYPES.get(ext, "application/octet-stream")
    try:
        body = target.read_bytes()
    except OSError:
        return 500, "text/plain; charset=utf-8", b"500 Read Error"

    return 200, ctype, body


def _build_raw_response(status: int, ctype: str, body: bytes,
                        method: str = "GET") -> bytes:
    reason = {
        200: "OK", 304: "Not Modified", 400: "Bad Request",
        404: "Not Found", 500: "Internal Server Error",
    }.get(status, "OK")

    head = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {ctype}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cache-Control: no-store\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("iso-8859-1")

    return head + (b"" if method == "HEAD" else body)


async def serve_http(port: int, www_dir, proxy: engine_mod.ProxyEngine) -> None:
    """在 HTTP 端口上同时提供 UI 静态页和 API。

    这是 UI 的主入口（ui/config 里 type: url 指向这个端口）。
    """
    from pathlib import Path

    app = ApiApp(proxy)
    www = Path(www_dir)

    log.info("UI 目录: %s", www)

    async def handle(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            parsed = await _read_http_request(reader)
            if not parsed:
                return

            method, path, query, headers, body = parsed     # type: ignore[misc]

            # ---- API ----
            if path.startswith("/api/"):
                req = Request(method, path, query, body, headers)
                resp = await app.handle(req)
                writer.write(_build_response(resp, method))
                await writer.drain()
                return

            # ---- 静态文件 ----
            status, ctype, content = _serve_static(www, path)
            writer.write(_build_raw_response(status, ctype, content, method))
            await writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            pass
        except Exception:                  # noqa: BLE001
            log.exception("HTTP 连接异常 peer=%s", peer)
            try:
                writer.write(_build_raw_response(
                    500, "text/plain; charset=utf-8", b"500 Internal Error"))
                await writer.drain()
            except Exception:              # noqa: BLE001
                pass
        finally:
            try:
                writer.close()
            except Exception:              # noqa: BLE001
                pass

    server = await asyncio.start_server(handle, host="0.0.0.0", port=port,
                                        backlog=128)
    log.info("UI + API 已监听 HTTP :%d", port)

    async with server:
        await server.serve_forever()
