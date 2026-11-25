"""dnsrp 反向代理引擎。

设计要点：
  * 每个监听端口一个 asyncio server；同端口按 Host/SNI 分流。
  * TLS 证书**按域名实时从 fnOS 登记表取**，不缓存到磁盘、不复制证书。
  * 支持 WebSocket 透传（HTTP/1.1 Upgrade）。
  * 用流式转发，大文件不占内存。

不做什么：
  * 不做缓存、不做 gzip、不做请求改写（保持透明代理语义）。
  * 不做 HTTP/2（fnOS 场景下 HTTP/1.1 + TLS 已够用）。
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from typing import Any

from . import certs as cert_mod

log = logging.getLogger("dnrp.proxy")

# 逐跳头，转发时必须剔除（RFC 7230 §6.1）
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",           # 见下方 WebSocket 特殊处理
}

# 转发给后端时保留的头
FORWARD_HEADERS = {
    "host",
    "user-agent",
    "accept",
    "accept-language",
    "accept-encoding",
    "content-type",
    "content-length",
    "cookie",
    "authorization",
    "range",
    "if-none-match",
    "if-modified-since",
    "referer",
    "origin",
    "cache-control",
    "pragma",
}

MAX_HEADER = 64 * 1024


@dataclass
class Rule:
    """一条反代规则（从 SQLite 读出后转成这个结构）。"""

    id: int
    name: str
    domains: list[str]
    listen_port: int
    listen_tls: bool
    target_scheme: str
    target_host: str
    target_port: int
    cert_id: int | None = None
    force_https: bool = False
    preserve_host: bool = False
    timeout_sec: int = 30
    enabled: bool = True

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> "Rule":
        domains = [d.strip() for d in (row.get("domains") or "").split(",") if d.strip()]
        return cls(
            id=int(row["id"]),
            name=str(row.get("name") or ""),
            domains=domains,
            listen_port=int(row["listen_port"]),
            listen_tls=bool(row.get("listen_tls")),
            target_scheme=str(row.get("target_scheme") or "http"),
            target_host=str(row.get("target_host") or "127.0.0.1"),
            target_port=int(row["target_port"]),
            cert_id=row.get("cert_id"),
            force_https=bool(row.get("force_https")),
            preserve_host=bool(row.get("preserve_host")),
            timeout_sec=int(row.get("timeout_sec") or 30),
            enabled=bool(row.get("enabled", 1)),
        )


@dataclass
class Listener:
    """一个监听端口的运行时状态。"""

    port: int
    tls: bool
    server: asyncio.AbstractServer | None = None
    rules: dict[str, Rule] = field(default_factory=dict)   # domain -> rule
    wildcard_rules: list[tuple[str, Rule]] = field(default_factory=list)


class ProxyEngine:
    """反代引擎：管理所有监听端口，按域名路由。"""

    def __init__(self) -> None:
        self._listeners: dict[int, Listener] = {}
        self._running = False

    # ------------------------------------------------------------- 生命周期

    async def start(self, rules: list[Rule]) -> None:
        self._running = True
        await self.apply(rules)

    async def stop(self) -> None:
        self._running = False
        for port, lis in list(self._listeners.items()):
            if lis.server:
                lis.server.close()
                try:
                    await lis.server.wait_closed()
                except Exception:                     # noqa: BLE001
                    pass
                log.info("已停止监听 :%d", port)
        self._listeners.clear()

    async def apply(self, rules: list[Rule]) -> None:
        """应用一组规则：重建监听端口集合。

        先停掉不再需要的端口，再启动新增的，最后刷新路由表。
        """
        enabled = [r for r in rules if r.enabled]

        # 按端口分组
        by_port: dict[int, list[Rule]] = {}
        for r in enabled:
            by_port.setdefault(r.listen_port, []).append(r)

        # 端口是否要求 TLS（同端口规则必须一致）
        port_tls: dict[int, bool] = {}
        for port, rs in by_port.items():
            tls_flags = {r.listen_tls for r in rs}
            if len(tls_flags) > 1:
                log.warning("端口 :%d 上的规则 TLS 设置不一致，取多数", port)
            port_tls[port] = sum(1 for r in rs if r.listen_tls) > len(rs) / 2

        # 停掉多余的端口
        for port in list(self._listeners):
            if port not in by_port:
                await self._close_port(port)

        # 启动/更新端口
        for port, rs in by_port.items():
            want_tls = port_tls[port]
            existing = self._listeners.get(port)
            if existing and existing.tls != want_tls:
                await self._close_port(port)
                existing = None
            if existing is None:
                ok = await self._open_port(port, want_tls)
                if not ok:
                    continue
                existing = self._listeners[port]
            self._load_routes(existing, rs)

        log.info("反代规则已应用：%d 个端口，%d 条规则", len(self._listeners), len(enabled))

    async def _open_port(self, port: int, tls: bool) -> bool:
        ssl_ctx: ssl.SSLContext | None = None
        if tls:
            ssl_ctx, _resolve = cert_mod.build_ssl_context_loader()
            if not cert_mod.load_default_chain(ssl_ctx):
                log.error(
                    "端口 :%d 需要 TLS，但读不到任何可用证书。"
                    "请确认应用已加入 www-data 组且在 fnOS 证书管理里有证书。", port
                )
                return False

        try:
            server = await asyncio.start_server(
                lambda r, w: self._handle(r, w, port),
                host="0.0.0.0",
                port=port,
                ssl=ssl_ctx,
                backlog=128,
                limit=MAX_HEADER,
            )
        except OSError as exc:
            log.error("端口 :%d 监听失败: %s", port, exc)
            return False

        self._listeners[port] = Listener(port=port, tls=tls, server=server)
        log.info("正在监听 :%d (%s)", port, "HTTPS" if tls else "HTTP")
        return True

    async def _close_port(self, port: int) -> None:
        lis = self._listeners.pop(port, None)
        if not lis or not lis.server:
            return
        lis.server.close()
        try:
            await lis.server.wait_closed()
        except Exception:                             # noqa: BLE001
            pass
        log.info("已关闭端口 :%d", port)

    def _load_routes(self, lis: Listener, rules: list[Rule]) -> None:
        lis.rules.clear()
        lis.wildcard_rules.clear()
        for r in rules:
            for d in r.domains:
                d_low = d.lower()
                if d_low.startswith("*."):
                    lis.wildcard_rules.append((d_low[1:], r))   # ".example.com"
                else:
                    lis.rules[d_low] = r
        # 通配符按后缀长度降序，保证最长匹配优先
        lis.wildcard_rules.sort(key=lambda t: len(t[0]), reverse=True)

    # ------------------------------------------------------------- 路由

    def _match(self, lis: Listener, host: str | None) -> Rule | None:
        if not host:
            return None
        host = host.split(":")[0].lower()
        rule = lis.rules.get(host)
        if rule:
            return rule
        for suffix, r in lis.wildcard_rules:
            if host.endswith(suffix):
                return r
        return None

    # ------------------------------------------------------------- 请求处理

    async def _handle(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int
    ) -> None:
        lis = self._listeners.get(port)
        if not lis:
            writer.close()
            return

        peer = writer.get_extra_info("peername")
        try:
            request = await self._read_request(reader)
            if request is None:
                return
            method, target, version, headers = request

            host = headers.get("host")
            rule = self._match(lis, host)

            if rule is None:
                # 报错里只显示主机名，避免 "host:52441 ... on port 52441"
                # 这种端口重复出现、看起来像 bug 的写法
                clean_host = (host or "(none)").split(":")[0]
                known = sorted(lis.rules.keys())
                hint = ""
                if known:
                    shown = "、".join(known[:6])
                    if len(known) > 6:
                        shown += f" 等 {len(known)} 个"
                    hint = f"\n该端口已配置的域名：{shown}"
                elif lis.wildcard_rules:
                    hint = "\n该端口只有通配符规则，请检查域名后缀"

                await self._send_error(
                    writer, 404,
                    f"没有匹配的反向代理规则\n"
                    f"  请求域名：{clean_host}\n"
                    f"  监听端口：{port}{hint}",
                )
                return

            # HTTP → HTTPS 跳转（仅当该端口的规则要求）
            if rule.force_https and not lis.tls:
                location = self._https_location(rule, host)
                if location:
                    await self._send_redirect(writer, 301, location)
                    return

            await self._forward(reader, writer, method, target, version,
                                headers, rule, lis)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        except Exception:                             # noqa: BLE001
            log.exception("处理请求异常 port=%d peer=%s", port, peer)
            try:
                await self._send_error(writer, 502, "Bad Gateway")
            except Exception:                         # noqa: BLE001
                pass
        finally:
            try:
                writer.close()
            except Exception:                         # noqa: BLE001
                pass

    async def _read_request(
        self, reader: asyncio.StreamReader
    ) -> tuple[str, str, str, dict[str, str]] | None:
        try:
            head = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"), timeout=30
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            return None

        try:
            text = head.decode("iso-8859-1")
        except UnicodeDecodeError:
            return None

        lines = text.split("\r\n")
        if not lines or not lines[0]:
            return None

        parts = lines[0].split(" ")
        if len(parts) != 3:
            return None
        method, target, version = parts

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip().lower()] = v.strip()

        return method, target, version, headers

    def _https_location(self, rule: Rule, host: str | None) -> str | None:
        """构造 HTTPS 跳转地址。

        目标端口：如果该域名还有一条 TLS 规则，用它；否则跳过。
        """
        if not host:
            return None
        host_no_port = host.split(":")[0]

        # 在同端口集合里找该域名的 TLS 规则
        for lis in self._listeners.values():
            if not lis.tls:
                continue
            if self._match(lis, host_no_port) is not None:
                port_part = "" if lis.port == 443 else f":{lis.port}"
                return f"https://{host_no_port}{port_part}/"

        return None

    # ------------------------------------------------------------- 转发

    async def _forward(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        headers: dict[str, str],
        rule: Rule,
        lis: Listener,
    ) -> None:
        """把请求转发到后端，再把响应流式回传。"""
        is_upgrade = headers.get("upgrade", "").lower() == "websocket"

        try:
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(rule.target_host, rule.target_port),
                timeout=min(rule.timeout_sec, 10),
            )
        except (OSError, asyncio.TimeoutError) as exc:
            log.warning("后端连接失败 %s:%d -> %s",
                        rule.target_host, rule.target_port, exc)
            await self._send_error(
                client_writer, 502,
                f"Bad Gateway: 无法连接 {rule.target_host}:{rule.target_port}",
            )
            return

        try:
            # ---- 构造转发请求头 ----
            # ★ 用「黑名单」而不是白名单：只剔除逐跳头，其余原样转发。
            #   之前的白名单会漏掉这些关键头：
            #     transfer-encoding   → chunked 请求体无法被后端解析（P0-1）
            #     sec-websocket-key   → WebSocket 握手 100% 失败（P0-2）
            #     connection          → 带值的 Connection 被吞，后端不升级（P0-3）
            out_lines = [f"{method} {target} HTTP/1.1"]
            forwarded = set()
            for k, v in headers.items():
                # 逐跳头一律由代理重新构造，不直接转发
                if k in HOP_BY_HOP:
                    continue
                if k == "host":
                    host_val = (v if rule.preserve_host
                                else f"{rule.target_host}:{rule.target_port}")
                    out_lines.append(f"Host: {host_val}")
                else:
                    out_lines.append(f"{k.title()}: {v}")
                forwarded.add(k)

            # ★ chunked 请求体：必须显式带上 Transfer-Encoding 头，
            #   否则后端收到 chunk 字节流却以为没有 body。
            if headers.get("transfer-encoding", "").lower() == "chunked":
                out_lines.append("Transfer-Encoding: chunked")

            # ★ WebSocket 升级：显式构造 Connection + Upgrade，
            #   不管客户端原来怎么写的（可能是 keep-alive, Upgrade）。
            if is_upgrade:
                out_lines.append("Connection: Upgrade")
                out_lines.append(f"Upgrade: {headers.get('upgrade', 'websocket')}")

            out_lines.append("")
            backend_writer.write("\r\n".join(out_lines).encode("iso-8859-1"))
            await backend_writer.drain()

            # ---- 转发请求体 ----
            clen = headers.get("content-length")
            if clen and clen.isdigit() and int(clen) > 0:
                await self._pipe(backend_reader, backend_writer,
                                 int(clen), client_reader)
            elif headers.get("transfer-encoding", "").lower() == "chunked":
                await self._pipe_chunked(backend_reader, backend_writer,
                                         client_reader)

            # ---- 回传响应头 ----
            try:
                resp_head = await asyncio.wait_for(
                    backend_reader.readuntil(b"\r\n\r\n"),
                    timeout=rule.timeout_sec,
                )
            except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                    asyncio.LimitOverrunError):
                await self._send_error(client_writer, 504, "Gateway Timeout")
                return

            client_writer.write(resp_head)
            await client_writer.drain()

            # ---- 判断响应体长度 ----
            resp_text = resp_head.decode("iso-8859-1", "ignore")
            resp_clen = None
            resp_chunked = False
            for line in resp_text.split("\r\n")[1:]:
                if not line:
                    continue
                k, _, v = line.partition(":")
                kl = k.strip().lower()
                if kl == "content-length" and v.strip().isdigit():
                    resp_clen = int(v.strip())
                elif kl == "transfer-encoding" and "chunked" in v.lower():
                    resp_chunked = True

            # WebSocket 升级成功后进入双向透传
            if is_upgrade and "101" in resp_text.split("\r\n")[0]:
                await self._tunnel(client_reader, client_writer,
                                   backend_reader, backend_writer)
                return

            # ---- 回传响应体 ----
            if resp_clen is not None:
                await self._pipe(client_writer, client_writer,
                                 resp_clen, backend_reader)
            elif resp_chunked:
                await self._relay_all(backend_reader, client_writer)
            else:
                # 无长度信息且非 chunked：读到 EOF
                await self._relay_all(backend_reader, client_writer)

            await client_writer.drain()
        finally:
            try:
                backend_writer.close()
            except Exception:                         # noqa: BLE001
                pass

    async def _pipe(
        self,
        _dst_reader: asyncio.StreamReader,
        dst_writer: asyncio.StreamWriter,
        length: int,
        src_reader: asyncio.StreamReader,
    ) -> None:
        """精确转发 length 字节。"""
        remaining = length
        while remaining > 0:
            chunk = await src_reader.read(min(65536, remaining))
            if not chunk:
                break
            dst_writer.write(chunk)
            await dst_writer.drain()
            remaining -= len(chunk)

    async def _pipe_chunked(
        self,
        _dst_reader: asyncio.StreamReader,
        dst_writer: asyncio.StreamWriter,
        src_reader: asyncio.StreamReader,
    ) -> None:
        """转发 chunked 请求体（原样搬运分块）。"""
        while True:
            line = await src_reader.readuntil(b"\r\n")
            dst_writer.write(line)
            try:
                size = int(line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                # 读 trailer
                trailer = await src_reader.readuntil(b"\r\n")
                dst_writer.write(trailer)
                break
            data = await src_reader.readexactly(size + 2)
            dst_writer.write(data)
            await dst_writer.drain()

    async def _relay_all(
        self, src: asyncio.StreamReader, dst: asyncio.StreamWriter
    ) -> None:
        """读到 EOF 为止全量转发。"""
        while True:
            chunk = await src.read(65536)
            if not chunk:
                break
            dst.write(chunk)
            await dst.drain()

    async def _tunnel(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        backend_reader: asyncio.StreamReader,
        backend_writer: asyncio.StreamWriter,
    ) -> None:
        """WebSocket 双向透传。"""

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass

        await asyncio.gather(
            pump(client_reader, backend_writer),
            pump(backend_reader, client_writer),
            return_exceptions=True,
        )

    # ------------------------------------------------------------- 响应工具

    async def _send_error(
        self, writer: asyncio.StreamWriter, status: int, message: str
    ) -> None:
        body = message.encode("utf-8")
        head = (
            f"HTTP/1.1 {status} {self._reason(status)}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("iso-8859-1")
        writer.write(head + body)
        await writer.drain()

    async def _send_redirect(
        self, writer: asyncio.StreamWriter, status: int, location: str
    ) -> None:
        body = f"Redirecting to {location}".encode("utf-8")
        head = (
            f"HTTP/1.1 {status} {self._reason(status)}\r\n"
            f"Location: {location}\r\n"
            f"Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("iso-8859-1")
        writer.write(head + body)
        await writer.drain()

    @staticmethod
    def _reason(status: int) -> str:
        return {
            301: "Moved Permanently",
            302: "Found",
            400: "Bad Request",
            404: "Not Found",
            502: "Bad Gateway",
            504: "Gateway Timeout",
        }.get(status, "Error")

    # ------------------------------------------------------------- 状态

    def status(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for port, lis in sorted(self._listeners.items()):
            out.append({
                "port": port,
                "tls": lis.tls,
                "domains": sorted(lis.rules.keys()),
                "wildcards": [r.domains for _s, r in lis.wildcard_rules],
                "rules": len(set(id(r) for r in lis.rules.values())
                             | set(id(r) for _s, r in lis.wildcard_rules)),
            })
        return out
