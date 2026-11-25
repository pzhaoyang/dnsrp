"""DNS-RP 主程序入口。

启动顺序：
  1. 初始化 SQLite
  2. 启动反代引擎（读本地规则）
  3. 启动 API 服务（unix socket）
  4. 等待信号，退出时优雅关闭

设计：反代和 API 跑在同一个 asyncio 事件循环里，
好处是 API 修改规则后能立刻 `await proxy.apply()` 生效，无需重启进程。
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from . import config, store
from .api import server as api_server
from .proxy import engine as engine_mod


def setup_logging(verbose: bool = False) -> None:
    """配置日志：文件 + 控制台。"""
    config.ensure_dirs()

    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-5s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 文件：按大小轮转，避免占满根分区
    try:
        fh = RotatingFileHandler(
            config.LOG_FILE, maxBytes=config.LOG_MAX_BYTES,
            backupCount=2, encoding="utf-8",
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError as exc:
        print(f"无法写日志文件 {config.LOG_FILE}: {exc}", file=sys.stderr)

    # 控制台（systemd 捕获）
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    root.addHandler(sh)

    # 第三方噪音
    logging.getLogger("asyncio").setLevel(logging.WARNING)


def write_pid() -> None:
    try:
        config.PID_FILE.write_text(str(os.getpid()), encoding="utf-8")
    except OSError:
        pass


def clear_pid() -> None:
    try:
        config.PID_FILE.unlink()
    except OSError:
        pass


async def run(verbose: bool = False) -> int:
    setup_logging(verbose)
    log = logging.getLogger("dnrp")

    log.info("=" * 56)
    log.info("DNS-RP 启动中  (uid=%d, pid=%d)", os.getuid(), os.getpid())
    log.info("数据目录: %s", config.PKGVAR)

    # 1. 数据库
    store.init_db()
    log.info("SQLite 已就绪: %s", config.DB_PATH)

    # 2. 反代引擎
    proxy = engine_mod.ProxyEngine()
    rows = store.list_proxy_rules()
    rules = [engine_mod.Rule.from_row(r) for r in rows]
    if rules:
        await proxy.start(rules)
    else:
        log.info("暂无启用的反代规则")

    # 3. UI + API 服务（HTTP 端口，ui/config 里 type:url 直连这里）
    #
    # ★ 为什么用 HTTP 端口而不是 CGI：
    #   走 CGI 的话，调用 fnOS 内部接口需要用户的会话密钥做签名，
    #   而 CGI 环境拿不到。改为应用自己起 HTTP 服务，
    #   ui/config 用 type:url 让浏览器直连 —— 与 fncleankernel / OpenList
    #   等官方认可的第三方应用一致，用户点开即用，不需要任何认证。
    ui_port = config.UI_PORT
    api_task = asyncio.create_task(
        api_server.serve_http(ui_port, config.WWW_DIR, proxy),
        name="ui-http",
    )
    log.info("UI 访问地址: http://<NAS>: %d/", ui_port)

    # 4. 等信号
    stop = asyncio.Event()

    def on_signal() -> None:
        log.info("收到停止信号")
        stop.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, on_signal)
        except NotImplementedError:
            signal.signal(sig, lambda *_: stop.set())

    write_pid()
    log.info("DNS-RP 已就绪")

    try:
        await stop.wait()
    finally:
        log.info("正在关闭...")
        api_task.cancel()
        try:
            await api_task
        except (asyncio.CancelledError, Exception):   # noqa: BLE001
            pass
        await proxy.stop()
        clear_pid()
        try:
            Path(config.SOCKET_PATH).unlink()
        except OSError:
            pass
        log.info("已停止")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="dnrp", description="DNS-RP 主控进程")
    ap.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    ap.add_argument("--check", action="store_true", help="只做环境自检后退出")
    args = ap.parse_args(argv)

    if args.check:
        return do_check()

    try:
        return asyncio.run(run(args.verbose))
    except KeyboardInterrupt:
        return 0


def do_check() -> int:
    """环境自检：不启动服务，只报告各项能力是否就绪。"""
    from . import config as cfg
    from .proxy import certs as cert_mod

    print("=" * 60)
    print("DNS-RP 环境自检")
    print("=" * 60)

    # 自检时顺带建目录，方便首次部署
    try:
        cfg.ensure_dirs()
    except OSError as exc:
        print(f"\n⚠ 无法创建数据目录 {cfg.PKGVAR}: {exc}")

    print(f"\n运行身份: uid={os.getuid()} gid={os.getgid()}")
    try:
        import grp
        import pwd

        user = pwd.getpwuid(os.getuid()).pw_name
        groups = [grp.getgrgid(g).gr_name for g in os.getgroups()]
        print(f"用户: {user}")
        print(f"组:   {', '.join(groups)}")
        if "www-data" not in groups:
            print("  ⚠ 不在 www-data 组，可能读不到 fnOS 证书")
    except (KeyError, ImportError):
        pass

    print("\n--- 路径 ---")
    for name, path in [
        ("PKGVAR", cfg.PKGVAR),
        ("SQLite", cfg.DB_PATH),
        ("socket", cfg.SOCKET_PATH),
        ("证书登记表", cfg.FNOS_CERT_REGISTRY),
    ]:
        exists = "✓" if Path(path).exists() else "✗"
        print(f"  {exists} {name:<12} {path}")

    print("\n--- 证书 ---")
    entries = cert_mod.load_registry()
    readable = sum(1 for e in entries if e.readable())
    print(f"  登记表条目: {len(entries)}，可读: {readable}")
    if entries and readable == 0:
        print("  ⚠ 全部不可读 —— 请把应用用户加入 www-data 组")

    print("\n--- DDNS ---")
    try:
        from .ddns import fnos_db

        ok, detail = fnos_db.available()
        if ok:
            print(f"  ✓ 可访问 fnOS DDNS 表（{detail} 条记录）")
        else:
            print(f"  ✗ 无法访问: {detail}")
    except Exception as exc:              # noqa: BLE001
        print(f"  ✗ {exc}")

    print("\n--- 端口 ---")
    print(f"  保留端口: {sorted(cfg.RESERVED_PORTS)}")
    print(f"  默认监听: {cfg.DEFAULT_LISTEN_PORT}")

    print("\n自检完成。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
