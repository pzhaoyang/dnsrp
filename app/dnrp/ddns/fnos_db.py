"""fnOS DDNS 数据访问层。

设计原则（重要）：
  * **只读写 d_dns_record 一张表**，不碰 trim_connect 的其他表。
  * **不保存、不解密 access_secret**。凭据留在 fnOS 数据库里，
    新增记录时从同根域的已有记录**复制密文**。
    （已实测：密文可复制使用，因为解密后是同一个 Token）
  * 实际 IP 上报完全交给 fnOS 自己的 gocron 定时任务，
    本模块只负责「登记」和「查状态」。

实测结论（imedia，fnOS 1.2.1011）：
  * 复制同根域凭据 -> 约 80 秒内 fnOS 完成上报，status 变 suc
  * 跨根域复制 -> 插入成功但 fnOS 上报会失败（Token 不属于该域）
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from typing import Any

from .. import config

log = logging.getLogger("dnrp.ddns")

# 常见二级后缀（用于判断根域）。fnOS 自己也是按「最后两段」粗判，
# 这里跟随同样策略，并对少数多段后缀做特判。
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "com.tw", "co.jp", "co.kr", "com.au",
}


def zone_of(domain: str) -> str:
    """从域名提取根域。

    a.b.example.com -> example.com
    x.com.cn          -> x.com.cn
    """
    d = domain.strip().lstrip("*.").lower()
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# ---------------------------------------------------------------- psql 封装


class PsqlError(RuntimeError):
    pass


def _run_psql(sql: str, db: str = config.FNOS_PG_DB_DDNS,
              tuples_only: bool = True) -> str:
    """执行 SQL。

    fnOS 的 postgres 用 peer 认证，需要以 postgres 用户执行 psql。

    ★ 实现要点（踩过的坑）：
      1. 临时文件必须放在 postgres 用户可读的位置（/tmp 默认 0600
         且属主是当前用户，postgres 读不到 → Permission denied）。
      2. 用 `install -m 600` 或在写完后 chmod 0644；
         更简单：写到 /tmp 后再 chmod a+r。
      3. 若已经是 root，直接用 `su postgres -c`；否则用 `sudo -n -u postgres`。
    """
    import os
    import shlex
    import tempfile

    flags = ["-t", "-A"] if tuples_only else ["-q"]

    # 用 /tmp 下的具名文件，确保 postgres 可读
    fd, path = tempfile.mkstemp(prefix="dnrp-", suffix=".sql", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(sql)
        os.chmod(path, 0o644)          # postgres 需要能读

        inner = (
            f"psql -U {shlex.quote(config.FNOS_PG_USER)} "
            f"-d {shlex.quote(db)} -v ON_ERROR_STOP=1 "
            + " ".join(flags)
            + f" -f {shlex.quote(path)}"
        )

        if os.geteuid() == 0:
            cmd = ["su", "-s", "/bin/sh", config.FNOS_PG_USER, "-c", inner]
        else:
            cmd = ["sudo", "-n", "-u", config.FNOS_PG_USER,
                   "sh", "-c", inner]

        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=30, check=False)
        if proc.returncode != 0:
            msg = (proc.stderr or proc.stdout or "").strip()
            raise PsqlError(msg or f"psql 退出码 {proc.returncode}")
        return proc.stdout
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _sql_str(value: str) -> str:
    """SQL 字符串字面量转义。"""
    return "'" + str(value).replace("'", "''") + "'"


# ---------------------------------------------------------------- 记录读取


def list_records() -> list[dict[str, Any]]:
    """列出 fnOS 的全部 DDNS 记录。**不含凭据**。"""
    sql = """
        SELECT id, domain, provider, ipv4, ipv6, ipv4_addr, ipv6_addr,
               ttl, status, last_update_time, update_interval,
               last_update_error, created_time, updated_time
        FROM d_dns_record
        ORDER BY id;
    """
    out = _run_psql(sql)
    rows: list[dict[str, Any]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        f = line.split("|")
        if len(f) < 13:
            continue
        rows.append({
            "id": int(f[0]),
            "domain": f[1],
            "provider": f[2],
            "ipv4": f[3],
            "ipv6": f[4],
            "ipv4_addr": f[5],
            "ipv6_addr": f[6],
            "ttl": f[7],
            "status": f[8],
            "last_update_time": f[9],
            "update_interval": f[10],
            "last_update_error": f[11],
            "zone": zone_of(f[1]),
        })
    return rows


def list_zones() -> list[dict[str, Any]]:
    """列出可用的根域及其模板记录（供新增时复制凭据）。

    用原始字符串避免正则里的 \\. 触发 Python 转义警告。
    """
    sql = r"""
        SELECT DISTINCT ON (substring(domain from '([^.]+\.[^.]+)$'))
               id, domain, provider
        FROM d_dns_record
        ORDER BY substring(domain from '([^.]+\.[^.]+)$'), id;
    """
    out = _run_psql(sql)
    zones: list[dict[str, Any]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        f = line.split("|")
        if len(f) < 3:
            continue
        zones.append({
            "recordId": int(f[0]),
            "domain": f[1],
            "provider": f[2],
            "zone": zone_of(f[1]),
        })
    return zones


def find_template(zone: str) -> dict[str, Any] | None:
    """找一条同根域的记录作为凭据模板（含密文，仅内部使用）。

    ★ 注意：SELECT 了 9 列，split 后长度必须 >= 9。
      早期写成 < 10 会导致永远返回 None（off-by-one 坑）。
    """
    sql = f"""
        SELECT id, domain, provider, access_key, access_secret,
               ipv4, ipv6, ttl, update_interval
        FROM d_dns_record
        WHERE domain = {_sql_str(zone)}
           OR domain = {_sql_str('*.' + zone)}
           OR domain LIKE {_sql_str('%.' + zone)}
        ORDER BY
          CASE WHEN domain = {_sql_str(zone)} THEN 0
               WHEN domain = {_sql_str('*.' + zone)} THEN 1
               ELSE 2 END,
          id
        LIMIT 1;
    """
    out = _run_psql(sql)
    for line in out.splitlines():
        if not line.strip():
            continue
        f = line.split("|")
        if len(f) < 9:
            continue
        return {
            "id": int(f[0]),
            "domain": f[1],
            "provider": f[2],
            "access_key": f[3],
            "access_secret": f[4],
            "ipv4": f[5] or "auto",
            "ipv6": f[6] or "auto",
            "ttl": f[7] or "600",
            "update_interval": f[8] or "5",
        }
    return None


def get_record(domain: str) -> dict[str, Any] | None:
    for r in list_records():
        if r["domain"] == domain:
            return r
    return None


# ---------------------------------------------------------------- 记录写入


def create_record(
    domain: str,
    provider: str,
    access_key: str,
    access_secret: str,
    update_interval: int = 5,
    ttl: int = 600,
    ipv4: str = "auto",
    ipv6: str = "auto",
) -> int:
    """插入一条 DDNS 记录，返回新记录 id。

    凭据由调用方从同根域模板复制传入。fnOS 的定时任务会在
    update_interval 分钟内接手上报。
    """
    now_ms = int(time.time() * 1000)
    sql = f"""
        INSERT INTO d_dns_record
          (provider, domain, ipv4, ipv6, ttl, access_key, access_secret,
           status, last_update_time, update_interval, query_url,
           last_update_error, created_time, updated_time)
        VALUES
          ({_sql_str(provider)}, {_sql_str(domain)},
           {_sql_str(ipv4)}, {_sql_str(ipv6)}, {int(ttl)},
           {_sql_str(access_key)}, {_sql_str(access_secret)},
           'init', {now_ms}, {int(update_interval)}, '', '', {now_ms}, {now_ms})
        RETURNING id;
    """
    out = _run_psql(sql)
    for line in out.splitlines():
        line = line.strip()
        if line.isdigit():
            return int(line)
    raise PsqlError("插入后未返回记录 id")


def delete_record(domain: str) -> bool:
    """删除一条 DDNS 记录（只删数据库，不动远端 DNS 记录）。"""
    sql = f"DELETE FROM d_dns_record WHERE domain = {_sql_str(domain)};"
    try:
        _run_psql(sql, tuples_only=False)
        return True
    except PsqlError as exc:
        log.warning("删除 %s 失败: %s", domain, exc)
        return False


def update_interval_of(domain: str) -> int:
    rec = get_record(domain)
    if not rec:
        return 5
    try:
        return int(rec.get("update_interval") or 5)
    except (TypeError, ValueError):
        return 5


# ---------------------------------------------------------------- 可用性探测


def available() -> tuple[bool, str]:
    """探测能否访问 fnOS 的 DDNS 表。"""
    try:
        out = _run_psql("SELECT count(*) FROM d_dns_record;")
        return True, out.strip()
    except (PsqlError, OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
