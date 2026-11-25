"""dnsrp 本地状态存储（SQLite）。

只存「本应用自己的」状态：反代规则、以及 DDNS/证书到 fnOS 的映射关系。
真正的凭据、证书内容都不在这里 —— 它们在 fnOS 侧。

三张表：
  proxy_rule  反代规则（本应用独有）
  ddns_link   DDNS 记录与 fnOS d_dns_record.id 的映射
  cert_link   证书与 fnOS cert.id 的映射
"""

from __future__ import annotations

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import config

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- 反代规则
CREATE TABLE IF NOT EXISTS proxy_rule (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    domains       TEXT    NOT NULL,            -- 逗号分隔
    listen_port   INTEGER NOT NULL,
    listen_tls    INTEGER NOT NULL DEFAULT 0,
    cert_id       INTEGER,                     -- 为空=按域名自动匹配
    target_scheme TEXT    NOT NULL DEFAULT 'http',
    target_host   TEXT    NOT NULL,
    target_port   INTEGER NOT NULL,
    force_https   INTEGER NOT NULL DEFAULT 0,
    preserve_host INTEGER NOT NULL DEFAULT 0,
    timeout_sec   INTEGER NOT NULL DEFAULT 30,
    created_time  INTEGER NOT NULL,
    updated_time  INTEGER NOT NULL
);

-- DDNS：本地视图 + 指向 fnOS 记录的 id
CREATE TABLE IF NOT EXISTS ddns_link (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    domain          TEXT    NOT NULL UNIQUE,
    zone            TEXT    NOT NULL,
    provider        TEXT    NOT NULL DEFAULT 'cloudflare',
    fnos_record_id  INTEGER,                   -- 对应 d_dns_record.id
    template_domain TEXT,                      -- 从哪条记录复制的凭据
    update_interval INTEGER NOT NULL DEFAULT 5,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_time    INTEGER NOT NULL,
    updated_time    INTEGER NOT NULL
);

-- 证书：本地视图 + 指向 fnOS cert 记录
CREATE TABLE IF NOT EXISTS cert_link (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fnos_cert_id    INTEGER,                   -- 对应 cert.id
    primary_domain  TEXT    NOT NULL,
    domains         TEXT    NOT NULL,          -- 逗号分隔
    key_type        TEXT    NOT NULL DEFAULT 'RSA',
    auto_renew      INTEGER NOT NULL DEFAULT 1,
    desc_text       TEXT,
    created_time    INTEGER NOT NULL,
    updated_time    INTEGER NOT NULL,
    UNIQUE(fnos_cert_id)
);

CREATE INDEX IF NOT EXISTS idx_proxy_port ON proxy_rule(listen_port);
CREATE INDEX IF NOT EXISTS idx_ddns_zone  ON ddns_link(zone);
CREATE INDEX IF NOT EXISTS idx_cert_dom   ON cert_link(primary_domain);
"""


def _now() -> int:
    return int(time.time())


def _db_path() -> Path:
    return config.DB_PATH


@contextmanager
def connect(path: Path | None = None) -> Iterator[sqlite3.Connection]:
    """打开数据库连接，自动提交/回滚。"""
    db = path or _db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db), timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(path: Path | None = None) -> None:
    """初始化表结构（幂等）。"""
    with connect(path) as conn:
        conn.executescript(SCHEMA)


# ------------------------------------------------------------------ proxy_rule


def list_proxy_rules(path: Path | None = None) -> list[dict[str, Any]]:
    with connect(path) as conn:
        rows = conn.execute(
            "SELECT * FROM proxy_rule ORDER BY listen_port, id"
        ).fetchall()
    return [dict(r) for r in rows]


def get_proxy_rule(rule_id: int, path: Path | None = None) -> dict[str, Any] | None:
    with connect(path) as conn:
        row = conn.execute(
            "SELECT * FROM proxy_rule WHERE id=?", (rule_id,)
        ).fetchone()
    return dict(row) if row else None


def upsert_proxy_rule(data: dict[str, Any], path: Path | None = None) -> int:
    """新增或更新反代规则，返回 id。

    注意：schema 里多数列是 NOT NULL，而前端可能不传某些可选字段
    （如 force_https / preserve_host），所以这里必须给每个字段兜底，
    不能用 data.get(f) 直接取（会得到 None 触发 NOT NULL 约束）。
    """
    now = _now()
    rule_id = data.get("id")

    def _bool(v: Any, default: int = 0) -> int:
        if v is None:
            return default
        return 1 if v else 0

    def _int(v: Any, default: int) -> int:
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    domains = data.get("domains")
    if isinstance(domains, (list, tuple)):
        domains = ",".join(str(d).strip() for d in domains if str(d).strip())
    domains = (domains or "").strip()

    fields = [
        "name", "enabled", "domains", "listen_port", "listen_tls",
        "cert_id", "target_scheme", "target_host", "target_port",
        "force_https", "preserve_host", "timeout_sec",
    ]
    values = [
        (data.get("name") or "").strip(),
        _bool(data.get("enabled"), 1),
        domains,
        _int(data.get("listen_port"), config.DEFAULT_LISTEN_PORT),
        _bool(data.get("listen_tls")),
        data.get("cert_id") or None,
        (data.get("target_scheme") or "http").strip(),
        (data.get("target_host") or "127.0.0.1").strip(),
        _int(data.get("target_port"), 80),
        _bool(data.get("force_https")),
        _bool(data.get("preserve_host")),
        _int(data.get("timeout_sec"), 30),
    ]

    with connect(path) as conn:
        if rule_id:
            sets = ", ".join(f"{f}=?" for f in fields)
            conn.execute(
                f"UPDATE proxy_rule SET {sets}, updated_time=? WHERE id=?",
                (*values, now, int(rule_id)),
            )
            return int(rule_id)

        cols = ", ".join(fields)
        ph = ", ".join("?" for _ in fields)
        cur = conn.execute(
            f"INSERT INTO proxy_rule ({cols}, created_time, updated_time) "
            f"VALUES ({ph}, ?, ?)",
            (*values, now, now),
        )
        # 冲突分支回查真实 id
        cid = data.get("fnos_cert_id")
        if cid is not None:
            row = conn.execute(
                "SELECT id FROM cert_link WHERE fnos_cert_id=?", (cid,)).fetchone()
            if row:
                return int(row["id"])
        return int(cur.lastrowid)


def delete_proxy_rule(rule_id: int, path: Path | None = None) -> bool:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM proxy_rule WHERE id=?", (rule_id,))
        return cur.rowcount > 0


# ------------------------------------------------------------------- ddns_link


def list_ddns(path: Path | None = None) -> list[dict[str, Any]]:
    with connect(path) as conn:
        rows = conn.execute("SELECT * FROM ddns_link ORDER BY domain").fetchall()
    return [dict(r) for r in rows]


def upsert_ddns(data: dict[str, Any], path: Path | None = None) -> int:
    now = _now()
    with connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO ddns_link
              (domain, zone, provider, fnos_record_id, template_domain,
               update_interval, enabled, created_time, updated_time)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(domain) DO UPDATE SET
               zone=excluded.zone,
               provider=excluded.provider,
               fnos_record_id=COALESCE(excluded.fnos_record_id, ddns_link.fnos_record_id),
               template_domain=excluded.template_domain,
               update_interval=excluded.update_interval,
               enabled=excluded.enabled,
               updated_time=excluded.updated_time
            """,
            (
                data.get("domain") or "",
                data.get("zone") or "",
                data.get("provider", "cloudflare"),
                data.get("fnos_record_id"),
                data.get("template_domain"),
                int(data.get("update_interval", 5) or 5),
                1 if data.get("enabled", True) else 0,
                now,
                now,
            ),
        )
        # ON CONFLICT DO UPDATE 时 lastrowid 不可靠，回查真实 id
        dom = data.get("domain") or ""
        row = conn.execute(
            "SELECT id FROM ddns_link WHERE domain=?", (dom,)).fetchone()
        return int(row["id"]) if row else int(cur.lastrowid or 0)


def delete_ddns(domain: str, path: Path | None = None) -> bool:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM ddns_link WHERE domain=?", (domain,))
        return cur.rowcount > 0


# ------------------------------------------------------------------- cert_link


def list_certs(path: Path | None = None) -> list[dict[str, Any]]:
    with connect(path) as conn:
        rows = conn.execute("SELECT * FROM cert_link ORDER BY id").fetchall()
    return [dict(r) for r in rows]


def upsert_cert(data: dict[str, Any], path: Path | None = None) -> int:
    now = _now()
    with connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO cert_link
              (fnos_cert_id, primary_domain, domains, key_type,
               auto_renew, desc_text, created_time, updated_time)
            VALUES (?,?,?,?,?,?,?,?)
            ON CONFLICT(fnos_cert_id) DO UPDATE SET
               primary_domain=excluded.primary_domain,
               domains=excluded.domains,
               key_type=excluded.key_type,
               auto_renew=excluded.auto_renew,
               desc_text=excluded.desc_text,
               updated_time=excluded.updated_time
            """,
            (
                data.get("fnos_cert_id"),
                data.get("primary_domain") or "",
                data.get("domains") or "",
                data.get("key_type", "RSA"),
                1 if data.get("auto_renew", True) else 0,
                data.get("desc_text"),
                now,
                now,
            ),
        )
        return int(cur.lastrowid)


def update_cert_fnos_id(local_id: int, fnos_cert_id: int,
                        path: Path | None = None) -> None:
    with connect(path) as conn:
        conn.execute(
            "UPDATE cert_link SET fnos_cert_id=?, updated_time=? WHERE id=?",
            (fnos_cert_id, _now(), local_id),
        )


def delete_cert(local_id: int, path: Path | None = None) -> bool:
    with connect(path) as conn:
        cur = conn.execute("DELETE FROM cert_link WHERE id=?", (local_id,))
        return cur.rowcount > 0
