#!/usr/bin/env python3
"""为 DNS-RP 应用配置 PostgreSQL 只读+DDNS 写权限。

改动三处：
  1. 创建 PG 角色 dnsrp（无 superuser、无 createdb）
  2. pg_ident.conf 加映射：OS 用户 DNS-RP -> PG 角色 dnsrp
  3. pg_hba.conf 在兜底 md5 规则**之前**插入 peer 规则

用法：
  python3 setup_pg_dnrp.py            # 应用改动
  python3 setup_pg_dnrp.py --rollback # 回滚
"""

import os
import re
import shutil
import subprocess
import sys
import time

HBA = "/etc/postgresql/15/main/pg_hba.conf"
IDENT = "/etc/postgresql/15/main/pg_ident.conf"
STAMP = time.strftime("%Y%m%d-%H%M%S")

OS_USER = "DNS-RP"
PG_ROLE = "dnsrp"
MAP_NAME = "dnsrp_local"

HBA_LINE = f"local   trim_connect    {PG_ROLE:<20}                        peer map={MAP_NAME}"
IDENT_LINE = f"{MAP_NAME:<14}{OS_USER:<14}{PG_ROLE}"

MARK_BEGIN = "# --- DNS-RP app access (added by DNS-RP fpk) ---"
MARK_END = "# --- end DNS-RP ---"


def run(cmd, **kw):
    """以 postgres 用户执行命令。"""
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def psql(sql, db="postgres"):
    return run(["sudo", "-n", "-u", "postgres", "psql", "-d", db,
                "-v", "ON_ERROR_STOP=1", "-A", "-t", "-c", sql])


def backup():
    for f in (HBA, IDENT):
        dst = f"{f}.bak-dnrp-{STAMP}"
        shutil.copy2(f, dst)
        print(f"  备份: {dst}")


def read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def write(p, text):
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


def rollback():
    print("=== 回滚 ===")
    # 1. 撤销授权并删角色
    psql("REVOKE ALL ON DATABASE trim_connect FROM dnsrp;")
    psql("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM dnsrp;", "trim_connect")
    r = psql("DROP ROLE IF EXISTS dnsrp;")
    print(f"  删除角色: {r.stdout.strip() or r.stderr.strip()}")

    # 2. 从两个配置文件删掉我们加的块
    for p in (HBA, IDENT):
        s = read(p)
        s2 = re.sub(rf"\n?{re.escape(MARK_BEGIN)}.*?{re.escape(MARK_END)}\n?",
                    "\n", s, flags=re.S)
        if s2 != s:
            write(p, s2)
            print(f"  已清理: {p}")

    run(["sudo", "-n", "systemctl", "reload", "postgresql"])
    print("  已 reload")


def main():
    if "--rollback" in sys.argv:
        rollback()
        return 0

    print("=== 1. 备份配置 ===")
    backup()

    print("\n=== 2. 创建 PG 角色 ===")
    r = psql(f"""
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{PG_ROLE}') THEN
            CREATE ROLE {PG_ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
          END IF;
        END $$;
    """)
    print(f"  {r.stdout.strip() or r.stderr.strip() or 'OK'}")

    print("\n=== 3. 授权（最小必要） ===")
    grants = [
        ("postgres", f"GRANT CONNECT ON DATABASE trim_connect TO {PG_ROLE};"),
        ("trim_connect", f"GRANT USAGE ON SCHEMA public TO {PG_ROLE};"),
        # DDNS：需要读写（增删改查）
        ("trim_connect",
         f"GRANT SELECT, INSERT, UPDATE, DELETE ON d_dns_record TO {PG_ROLE};"),
        ("trim_connect",
         f"GRANT USAGE, SELECT ON SEQUENCE d_dns_record_id_seq TO {PG_ROLE};"),
        # 证书：只读（用于展示 fnOS 证书实体）
        ("trim_connect", f"GRANT SELECT ON cert TO {PG_ROLE};"),
        ("trim_connect", f"GRANT SELECT ON cert_renew TO {PG_ROLE};"),
    ]
    for db, sql in grants:
        r = psql(sql, db)
        mark = "OK" if r.returncode == 0 else "FAIL"
        print(f"  [{mark}] {sql[:70]}")
        if r.returncode != 0:
            print(f"        {r.stderr.strip()[:200]}")

    print("\n=== 4. 修改 pg_ident.conf ===")
    s = read(IDENT)
    if MAP_NAME not in s:
        if not s.endswith("\n"):
            s += "\n"
        s += f"\n{MARK_BEGIN}\n{IDENT_LINE}\n{MARK_END}\n"
        write(IDENT, s)
        print(f"  已添加映射: {IDENT_LINE}")
    else:
        print("  映射已存在")

    print("\n=== 5. 修改 pg_hba.conf（插到兜底 md5 之前） ===")
    lines = read(HBA).splitlines(keepends=True)

    # 已存在则跳过
    if MAP_NAME in "".join(lines):
        print("  规则已存在")
    else:
        # 找第一条 "local all all md5"（兜底规则）
        insert_at = None
        for i, ln in enumerate(lines):
            body = ln.split("#", 1)[0].strip()
            if not body:
                continue
            parts = body.split()
            if (len(parts) >= 4 and parts[0] == "local"
                    and parts[1] == "all" and parts[2] == "all"
                    and parts[3] == "md5"):
                insert_at = i
                break

        if insert_at is None:
            print("  ✗ 没找到兜底 md5 规则，中止（不改动文件）")
            return 1

        block = [f"{MARK_BEGIN}\n", f"{HBA_LINE}\n", f"{MARK_END}\n"]
        lines[insert_at:insert_at] = block
        write(HBA, "".join(lines))
        print(f"  已插入到第 {insert_at + 1} 行之前")

    print("\n=== 6. reload PostgreSQL ===")
    r = run(["sudo", "-n", "systemctl", "reload", "postgresql"])
    print(f"  {r.stdout.strip() or r.stderr.strip() or 'OK'}")

    print("\n=== 7. 验证（以 DNS-RP 用户身份连库） ===")
    r = run(["sudo", "-n", "-u", OS_USER, "psql", "-U", PG_ROLE,
             "-d", "trim_connect", "-A", "-t", "-c",
             "select count(*) from d_dns_record;"])
    if r.returncode == 0:
        print(f"  ✓ 连接成功，d_dns_record 记录数 = {r.stdout.strip()}")
    else:
        print(f"  ✗ 连接失败: {r.stderr.strip()[:300]}")
        return 1

    print("\n=== 8. 最终 pg_hba.conf 规则 ===")
    for i, ln in enumerate(read(HBA).splitlines(), 1):
        if ln.strip() and not ln.strip().startswith("#"):
            print(f"  {i:>2}: {ln}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
