"""种子证书生成。

fnOS 的 `cert.apply` 只接受**单域名**（服务端强校验 domain == DDNS 记录 domain），
多域名/通配符只能走「种子证书」路径：

    1. 生成自签多 SAN 种子证书（占位，从不用于 TLS）
    2. cert.upload   → SAN 从 X.509 解析入库
    3. cert.replace  → 补 renewal:1 + relatedDDNSId
    4. cert.renew    → fnOS 的 ACME 按全部 SAN 走 DNS-01 签真证书

★ 关键约束（实测）：
  * 种子证书必须 CA:FALSE。openssl req -x509 的默认扩展是 CA:TRUE，
    会导致 renew 报 "Certificate bundle starts with a CA certificate"。
  * CN 必须用**非通配符**域名。fnOS 把 CN 当证书主域名，
    续签时用它跟 DDNS 记录的 domain 比对；CN 是 *.x 会判 3000033。
  * 种子用 ECC → 签出 YE1/YE2（ECDSA 链）；用 RSA → YR1/YR2（RSA 链）。
    fnOS 的 ACME 会继承种子证书的密钥类型。
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any

log = logging.getLogger("dnrp.certs.seed")


class SeedError(RuntimeError):
    pass


def _run(args: list[str], **kw: Any) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(args, capture_output=True, timeout=60, check=False, **kw)


def pick_cn(domains: list[str]) -> str:
    """挑一个非通配符域名作为 CN。

    优先取列表里第一个非通配符域名；全是通配符时，把 *.x 去掉星号。
    """
    for d in domains:
        d = d.strip()
        if d and not d.startswith("*."):
            return d
    # 全是通配符：退化为去掉 "*."
    first = domains[0].strip()
    if first.startswith("*."):
        return first[2:]
    return first


def validate_domains(domains: list[str]) -> str:
    """校验域名列表，返回错误信息（空串表示通过）。"""
    if not domains:
        return "至少填写一个域名"

    import re

    pat = re.compile(r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")

    for d in domains:
        d = d.strip()
        if not d:
            return "域名列表里有空项"
        if not pat.match(d):
            return f"域名格式不合法: {d}"

    # 通配符只能出现在最左侧一级
    for d in domains:
        if "*" in d.strip() and not d.strip().startswith("*."):
            return f"通配符只能写作 *.example.com 形式: {d}"
        if d.strip().count("*") > 1:
            return f"通配符数量不合法: {d}"

    # 跨 zone 无法合成一张证书
    zones = set()
    for d in domains:
        parts = d.strip().lstrip("*.").split(".")
        zones.add(".".join(parts[-2:]))
    if len(zones) > 1:
        return (
            "跨根域无法合成一张证书（" + "、".join(sorted(zones)) + "），"
            "请按根域分别签发"
        )

    return ""


def gen_seed_cert(
    domains: list[str], ecc: bool = False, days: int = 365
) -> tuple[str, str]:
    """生成自签多 SAN 种子证书，返回 (cert_pem, key_pem)。

    ecc=True 时用 EC P-256；否则 RSA 2048。
    """
    cn = pick_cn(domains)
    san = ",".join(f"DNS:{d.strip()}" for d in domains)

    work = tempfile.mkdtemp(prefix="dnrp-seed-")
    try:
        keyf = os.path.join(work, "seed.key")
        crtf = os.path.join(work, "seed.crt")
        cnf = os.path.join(work, "openssl.cnf")

        # 显式写 CA:FALSE —— 这是 fnOS renew 能成功的前提
        with open(cnf, "w", encoding="utf-8") as fh:
            fh.write(
                "[req]\n"
                "distinguished_name = dn\n"
                "prompt = no\n"
                "x509_extensions = v3_req\n"
                "\n"
                "[dn]\n"
                f"CN = {cn}\n"
                "\n"
                "[v3_req]\n"
                "basicConstraints = critical,CA:FALSE\n"
                "keyUsage = critical,digitalSignature,keyEncipherment\n"
                "extendedKeyUsage = serverAuth\n"
                f"subjectAltName = {san}\n"
            )

        # 1) 生成密钥
        if ecc:
            r = _run(["openssl", "ecparam", "-name", "prime256v1",
                      "-genkey", "-noout", "-out", keyf])
        else:
            r = _run(["openssl", "genrsa", "-out", keyf, "2048"])
        if r.returncode != 0:
            raise SeedError("生成私钥失败: " + r.stderr.decode(errors="replace"))

        # 2) 自签证书（用 -config 强制 CA:FALSE）
        r = _run([
            "openssl", "req", "-new", "-x509",
            "-key", keyf, "-out", crtf,
            "-days", str(days),
            "-config", cnf,
            "-sha256",
        ])
        if r.returncode != 0:
            raise SeedError("生成证书失败: " + r.stderr.decode(errors="replace"))

        # 3) 校验确实是 CA:FALSE
        chk = _run(["openssl", "x509", "-in", crtf, "-noout", "-text"])
        text = chk.stdout.decode(errors="replace")
        if "CA:TRUE" in text:
            raise SeedError(
                "种子证书被生成为 CA:TRUE —— fnOS 的 renew 会拒绝。"
                "请检查 openssl 版本或配置文件。"
            )

        with open(crtf, "r", encoding="utf-8") as fh:
            cert_pem = fh.read()
        with open(keyf, "r", encoding="utf-8") as fh:
            key_pem = fh.read()

        return cert_pem, key_pem
    finally:
        shutil.rmtree(work, ignore_errors=True)


def read_cert_files(cert_path: str, key_path: str) -> tuple[str, str]:
    """读取磁盘上的真实证书（用于补备注）。"""
    with open(cert_path, "r", encoding="utf-8", errors="ignore") as fh:
        cert = fh.read()
    with open(key_path, "r", encoding="utf-8", errors="ignore") as fh:
        key = fh.read()
    return cert, key


def find_issued_dir(primary_domain: str, after_ts: float) -> str | None:
    """在 fnOS 证书目录里找刚签发的证书目录。

    fnOS 的布局：/usr/trim/var/trim_connect/ssls/<domain>/<epoch>/
    返回最新的、时间戳 >= after_ts 的目录路径。
    """
    from .. import config

    base = config.FNOS_SSL_ROOT / primary_domain
    if not base.is_dir():
        return None

    best: tuple[float, str] | None = None
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        try:
            ts = float(entry.name)
        except ValueError:
            continue
        if ts >= after_ts and (best is None or ts > best[0]):
            best = (ts, str(entry))

    return best[1] if best else None


def find_cert_in_dir(dir_path: str) -> tuple[str, str] | None:
    """在签发目录里找 cert / key 文件。

    文件名不统一（fullchain.crt / cert.crt / issued.crt / <domain>.crt），
    所以按「内容」判断而不是按名字。
    """
    import pathlib

    p = pathlib.Path(dir_path)
    if not p.is_dir():
        return None

    cert_file = None
    key_file = None

    for f in p.iterdir():
        if not f.is_file():
            continue
        name = f.name.lower()
        if cert_file is None and name.endswith(".crt"):
            # 优先 fullchain
            if "fullchain" in name:
                cert_file = f
            elif cert_file is None:
                cert_file = f
        if key_file is None and name.endswith(".key"):
            key_file = f

    # 重新挑一次：私钥优先选 private.key / *.private.key，
    # 避免同目录有 server.key 等其它 key 时选错（选错会毁掉证书密钥对）。
    for f in p.iterdir():
        if f.is_file() and f.name.lower().endswith(".key") \
                and "private" in f.name.lower():
            key_file = f
            break

    # 重新挑一次：fullchain 优先
    if cert_file is None or "fullchain" not in cert_file.name.lower():
        for f in p.iterdir():
            if f.is_file() and f.name.lower().endswith(".crt") \
                    and "fullchain" in f.name.lower():
                cert_file = f
                break

    if cert_file is None:
        return None
    # 私钥可能不存在（某些路径只给 cert）
    key_text = ""
    if key_file is not None:
        try:
            key_text = key_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            key_text = ""

    try:
        cert_text = cert_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None

    return cert_text, key_text
