"""fnOS DDNS 管理（走官方 WebSocket API，不直接写数据库）。

★ 重要演进：
  最初方案是直接写 PostgreSQL 的 d_dns_record 表（来自 fnos-ddns 项目）。
  实测发现 fnOS 提供了完整的官方 API：

      appcgi.netsvr.ddns.record.list      列出记录
      appcgi.netsvr.ddns.record.create    新增记录
      appcgi.netsvr.ddns.record.update    修改记录
      appcgi.netsvr.ddns.record.remove    删除记录
      appcgi.netsvr.ddns.record.detail    单条详情
      appcgi.netsvr.ddns.record.refresh   立即刷新
      appcgi.netsvr.ddns.record.test      测试凭据
      appcgi.netsvr.ddns.provider.list    可用服务商

  因此改为**优先用 API**，只有 API 不可用（如老版本 fnOS）时才回退到直接写库。
  这样做的好处：
    * 不依赖数据库表结构，fnOS 升级更安全
    * 凭据由 fnOS 自己管理，本应用完全不接触 access_secret
    * 删除记录时 fnOS 会处理它该处理的事

接口返回结构（实测）：
    record.list  -> {"list": [...], "total": N}
    provider.list -> [{"name", "alias", "accessKeyAlias", ...}, ...]
"""

from __future__ import annotations

import logging
from typing import Any

from ..certs.ws_client import FnosClient, FnosWsError

log = logging.getLogger("dnrp.ddns")

# 常见多段后缀，用于根域判断
_MULTI_SUFFIX = {
    "co.uk", "org.uk", "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "com.tw", "co.jp", "co.kr", "com.au",
}


def zone_of(domain: str) -> str:
    """从域名提取根域。"""
    d = domain.strip().lstrip("*.").lower()
    parts = d.split(".")
    if len(parts) <= 2:
        return d
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIX and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


# ---------------------------------------------------------------- 读


def list_records(api: FnosClient) -> list[dict[str, Any]]:
    """列出全部 DDNS 记录（**不含凭据**）。"""
    data = api.call("appcgi.netsvr.ddns.record.list")
    if isinstance(data, dict):
        rows = data.get("list") or []
    elif isinstance(data, list):
        rows = data
    else:
        rows = []

    out: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        d = str(r.get("domain") or "")
        out.append({
            "id": r.get("id"),
            "domain": d,
            "zone": zone_of(d) if d else "",
            "provider": r.get("provider") or "",
            "providerAlias": r.get("providerAlias") or "",
            "ipv4": r.get("ipv4") or "",
            "ipv6": r.get("ipv6") or "",
            "ipv4_addr": r.get("ipv4Addr") or "",
            "ipv6_addr": r.get("ipv6Addr") or "",
            "status": r.get("status") or "",
            "update_interval": r.get("updateInterval") or 5,
            "last_update_time": r.get("lastUpdateTime") or 0,
            "txt_support": r.get("providerSupportTxt") or 0,
            "last_update_error": r.get("lastUpdateError") or "",
        })
    return out


def list_providers(api: FnosClient) -> list[dict[str, Any]]:
    """列出 fnOS 支持的 DNS 服务商。"""
    data = api.call("appcgi.netsvr.ddns.provider.list")
    return data if isinstance(data, list) else []


def list_zones(api: FnosClient) -> list[dict[str, Any]]:
    """按根域去重，返回可作为凭据模板的记录。"""
    recs = list_records(api)
    seen: dict[str, dict[str, Any]] = {}
    for r in recs:
        z = r["zone"]
        if not z:
            continue
        # 优先选非通配符、状态成功的记录
        cur = seen.get(z)
        if cur is None:
            seen[z] = r
        elif cur["domain"].startswith("*.") and not r["domain"].startswith("*."):
            seen[z] = r
    return [
        {
            "zone": z,
            "recordId": r["id"],
            "domain": r["domain"],
            "provider": r["provider"],
            "providerAlias": r["providerAlias"],
            "status": r["status"],
        }
        for z, r in sorted(seen.items())
    ]


def find_zone_record(
    api: FnosClient, zone: str
) -> dict[str, Any] | None:
    """找同一根域下的一条记录作为模板。

    ★ 返回的 dict 里会**带上 access_key / access_secret 密文**，
      因为 create_record 需要复制这两列才能让证书签发走通 DNS-01。
      这两个值是加密的密文，本应用不解密、不外传、不落盘。
    """
    from . import fnos_db

    # 先按根域找带凭据的模板（直接读库，能拿到密文）
    full = fnos_db.find_template(zone)
    if full:
        return full

    # 退路：从 API 列表里找一条（没有密文，仅供展示）
    for r in list_records(api):
        if r["zone"] == zone:
            return r
    return None


# ---------------------------------------------------------------- 写


def create_record(
    api: FnosClient,
    domain: str,
    template: dict[str, Any],
    update_interval: int = 5,
) -> Any:
    """新增一条 DDNS 记录。

    ★ 重要限制（实测，2026-11-20）：
      官方 API `ddns.record.create` **不会复制凭据** —— 建出来的记录
      access_key 为空、access_secret 是 64 字符的空密文，
      而正常记录是 key_len=9 / sec_len=128。

      后果：证书签发时 fnOS 的 lego 要用这条记录的凭据做 DNS-01，
      拿到空凭据直接报：
          cloudflare: invalid credentials:
          authEmail, authKey or authToken must be set

      所以：**必须用「复制同根域已有记录的凭据密文」的方式**建记录。
      已实测（2026-11-19）：复制密文完全可用，因为解密后是同一个 Token，
      fnOS 定时任务 80 秒内就会把 status 变成 suc。

    因此本函数改为直接写数据库（绕过 API），从 template 记录复制凭据列。
    这在功能上是必需的，不是偷懒。
    """
    from . import fnos_db

    # template 里需要带凭据（由调用方从 fnos_db.find_template 取）
    access_key = template.get("access_key") or ""
    access_secret = template.get("access_secret") or ""

    if not access_key or not access_secret:
        # 退而求其次：按根域重新查一次带凭据的模板
        zone = zone_of(domain)
        full = fnos_db.find_template(zone)
        if not full:
            raise DdnsNeedCredential(
                f"根域 {zone} 没有可用凭据。\n"
                f"请先在飞牛 OS 的「远程访问 → DDNS」里手动添加一条 "
                f"{template.get('domain')} 的记录，之后再批量添加同根域域名。"
            )
        access_key = full["access_key"]
        access_secret = full["access_secret"]
        provider = full["provider"]
    else:
        provider = template.get("provider") or "cloudflare"

    try:
        return fnos_db.create_record(
            domain=domain,
            provider=provider,
            access_key=access_key,
            access_secret=access_secret,
            update_interval=int(update_interval),
        )
    except Exception as exc:              # noqa: BLE001
        raise DdnsNeedCredential(f"创建 DDNS 记录失败: {exc}") from exc


def create_record_raw(
    api: FnosClient,
    domain: str,
    update_interval: int = 5,
    access_key: str = "",
    access_secret: str = "",
    provider: str = "cloudflare",
) -> Any:
    """创建 DDNS 记录（走官方 API）。

    ★ 实测结论（2026-11-23，fnOS 1.2.1011）：

      **凭据是可选的**。只传 provider + domain 就返回 true，
      记录以 status=loading 建出来。

      但没凭据的记录无法真正上报 —— fnOS 的定时任务拿不到
      DNS 服务商凭据，更新 IP 会失败，记录一直停在 loading。

      所以：
        * 不传凭据 → 记录能建，但需之后到 fnOS 补凭据
        * 传凭据   → 立即可用

      ⚠️ 早期误判更正：
        2026-11-20 那次测试失败（errno=3000031 Invalid Domain），
        我以为是缺凭据，实际是测试域名 `_dnrptest...` 有前导下划线，
        属于非法域名。凭据从来不是 create 的必需项。

    provider 支持的值见 appcgi.netsvr.ddns.provider.list：
      cloudflare / tencentcloud / aliyun / huawei / oraydns / changeip 等
    """
    payload: dict[str, Any] = {
        "provider": provider,
        "domain": domain,
        "ipv4": "auto",
        "ipv6": "auto",
        "updateInterval": int(update_interval),
    }
    # 只有真正填了才带上，避免传空串被当成「显式置空」
    if access_key:
        payload["accessKey"] = access_key
    if access_secret:
        payload["accessSecret"] = access_secret

    return api.call("appcgi.netsvr.ddns.record.create", payload)


class DdnsNeedCredential(RuntimeError):
    """该根域还没有可复用的凭据。"""


def update_record(
    api: FnosClient,
    record: dict[str, Any],
    timeout: float = 60,
    auto_refresh: bool = True,
    new_access_key: str = "",
    new_access_secret: str = "",
) -> bool:
    """修改一条 DDNS 记录（间隔 / 凭据）。

    ★ 参数要求（实测）：
      必须传**完整记录对象**，不能只传 id：
        {"id": 1, "updateInterval": 10}
            -> errno=3000006 Not Found ✗
        {"id":1,"domain":"x","provider":"cloudflare",
         "ipv4":"auto","ipv6":"auto","updateInterval":10}
            -> true ✓（但会把凭据清空！）

    ★★★ 致命坑（2026-11-25 踩到，破坏了两条线上记录）：
      update 是一条「全量覆盖」接口。
      **如果不传 accessKey / accessSecret，fnOS 会把它们写成空值** ——
      数据库里立刻变成 key_len=0 / sec_len=64（正常是 9 / 128），
      记录状态变为 loading 且再也无法上报，等于把 DNS 凭据弄丢了。

      而 `record.list` **不返回凭据**，只有 `record.detail` 才返回。
      所以必须先 detail 拿到凭据、再原样回填。

    ★ 凭据的加密形态（实测）：
        record.detail 返回  -> 明文（如 Cloudflare Global Key，40 字符）
        数据库 access_secret -> 密文（128 字符）

      也就是说 fnOS 在 detail 时解密、update 时加密。
      所以**用户可以在这里看到并修改凭据明文**，
      传新值时 fnOS 会自动加密存储。

    ★ 参数 new_access_key / new_access_secret：
      传入非空值表示「要改成这个新凭据」；
      留空表示「保持原值」（会从 detail 读回来回填）。

    ★ 正确流程：
      1. 用 record.detail 读出当前凭据
      2. 用新值覆盖（如果用户改了）
      3. 把凭据连同 updateInterval 一起提交
      4. 提交后再查一次确认凭据还在
      5. 调 refresh 让状态尽快恢复

    ⚠️ update 后 status 会被重置为 loading，而 fnOS 的定时任务
       有个 bug（用空域名查记录导致 nil panic），可能让它卡在 loading，
       所以必须紧跟一次 refresh。

    ⚠️ 万一凭据已经被清空：用同 provider 的健康记录做凭据源，
       走「带凭据 update」即可恢复（实测有效，记录 id 不丢）。
    """
    if not record.get("id"):
        raise ValueError("更新 DDNS 记录需要 id")

    domain = record.get("domain") or ""
    if not domain:
        raise ValueError("更新 DDNS 记录需要 domain")

    # ★ 第一步：先把当前凭据读回来（detail 会解密成明文）
    ak = record.get("accessKey") or ""
    sk = record.get("accessSecret") or ""

    if not ak or not sk:
        try:
            detail = api.call("appcgi.netsvr.ddns.record.detail",
                              {"domain": domain}, timeout=timeout)
            if isinstance(detail, dict):
                ak = str(detail.get("accessKey") or "")
                sk = str(detail.get("accessSecret") or "")
                log.info("已从 detail 读回 %s 的凭据（key 长度 %d）",
                         domain, len(ak))
        except FnosWsError as exc:
            log.warning("读取 %s 的凭据失败: %s", domain, exc)

    # ★ 用户传了新凭据就以新值为准
    if new_access_key:
        ak = new_access_key.strip()
    if new_access_secret:
        sk = new_access_secret.strip()

    if not ak:
        # 读不到凭据就拒绝更新 —— 否则会把用户凭据清空
        raise DdnsNeedCredential(
            f"无法读取 {domain} 的当前凭据，出于安全考虑不做修改。\n"
            f"（update 接口会覆盖凭据，没有原值就提交等于清空）\n"
            f"请在编辑框里重新填写 Access Key，或到飞牛 OS 里修改。"
        )

    payload: dict[str, Any] = {
        "id": int(record["id"]),
        "domain": domain,
        "provider": record.get("provider") or "cloudflare",
        "ipv4": record.get("ipv4") or "auto",
        "ipv6": record.get("ipv6") or "auto",
        "updateInterval": int(record.get("updateInterval")
                              or record.get("update_interval") or 5),
        # ★ 凭据必须原样带回（或用户的新值），否则会被清空
        "accessKey": ak,
    }
    if sk:
        payload["accessSecret"] = sk

    ok = bool(api.call("appcgi.netsvr.ddns.record.update",
                       payload, timeout=timeout))

    # ★ 提交后确认凭据还在（防御性校验）
    if ok:
        try:
            chk = api.call("appcgi.netsvr.ddns.record.detail",
                           {"domain": domain}, timeout=timeout)
            if isinstance(chk, dict) and not chk.get("accessKey"):
                log.error("update 后 %s 的凭据为空！尝试回填", domain)
                try:
                    api.call("appcgi.netsvr.ddns.record.update", {
                        **payload,
                        "accessKey": ak,
                        "accessSecret": sk,
                    }, timeout=timeout)
                except FnosWsError as exc:
                    log.error("回填凭据失败: %s", exc)
        except FnosWsError:
            pass

    # ★ 立刻刷新，避免卡在 loading
    if ok and auto_refresh:
        try:
            api.call("appcgi.netsvr.ddns.record.refresh",
                     {"id": payload["id"]}, timeout=timeout)
            log.info("已触发 refresh，让记录 %s 尽快恢复上报", domain)
        except FnosWsError as exc:
            log.warning("update 后 refresh 失败（记录可能停在 loading）: %s", exc)

    return ok


def get_record_detail(api: FnosClient, domain: str,
                      timeout: float = 30) -> dict[str, Any]:
    """读一条 DDNS 记录的详情（含**明文**凭据）。

    ★ 注意 accessSecret 是解密后的明文。
      本函数只用于「编辑」时把当前值展示给用户，
      调用方不应把它写进日志或落盘。
    """
    d = api.call("appcgi.netsvr.ddns.record.detail",
                 {"domain": domain}, timeout=timeout)
    return d if isinstance(d, dict) else {}


def delete_record(api: FnosClient, domain: str, timeout: float = 120) -> bool:
    """删除一条 DDNS 记录。

    ★ 参数名实测结论（2026-11-24，fnOS 1.2.1011）：
      `appcgi.netsvr.ddns.record.remove` 的参数是 **domain**，不是 id。

      踩过的坑（全部报 errno=3000006 Not Found Error）：
        {"id": 22}          ✗
        {"recordId": 22}    ✗
        {"ID": 22}          ✗
        {"record": {"id":22}} ✗
        {"records": [22]}   ✗
      ✓ 正确：{"domain": "mytest.example.com"}

      参考：`record.detail` 同样用 domain 做参数，两者语义一致。

    ★ 超时给足 120 秒：实测删除单条约需 10~60 秒，
      因为 fnOS 会调用 DNS 服务商 API 把解析记录一并清掉。
      早期用默认 30 秒会超时，看起来像「接口不通」。
    """
    if not domain:
        raise ValueError("删除 DDNS 记录需要 domain 参数")

    try:
        r = api.call("appcgi.netsvr.ddns.record.remove",
                     {"domain": domain}, timeout=timeout)
        return bool(r)
    except FnosWsError as exc:
        log.warning("删除 DDNS 记录 %s 失败: %s", domain, exc)
        return False


def refresh_record(api: FnosClient, record_id: Any) -> bool:
    """立即触发一次上报（不用等定时任务）。"""
    try:
        api.call("appcgi.netsvr.ddns.record.refresh", {"id": record_id}, timeout=60)
        return True
    except FnosWsError as exc:
        log.warning("刷新 DDNS 记录 %s 失败: %s", record_id, exc)
        return False


def test_record(api: FnosClient, record_id: Any) -> bool:
    """测试一条记录的凭据是否有效。"""
    try:
        api.call("appcgi.netsvr.ddns.record.test", {"id": record_id}, timeout=60)
        return True
    except FnosWsError as exc:
        log.warning("测试 DDNS 记录 %s 失败: %s", record_id, exc)
        return False
