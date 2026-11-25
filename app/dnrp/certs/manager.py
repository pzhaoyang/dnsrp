"""证书签发的编排层。

把「生成种子证书 → upload → replace → renew」这一套流程封装成一次调用，
并处理单域名走 cert.apply 的捷径。

★ 两条签发路径（实测总结）：

  路径 A（单域名，有邮箱）：
      cert.apply(domain, renewEmail, relatedDDNSId)
      → 一步到位，备注保留

  路径 B（多域名/通配符/无邮箱）：
      1. gen_seed_cert(domains, ecc)   自签多 SAN 种子（CA:FALSE）
      2. cert.upload(cert, key)        SAN 入库
      3. cert.replace(id, renewal=1, relatedDDNSId=...)
      4. cert.renew(id)                fnOS ACME 按 SAN 走 DNS-01
      → 备注可能被清空，需要从磁盘读真证书再 replace 一次补回

★ 约束：
  * cert.apply 的 domain 必须 == 所选 DDNS 记录的 domain（否则 3000033）
  * 通配符 *.x 是**独立**的 DDNS 记录
  * relatedDDNSId 决定用哪个 DNS 商凭据做 DNS-01 验证
"""

from __future__ import annotations

import logging
import time
from typing import Any

from . import seed
from .ws_client import FnosClient, FnosWsError, TwofaRequired

log = logging.getLogger("dnrp.certs.manager")


class CertError(RuntimeError):
    pass


def _find_ddns_for(api: FnosClient, domains: list[str]) -> int | None:
    """挑一个能用于 DNS-01 的 DDNS 记录 id。

    ★★ 关键约束（2026-11-24 实测踩坑）：
       fnOS 的 cert.renew 会校验
           「证书 CN 域名」== 「cert_renew.ddns_related_id 那条记录的 domain」
       不一致就报 **Cert Apply Domain Not Match**，证书停在自签状态。

       所以**必须精确匹配**，不能用同根域的其它记录顶替！

       踩过的坑：签 mytest.example.com 时，表里没有 mytest 的记录，
       旧逻辑退到「同根域任意一条」（选到了 nas.example.com），
       结果 fnOS 侧直接拒绝，证书签出来 issued_by 还是自签域名。

    匹配顺序（只有这几个，找不到就是 None）：
      1. 与 CN 域名完全相同
      2. 与待签域名列表中任意一个完全相同
      3. 通配符场景：`*.example.com` 处理为 `example.com` 再比一次

    ★ 返回 None 时调用方必须**明确报错**并指引用户先去建 DDNS 记录，
      绝不能拿别的记录凑数。
    """
    from ..ddns import api_client

    rows = api_client.list_records(api)
    if not rows:
        return None

    by_domain: dict[str, int] = {}
    for r in rows:
        d = str(r.get("domain") or "").strip()
        rid = r.get("id")
        if d and rid is not None:
            by_domain[d] = int(rid)

    def _norm(d: str) -> str:
        """把 *.x 规范成 x，便于比对。"""
        d = d.strip().lower()
        return d[2:] if d.startswith("*.") else d

    cn = seed.pick_cn(domains)

    # 1) CN 精确匹配（含通配符归一化）
    if cn in by_domain:
        return by_domain[cn]
    cn_norm = _norm(cn)
    for d, rid in by_domain.items():
        if _norm(d) == cn_norm:
            return rid

    # 2) 域名列表里任意一个精确匹配
    for want in domains:
        want = want.strip()
        if want in by_domain:
            return by_domain[want]
        w_norm = _norm(want)
        for d, rid in by_domain.items():
            if _norm(d) == w_norm:
                return rid

    # 3) 找不到就返回 None —— 由调用方报错，绝不凑数
    log.warning(
        "没有与本证书域名精确匹配的 DDNS 记录（CN=%s，域名=%s）；"
        "fnOS 要求 cert_renew 的 ddns_related_id 指向同名记录",
        cn, ",".join(domains),
    )
    return None


def issue_cert(
    api: FnosClient,
    domains: list[str],
    *,
    email: str = "",
    ecc: bool = False,
    desc: str = "",
    ddns_id: int | None = None,
) -> dict[str, Any]:
    """签发一张证书。

    返回 {id, domains, method, note}。
    """
    domains = [d.strip() for d in domains if d.strip()]
    err = seed.validate_domains(domains)
    if err:
        raise CertError(err)

    # 选定 DDNS 记录（DNS-01 凭据来源）
    if ddns_id is None:
        ddns_id = _find_ddns_for(api, domains)
    if not ddns_id:
        cn = seed.pick_cn(domains)
        raise CertError(
            f"没有找到与证书域名精确匹配的 DDNS 记录。\n\n"
            f"飞牛 OS 要求「证书主域名」和「DDNS 记录的域名」完全一致，"
            f"否则签发会失败（报 Cert Apply Domain Not Match）。\n\n"
            f"本证书的主域名是：{cn}\n\n"
            f"解决方式：先在「DDNS」页添加一条域名为 {cn} 的记录，"
            f"然后再回来申请证书。"
        )

    single = len(domains) == 1
    is_wildcard = any(d.startswith("*.") for d in domains)

    # ---------- 路径 A：单域名 + 有邮箱 + 非通配符 + **未要求 ECC** ----------
    #
    # ★ 重要：cert.apply 不支持指定密钥类型，它只会签 RSA（YR1 链）。
    #   早期实现里 ecc 参数被忽略了 —— 用户在界面上选了 ECC，
    #   只要填了邮箱就会走这条路，结果拿到 RSA 证书。
    #   所以这里必须把 ecc 纳入判断：要求 ECC 时不走 apply。
    #
    #   通配符也不走 apply（cert.apply 的 domain 必须是 *.x 形式的
    #   DDNS 记录，稳妥起见一律走种子路径）。
    if single and email and not is_wildcard and not ecc:
        log.info("走 cert.apply 路径（单域名 + 邮箱 + RSA）")
        try:
            data = api.call("appcgi.netsvr.cert.apply", {
                "domain": domains[0],
                "renewEmail": email,
                "relatedDDNSId": ddns_id,
                "des": desc or "dnsrp",
            })
            cid = (data or {}).get("id") if isinstance(data, dict) else None
            return {
                "id": cid,
                "domains": domains,
                "method": "apply",
                "note": "已通过 fnOS 原生申请流程签发（RSA）",
            }
        except FnosWsError as exc:
            log.warning("cert.apply 失败，回退到种子路径: %s", exc)

    if ecc and single and email and not is_wildcard:
        log.info("要求 ECC，跳过 cert.apply（该接口只支持 RSA），走种子路径")

    # ---------- 路径 B：种子证书路径 ----------
    log.info("走种子证书路径（多域名/通配符/无邮箱）")
    cert_pem, key_pem = seed.gen_seed_cert(domains, ecc=ecc)

    # fnOS 的 upload/replace 要求 base64 编码的 PEM，不是原始 PEM
    import base64 as _b64

    cert_b64 = _b64.b64encode(cert_pem.encode()).decode()
    key_b64 = _b64.b64encode(key_pem.encode()).decode()

    started = time.time()
    desc_final = desc or "dnsrp"

    # 1) 上传种子证书
    # ★ 参数名必须精确：privateKeyBase64 / certificateBase64 /
    #   issuerCertificateBase64 / desc / isDefault /
    #   privateKeyPath / certificatePath / issuerCertificatePath
    #   少一个或名字不对就报 errno=3000001 Invalid Params
    try:
        api.call("appcgi.netsvr.cert.upload", {
            "privateKeyBase64": key_b64,
            "certificateBase64": cert_b64,
            "issuerCertificateBase64": "",
            "desc": desc_final,
            "isDefault": 0,
            "privateKeyPath": "",
            "certificatePath": "",
            "issuerCertificatePath": "",
        })
    except FnosWsError as exc:
        raise CertError(f"导入种子证书失败: {exc}") from exc

    # 2) 从列表里找刚导入的条目（upload 不返回 id）
    rows = list_certs(api)
    same = [e for e in rows if str(e.get("desc") or "") == desc_final]
    if not same:
        raise CertError(f"导入后在证书列表里找不到 desc={desc_final} 的条目")
    cid = max(same, key=lambda e: e.get("id") or 0).get("id")
    if cid is None:
        raise CertError("无法确定证书 id")

    # 3) 补续签资格（renewal=1 + relatedDDNSId）
    try:
        api.call("appcgi.netsvr.cert.replace", {
            "privateKeyBase64": key_b64,
            "certificateBase64": cert_b64,
            "issuerCertificateBase64": "",
            "desc": desc_final,
            "id": cid,
            "isDefault": 0,
            "privateKeyPath": "",
            "certificatePath": "",
            "issuerCertificatePath": "",
            "renewal": 1,
            "relatedDDNSId": ddns_id,
        })
    except FnosWsError as exc:
        raise CertError(
            f"赋予续签资格失败: {exc}\n"
            "常见原因：所选 DDNS 记录与该域名不匹配"
        ) from exc

    # 4) 触发 ACME 签发
    try:
        proc_id = api.call("appcgi.netsvr.cert.renew", {"id": cid}, timeout=60)
    except FnosWsError as exc:
        msg = str(exc)
        if "3000033" in msg:
            raise CertError(
                f"{exc}\n"
                "提示：证书域名与所选 DDNS 记录的 domain 不匹配。"
                "请在 DDNS 页添加一条与证书域名同名的记录。"
            ) from exc
        raise CertError(f"触发签发失败: {exc}") from exc

    # 5) 轮询签发结果（DNS-01，通常 20~120 秒）
    status = _poll_issue(api, proc_id)

    note = "已通过种子证书路径签发" + (f"（{status}）" if status else "")

    # 6) 补备注（renew 会覆盖整条记录）
    if desc_final:
        try:
            if _restore_desc(api, cid, seed.pick_cn(domains), started,
                             desc_final, ddns_id):
                note += "，备注已补回"
        except FnosWsError as exc:
            log.warning("补备注失败: %s", exc)

    return {"id": cid, "domains": domains, "method": "seed", "note": note}


def _poll_issue(api: FnosClient, proc_id: Any, timeout: float = 180) -> str:
    """轮询签发状态，返回最终状态字符串。"""
    import time as _t

    if proc_id is None:
        return ""

    deadline = _t.time() + timeout
    last = ""
    while _t.time() < deadline:
        _t.sleep(5)
        try:
            st = api.call("appcgi.netsvr.cert.applystatus",
                          {"processId": proc_id}, timeout=30)
        except FnosWsError as exc:
            log.warning("查询签发状态失败: %s", exc)
            return last

        status = str((st or {}).get("status") or "")
        if status:
            last = status
            log.info("签发状态: %s", status)
        if status in ("success", "suc"):
            return status
        if status in ("fail", "failed", "error"):
            msg = (st or {}).get("errmsg") or (st or {}).get("message") or ""
            raise CertError(f"签发失败: {status} {msg}")

    return last or "timeout"


def _restore_desc(
    api: FnosClient, cert_id: Any, primary_domain: str,
    after_ts: float, desc: str,
    ddns_id: Any = None,
) -> bool:
    """renew 之后用磁盘上的真证书再 replace 一次，把备注写回。

    ★★★ 必须带上 renewal=1 和 relatedDDNSId！（2026-11-25 踩坑）

      `cert.replace` 是**全量覆盖**接口：不传 renewal 就等于把它写成 0。

      原来的实现只传了证书内容和 desc，结果每次签发完补备注时，
      都会把 renew 之前设好的 `renewal=1` 抹掉 ——
      证书签出来了，但没有续签资格，**到期就会静默失效**。

      实测对比：
        replace(..., renewal=1, relatedDDNSId=N)  -> renewal 保持 1
        replace(..., 不传 renewal)                -> renewal 变成 0

      所以这里必须把续签参数原样带上。

    ⚠️ 必须用真证书内容。用自签内容 replace 会把 Let's Encrypt 证书毁掉。
    """
    d = seed.find_issued_dir(primary_domain, after_ts - 5)
    if not d:
        log.info("未找到签发目录，跳过补备注")
        return False

    pair = seed.find_cert_in_dir(d)
    if not pair:
        log.info("签发目录里没有可读证书，跳过补备注")
        return False

    cert_pem, key_pem = pair
    if "BEGIN CERTIFICATE" not in cert_pem:
        return False
    if not key_pem:
        log.info("读不到私钥，跳过补备注")
        return False

    import base64 as _b64

    payload: dict[str, Any] = {
        "privateKeyBase64": _b64.b64encode(key_pem.encode()).decode(),
        "certificateBase64": _b64.b64encode(cert_pem.encode()).decode(),
        "issuerCertificateBase64": "",
        "desc": desc,
        "id": cert_id,
        "isDefault": 0,
        "privateKeyPath": "",
        "certificatePath": "",
        "issuerCertificatePath": "",
        # ★ 这两项绝不能省，否则 renewal 被清成 0
        "renewal": 1,
    }
    if ddns_id is not None:
        payload["relatedDDNSId"] = int(ddns_id)

    api.call("appcgi.netsvr.cert.replace", payload, timeout=60)

    # ★ 回读确认 renewal 真的是 1，否则续签会静默失效
    try:
        rows = api.call("appcgi.netsvr.cert.list", timeout=30)
        for r in (rows if isinstance(rows, list) else []):
            if r.get("id") == cert_id:
                if int(r.get("renewal") or 0) != 1:
                    log.error("补备注后 renewal=%s（应为 1），尝试修正",
                              r.get("renewal"))
                    fix = dict(payload)
                    fix["renewal"] = 1
                    api.call("appcgi.netsvr.cert.replace", fix, timeout=60)
                break
    except FnosWsError as exc:
        log.warning("回读 renewal 失败: %s", exc)

    log.info("备注已补回: %s（renewal 保持 1）", desc)
    return True


def renew_cert(api: FnosClient, cert_id: Any,
               wait: bool = True, timeout: float = 180) -> dict[str, Any]:
    """手动触发一张证书的续期。

    ★ 续期方式按证书类型不同（2026-11-25 实测）：

      * 用户申请的多域名证书（source=upload, renewal=1）：
          走 cert.renew(id)，重新走一次 ACME DNS-01。
      * fnOS 自签兜底证书（source=system，如 id=1 fnOS）：
          cert.renew 报 errno=3000035 Cert Not Renewable。
          要改用 **cert.sysreset**（无参数）—— 这正是 fnOS 设置页
          「更新系统证书」用的接口，会重新生成自签证书。
          实测：调用后 valid_from / last_renew_time 都更新了。
      * FN Connect 专属证书（source=trim）：
          两种接口都不行，由 FN Connect 服务自动管理，无法手动续。
          前端不应给它续期按钮。

      ⚠️ 对 ACME 证书：续期需要对应 DDNS 记录的凭据有效，
         且证书主域名必须与 cert_renew.ddns_related_id 指向的记录一致，
         否则报 Cert Apply Domain Not Match。

    返回 {id, domain, status, note}。
    """
    if cert_id is None:
        raise ValueError("续期需要证书 id")

    # 1. 前置检查：证书存在
    rows = list_certs(api)
    target = None
    for r in rows:
        if r.get("id") == cert_id:
            target = r
            break

    if target is None:
        raise CertError(f"证书不存在: id={cert_id}")

    source = str(target.get("source") or "")
    is_system = source == "system"

    # FN Connect 证书无法手动续期
    if source == "trim":
        raise CertError(
            f"「{target.get('domain')}」是 FN Connect 专属证书，"
            f"由 FN Connect 服务自动管理，无法在本应用手动续期。\n\n"
            f"如需更新，请在飞牛 OS「远程访问 / FN Connect」中操作。"
        )

    # 非系统证书必须有 renewal=1
    if not is_system and int(target.get("renewal") or 0) != 1:
        raise CertError(
            f"「{target.get('domain')}」这张证书没有续签资格（renewal=0）。\n\n"
            f"解决方式：用「申请证书」重新签一张，或到飞牛 OS 证书管理里操作。"
        )

    # 2. 触发续期
    if is_system:
        # ★ 系统自签证书用 sysreset（无参数），不是 cert.renew
        proc_id = None
        try:
            api.call("appcgi.netsvr.cert.sysreset", {}, timeout=60)
        except FnosWsError as exc:
            raise CertError(f"更新系统证书失败: {exc}") from exc
    else:
        try:
            proc_id = api.call("appcgi.netsvr.cert.renew",
                               {"id": int(cert_id)}, timeout=60)
        except FnosWsError as exc:
            msg = str(exc)
            if "3000033" in msg:
                raise CertError(
                    f"{exc}\n\n"
                    f"提示：这是「证书域名与 DDNS 记录不匹配」导致的。\n"
                    f"fnOS 要求证书主域名与 cert_renew 绑定的 DDNS 记录域名完全一致。\n"
                    f"请确认 {target.get('domain')} 在 DDNS 列表里有同名记录。"
                ) from exc
            if "3000025" in msg:
                raise CertError(
                    f"{exc}\n\n提示：该证书正在被使用中，暂时不能续期。"
                ) from exc
            raise CertError(f"触发续期失败: {exc}") from exc


    # 3. 轮询结果
    status = ""
    if wait and proc_id is not None:
        status = _poll_issue(api, proc_id, timeout=timeout)

    ok = status in ("success", "suc") if status else True
    note = ("续期成功" if ok else f"已提交续期请求（状态 {status or '处理中'}）")

    # 4. 续期后回读确认 renewed 状态与 renewal 标志
    try:
        after = None
        for r in list_certs(api):
            if r.get("id") == cert_id:
                after = r
                break
        if after:
            # ★ 系统自签证书 renewal 本来就是 0（不写 cert_renew 表），
            #   不要去「修正」它，否则会画蛇添足。
            if not is_system and int(after.get("renewal") or 0) != 1:
                log.warning("续期后 %s 的 renewal 变成 0，尝试修正",
                            target.get("domain"))
                _fix_renewal_flag(api, cert_id, after, timeout)
            note += f"（当前状态 {after.get('status')}，renewal={after.get('renewal')}）"
    except FnosWsError as exc:
        log.warning("续期后回读失败: %s", exc)

    return {
        "id": cert_id,
        "domain": target.get("domain", ""),
        "status": status or "submitted",
        "ok": ok,
        "note": note,
    }


def _fix_renewal_flag(api: FnosClient, cert_id: Any, cert: dict[str, Any],
                      timeout: float = 60) -> None:
    """把被意外清掉的 renewal 补回 1。

    续期和补备注都会走 cert.replace；任何一次忘了带 renewal 就会清成 0。
    这里从磁盘读真证书重新 replace 一次，带上 renewal=1。
    """
    dom = cert.get("domain", "")
    d = seed.find_issued_dir(dom, 0)
    if not d:
        return
    pair = seed.find_cert_in_dir(d)
    if not pair:
        return
    cert_pem, key_pem = pair
    if not key_pem:
        return

    import base64 as _b64

    # 找一条匹配的 DDNS 记录
    ddns_id = None
    try:
        from ..ddns import api_client
        for r in api_client.list_records(api):
            if r.get("domain") == dom:
                ddns_id = r.get("id")
                break
    except FnosWsError:
        pass

    payload = {
        "privateKeyBase64": _b64.b64encode(key_pem.encode()).decode(),
        "certificateBase64": _b64.b64encode(cert_pem.encode()).decode(),
        "issuerCertificateBase64": "",
        "desc": cert.get("des") or "dnsrp",
        "id": int(cert_id),
        "isDefault": int(cert.get("isDefault") or 0),
        "privateKeyPath": "",
        "certificatePath": "",
        "issuerCertificatePath": "",
        "renewal": 1,
    }
    if ddns_id is not None:
        payload["relatedDDNSId"] = int(ddns_id)

    api.call("appcgi.netsvr.cert.replace", payload, timeout=timeout)
    log.info("已补回 %s 的 renewal=1", dom)


def list_certs(api: FnosClient) -> list[dict[str, Any]]:
    """列出 fnOS 证书库。"""
    rows = api.call("appcgi.netsvr.cert.list") or []
    return rows if isinstance(rows, list) else []


def delete_cert(api: FnosClient, cert_id: Any) -> bool:
    """删除一张证书。

    ★ 实测结论（2026-11-24，fnOS 1.2.1011）：
      接口 `appcgi.netsvr.cert.remove` 的参数是 **id**（整数）。

      参数格式辨识依据（用不存在的 999999 试探，看错误码区分）：
        {"id": 999999}      -> errno=3000006 Not Found       ← 字段对，对象不存在
        {"certId": 999999}  -> errno=3000001 Invalid Params  ← 字段名错
        {"domain": "x"}     -> errno=3000001 Invalid Params  ← 字段名错

      关键技巧：**"Not Found" 而非 "Invalid Params" 说明字段名是对的**。

    ⚠️ fnOS 不允许删除正在使用的证书 —— 被某个域名引用或 isDefault=1 的
       会返回错误。需要先在「系统设置 → 证书管理」把域名的证书切走再删。

    ★ 只删证书库里的记录，不动磁盘上的历史目录
      （/usr/trim/var/trim_connect/ssls/ 由 fnOS 自己管理）。
    """
    if cert_id is None:
        raise ValueError("删除证书需要 id")

    return bool(api.call("appcgi.netsvr.cert.remove",
                         {"id": int(cert_id)}, timeout=60))


def list_ddns(api: FnosClient) -> list[dict[str, Any]]:
    """列出 fnOS DDNS 记录（签发时选凭据用）。"""
    from ..ddns import api_client

    return api_client.list_records(api)
