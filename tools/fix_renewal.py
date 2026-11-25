"""修复现存证书：把 renewal 补回 1。

针对已经签出来但 renewal=0 的证书（被 add备注 bug 抹掉的）。
"""

import sys
import base64
import json
import time

sys.path.insert(0, "/vol1/@appcenter/DNS-RP")
from dnrp.certs.ws_client import FnosClient
from dnrp.certs import seed

import os
c = FnosClient(
    host=os.environ.get("DNRP_HOST", "127.0.0.1"),
    port=int(os.environ.get("DNRP_WS_PORT", "16667")),
    username=os.environ.get("DNRP_USER", ""),
    password=os.environ.get("DNRP_PASS", ""),
)
c.connect()

# 1. 找出所有 renewal=0 的 letsencrypt 证书
print("=== 当前证书状态 ===")
rows = c.call("appcgi.netsvr.cert.list", timeout=30)
lst = rows if isinstance(rows, list) else []

need_fix = []
for r in lst:
    dom = r.get("domain", "")
    print(f"  id={r.get('id'):<5} {dom:<26} renewal={r.get('renewal')} "
          f"source={r.get('source')}")
    # 只修用户自己的（source=upload，即种子证书路径签出来的）
    if r.get("source") == "upload" and int(r.get("renewal") or 0) != 1:
        need_fix.append(r)

if not need_fix:
    print("\n  没有需要修复的证书")
    c.close()
    raise SystemExit(0)

# 2. 取一条 DDNS 记录的 id 作为 relatedDDNSId
import subprocess
ddns = c.call("appcgi.netsvr.ddns.record.list", timeout=30)
dl = ddns.get("list") if isinstance(ddns, dict) else ddns

print(f"\n=== 需要修复 {len(need_fix)} 张 ===")

for cert in need_fix:
    cid = cert["id"]
    dom = cert.get("domain", "")
    desc = cert.get("des") or "DNS-RP"

    # 找该证书的签发目录
    d = seed.find_issued_dir(dom, 0)
    if not d:
        print(f"  id={cid} {dom}: 找不到证书目录，跳过")
        continue
    pair = seed.find_cert_in_dir(d)
    if not pair:
        print(f"  id={cid} {dom}: 目录里没有证书文件，跳过")
        continue

    cert_pem, key_pem = pair
    if not key_pem:
        print(f"  id={cid} {dom}: 读不到私钥，跳过")
        continue

    # 找一个匹配的 DDNS 记录（域名相同优先）
    did = None
    for r in dl:
        if r.get("domain") == dom:
            did = r["id"]
            break
    if did is None:
        # 退到任意一条
        did = dl[0]["id"] if dl else None

    print(f"  id={cid} {dom}  desc={desc!r}  ddns_id={did}")

    try:
        r = c.call("appcgi.netsvr.cert.replace", {
            "privateKeyBase64": base64.b64encode(key_pem.encode()).decode(),
            "certificateBase64": base64.b64encode(cert_pem.encode()).decode(),
            "issuerCertificateBase64": "",
            "desc": desc,
            "id": cid,
            "isDefault": 0,
            "privateKeyPath": "", "certificatePath": "",
            "issuerCertificatePath": "",
            "renewal": 1,
            "relatedDDNSId": did,
        }, timeout=60)
        print(f"    replace -> {r}")
    except Exception as e:
        print(f"    失败: {str(e)[:150]}")

time.sleep(2)

print("\n=== 修复后 ===")
rows = c.call("appcgi.netsvr.cert.list", timeout=30)
for r in (rows if isinstance(rows, list) else []):
    print(f"  id={r.get('id'):<5} {r.get('domain',''):<26} "
          f"renewal={r.get('renewal')}")

c.close()
