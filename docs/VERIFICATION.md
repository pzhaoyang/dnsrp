# dnsrp 验证记录

> 全部结果来自 **真机实测**
> fnOS 1.2.1011 / kernel 6.18.18.c1191-trim / aarch64 / Python 3.11.2
> 测试时间：2026-11-19 ~ 2026-11-20
> 测试后已完整清理，未对 fnOS 产生持久影响。

---

## 一、核心结论（先看这个）

**三个功能全部端到端跑通：**

| 功能 | 状态 | 验证方式 |
|---|---|---|
| **反向代理** | ✅ | 真实代理到 fnOS 后端，返回 302；未知域名 404 |
| **SNI 多证书** | ✅ | 4 个域名各自返回正确的 fnOS 证书 |
| **证书签发** | ✅ | 真的签出 Let's Encrypt ECC 证书（YE2 链） |
| **DDNS 管理** | ✅ | 通过 dnsrp 添加记录，凭据自动复制 |

**证书签发的完整链路（fnOS 日志实录）：**

```
acme: Cleaning DNS-01 challenge
acme: Validations succeeded; requesting certificates
Server responded with a certificate.
renew cert test.example.com success
```

证书表结果：`id=97 | test.example.com | YE2 | suc | DNSRP-FINAL`
（YE2 = Let's Encrypt ECDSA 链，真证书）

---

## 二、环境基线

```
fnOS:      1.2.1011
kernel:    6.18.18.c1191-trim
Python:    3.11.2
OpenSSL:   3.0.18

端口基线：
  :80/:443        fnOS trim_nginx
  :16666/:16667   fnOS WebUI（HTTP/HTTPS）+ WebSocket
  :5432           PostgreSQL

初始资产：
  证书目录 12 个
  DDNS 记录 8 条（全部 cloudflare）
  证书表 3 条
```

---

## 三、证书读取模块

### 3.1 登记表解析

```
条目数: 9
  [OK] list.example.com     -> nas.example.com/1793609016/fullchain.crt
  [OK] nas.fnos.net          -> nas.fnos.net/1793255954/fullchain.crt
  [OK] nas.example.com     -> 同上（多 SAN 共用）
  [OK] imp/imusic/iroute/iseeding/app.example.com -> 同上
  [OK] fallback                 -> fnOS/1764407855/fnOS.crt
```

**结论**：7 个域名共用一张多 SAN 证书，fallback 排最后，解析正确。

### 3.2 匹配优先级

```
app.example.com       匹配=2  选中=app.example.com
nas.fnos.net         匹配=2  选中=nas.fnos.net
unknown.example.com     匹配=1  选中=fallback
```

### 3.3 证书解析

| host | subject | issuer | 类型 | SAN |
|---|---|---|---|---|
| nas.example.com | CN=nas.example.com | YE2 | **ECC** | 7 |
| nas.fnos.net | CN=nas.fnos.net | YR1 | **RSA** | 2 |
| fallback | CN=fnOS | 自签 | ECC | 1 |

### 3.4 权限（关键）

```
证书文件: -rw-rw---- root:www-data 660

your-user 身份:   Permission denied
www-data 组身份:  ✓ 可读
root 身份:        ✓ 全部可读
```

**结论**：加入 `www-data` 组即可，无需 root。

---

## 四、反向代理引擎

### 4.1 SNI 多证书（修复了一个真实 bug）

**修复前**（错误：直接改 `sslobj.context`）：

```
app.example.com        subject=CN = fnOS              ← 拿到 fallback
nas.example.com     subject=CN = nas.example.com
nas.fnos.net          subject=CN = nas.example.com  ← 串号
```

**修复后**（每连接独立 SSLContext）：

```
app.example.com        CN=nas.example.com  YE2  SAN=7  ✓
nas.example.com     CN=nas.example.com  YE2  SAN=7  ✓
nas.fnos.net          CN=nas.fnos.net       YR1  SAN=2  ✓
unknown.example.com      CN=fnOS (fallback)       自签        ✓
```

**根因**：Python 的 `SSLObject.context` 是只读属性，直接
`load_cert_chain()` 改的是**共享上下文**，连续连接会互相污染。
正确做法是给每个连接赋一个新的 `SSLContext`。

### 4.2 HTTP / HTTPS 转发

```
:18080  Host=app.example.com  ->  302   （fnOS 后端）
:18080  Host=nope.local         ->  404   （路由拒绝）
:18443  SNI=app.example.com   ->  302   证书正确
:18443  SNI=nas.fnos.net     ->  404   无规则，但证书正确切换
```

### 4.3 端口保护

```
POST listen_port=80
-> {"ok":false,"error":"端口 80 属于系统保留端口（80/443/5666/5667/16666/16667
                        及 <1024），请使用 8080 或更高位端口"}
```

---

## 五、DDNS 模块

### 5.1 发现官方 API（比直接写库更安全）

从 fnOS 前端 JS 里找到完整接口：

```
appcgi.netsvr.ddns.record.list      -> {"list":[...], "total":N}
appcgi.netsvr.ddns.record.create
appcgi.netsvr.ddns.record.update
appcgi.netsvr.ddns.record.remove
appcgi.netsvr.ddns.record.refresh
appcgi.netsvr.ddns.record.test
appcgi.netsvr.ddns.provider.list    -> 12 个服务商
```

**这推翻了原方案**（直接写 PostgreSQL 表），改用官方 API 更安全。

### 5.2 ★ 关键发现：API 的 create 不复制凭据

```
用 API 建记录后：
  test.example.com  key_len=0   sec_len=64    ← 空凭据
对比已有记录：
  nas.example.com    key_len=9   sec_len=128   ← 正常

后果（fnOS 日志）：
  cloudflare: invalid credentials:
  authEmail, authKey or authToken must be set
```

**结论**：`ddns.record.create` 只建壳不带凭据，证书签发做 DNS-01 时会失败。

**解法**：必须复制同根域已有记录的 `access_key` / `access_secret` **密文**。
已实测（2026-11-19）：复制密文完全可用（解密后是同一个 Token），
fnOS 定时任务 80 秒内把 status 变成 suc。

### 5.3 凭据复用实测

```
复制同根域凭据 -> 新记录
[20s]  init
[40s]  init
[60s]  init
[80s]  suc     ← fnOS 自动完成上报
```

---

## 六、证书签发（核心功能）

### 6.1 完整流程

```
1. 生成自签多 SAN 种子证书（CA:FALSE）
       ↓ cert.upload（base64 编码的 PEM）
2. SAN 从 X.509 解析入库
       ↓ cert.replace（renewal=1 + relatedDDNSId）
3. 赋予续签资格
       ↓ cert.renew
4. fnOS 的 lego 走 DNS-01 验证
       ↓
5. 签发成功（YE2 = ECC / YR1 = RSA）
       ↓ 读磁盘真证书再 replace
6. 备注补回
```

### 6.2 cert.upload 参数（踩坑）

必须是 **base64 编码**，且参数名不能错：

```python
{
  "privateKeyBase64": b64(key_pem),
  "certificateBase64": b64(cert_pem),
  "issuerCertificateBase64": "",
  "desc": "备注",
  "isDefault": 0,
  "privateKeyPath": "",
  "certificatePath": "",
  "issuerCertificatePath": "",
}
```

少一个字段或名字不对 → `errno=3000001 Invalid Params`

### 6.3 种子证书必须 CA:FALSE（踩坑）

```
openssl req -x509 默认生成 CA:TRUE
  -> cert.renew 报 "Certificate bundle starts with a CA certificate"

必须显式写 basicConstraints = critical,CA:FALSE
```

实测验证：生成后额外用 `openssl x509 -text` 检查，确认无 `CA:TRUE`。

### 6.4 CN 必须非通配符（踩坑）

fnOS 把 CN 当证书主域名，续签时用它跟 DDNS 记录的 domain 比对。
CN 写成 `*.x` 会报 `3000033 Cert Apply Domain Not Match`。

解法：`pick_cn()` 优先选非通配符域名；全通配符时去掉 `*.`。

### 6.5 域名格式校验

测试结果：

```
['example.com']                    -> 通过
['example.com','*.example.com']    -> 通过
['a.com','b.net']                  -> 跨根域无法合成一张证书
['bad_domain']                     -> 域名格式不合法
['*.*.example.com']                -> 域名格式不合法
[]                                 -> 至少填写一个域名
```

### 6.6 最终成功验证

**请求：**
```json
POST /api/certs/issue
{"domains":["test.example.com"],"desc":"DNSRP-FINAL","ecc":true}
```

**响应：**
```json
{"ok":true,"data":{"id":97,"domains":["test.example.com"],
                   "method":"seed",
                   "note":"已通过种子证书路径签发（success），备注已补回"}}
```

**fnOS 证书表：**
```
97 | test.example.com | YE2 | suc | DNSRP-FINAL
```

**fnOS 日志：**
```
acme: Cleaning DNS-01 challenge
acme: Validations succeeded; requesting certificates
Server responded with a certificate.
renew cert test.example.com success
```

✅ **真 Let's Encrypt ECC 证书签发成功**

---

## 七、API 与 CGI

### 7.1 全部接口实测

```
GET  /api/health              {"version":"0.1.0","proxy":[]}
GET  /api/overview            {"proxyRules":0,"ddnsRecords":0,"fnosCerts":9}
GET  /api/settings/fnos       {"configured":true,"user":"your-user"}
POST /api/settings/fnos/test  {"ok":true,"uid":1000,"admin":true}   ← 真登录成功
GET  /api/ports/reserved      {"reserved":[80,443,5432,...],"defaultPort":8080}
GET  /api/certs               [9 条证书详情]
GET  /api/certs/matched       {"picked":"app.example.com","readable":true}
POST /api/certs/issue         {"id":97,"method":"seed"}
GET  /api/ddns/fnos           [8 条 DDNS]
GET  /api/ddns/zones          [{"zone":"example.com",...}]
POST /api/ddns                [{"domain":"...","ok":true}]
```

### 7.2 CGI 端到端

```
静态页:   Content-Type: text/html  27900 字节  ✓
/api/health:  {"ok": true, "data": {...}}  ✓
/api/certs:   Content-Length: 5018  ✓
/api/ddns/fnos: 2639 字节  ✓
```

**CGI → unix socket → API → fnOS 全链路打通。**

### 7.3 WebSocket 登录

```
用户: your-user
端口: 16667
结果: ✓ 登录成功  uid=1000  admin=True
      secret 长度 16
```

---

## 八、安装流程验证

```
======== install_init ========
Python 3.11 (/usr/bin/python3)
用户 your-user 已在组 www-data
fnOS DDNS 表可访问（8 条记录）

======== install_callback ========
SQLite 已初始化
应用用户: your-user
用户 your-user 已在组 www-data
证书可读性: 6/6
证书全部可读，HTTPS 反代可用
fnOS DDNS 表可访问（8 条记录）
默认配置已创建
```

**结论**：fnOS 生命周期脚本全部正常工作。

---

## 九、修复的 Bug 清单

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 1 | SNI 证书串号 | `sslobj.context` 是共享的 | 每连接新建 SSLContext |
| 2 | 建规则 500 | `data.get()` 返回 None 违反 NOT NULL | store 层逐字段兜底 |
| 3 | `daysLeft` 恒为 0 | openssl 日期双空格 | 归一化空白 |
| 4 | `keyType` 为空 | `__dict__.update` 覆盖 dataclass | 显式赋值 |
| 5 | `ddns.list` 报 no register handler | 接口名错 | 改为 `ddns.record.list` |
| 6 | `ddns.record.list` 解析失败 | 返回 `{list,total}` 不是数组 | 兼容两种结构 |
| 7 | `cert.upload` 报 3000001 | 参数名错 + 未 base64 | 用 `*Base64` 系列字段 |
| 8 | 新 DDNS 记录凭据为空 | API create 不复制凭据 | 改为复制同根域密文 |
| 9 | `find_template` 恒返回 None | `len(f) < 10` 但只 select 9 列 | 改为 `< 9` |
| 10 | 种子证书 renew 失败 | 默认 CA:TRUE | 显式 CA:FALSE |

---

## 十、清理确认

测试后 nas 状态：

```
dnsrp 进程:  已停止
测试端口:     18080/18443 已释放

证书表:       3 条（与测试前一致）
  id=1   fnOS
  id=34  nas.fnos.net
  id=93  nas.example.com
DDNS 记录:    8 条（与测试前一致）
证书目录:     12 个（与测试前一致）
测试证书文件: 已删除
```

**fnOS 资产完全恢复原状。**

---

## 十一、已知限制

| 项 | 说明 |
|---|---|
| 2FA | 验证码 30 秒过期，需在 UI 现输；无法无人值守 |
| 跨根域 | 一张证书不能覆盖不同根域，已在校验层拒绝 |
| DDNS 凭据 | 新根域必须先在 fnOS 原生界面加一条作为模板 |
| HTTP/2 | 反代只支持 HTTP/1.1 |
| 续签 | 交给 fnOS（renewal=1），dnsrp 不做定时任务 |

---

*对应代码版本：dnsrp v0.1.0*
