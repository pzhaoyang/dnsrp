# dnsrp 设计文档（v0.1 草案）

> 项目名：**dnsrp**（DNS · Reverse Proxy）
> 目标平台：fnOS（飞牛 OS）
> 设计日期：2026-11-19
> 测试设备：nas（fnOS 1.2.1011 / kernel 6.18.18.c1191-trim / aarch64）

---

## 一、项目定位

把三件原本割裂的事合成**一个应用**，全部复用 fnOS 自有能力：

| 能力 | 复用的 fnOS 资源 | 不再自己造轮子 |
|---|---|---|
| 反向代理 | fnOS 证书系统（`network_gateway_cert.conf`） | 不用自己管证书文件 |
| 证书申请 | fnOS ACME 引擎（Let's Encrypt + DNS-01） | 不用自己实现 ACME 客户端 |
| DDNS | fnOS `trim_connect` 的 DDNS 定时任务 | 不用自己写 IP 检测/上报 |

**核心思路：dnsrp 只做「编排层」，所有脏活交给 fnOS。**

一句话概括三者关系：

```
DDNS 保证域名解析到本机
        ↓
证书申请（走 DNS-01）依赖 DDNS 凭据
        ↓
反代（HTTPS）依赖证书
        ↓
反过来，反代/证书/A记录 都需要在同一套域名清单里维护
```

**所以这三者天然是「域名」这一个实体的三个面，应该放进同一个应用统一管理。**

---

## 二、需求分解

### 2.1 需求原文

> 1. 实现反代功能，这就是最基本的，基于当前这个 app 做
> 2. 实现证书申请和管理功能共同控制 fnOS 的证书系统，也就是 fnos-multidomain-cert 融合进去
> 3. 再添加上 DDNS 的功能 fnos-ddns
>
> 共同特点：基本上利用 fnOS 系统的资源
> 1. 反代就是使用 fnOS 自己的证书系统
> 2. 证书管理就是能自己申请多域名证书、单域名证书到 fnOS 系统
> 3. 就是自己添加的 DDNS 能在 fnOS 系统中管理，而不是独立的

### 2.2 需求转译

| # | 需求 | 技术含义 | 落地方式 |
|---|---|---|---|
| R1 | 反代 | 监听端口、按域名路由、TLS 用 fnOS 证书 | 自建 Go/Python 反代进程，证书路径从 `network_gateway_cert.conf` 读 |
| R2 | 证书申请 | 多域名/单域名 → fnOS 证书库（可自动续签） | 调用 fnOS WebSocket API（`cert.upload`/`replace`/`renew`/`apply`） |
| R3 | DDNS | 批量增删改 → fnOS DDNS 列表（由 fnOS 定时上报） | 写 `trim_connect.d_dns_record` 表 + 触发/等待 fnOS 定时任务 |

### 2.3 隐含需求（从三个项目的问题反推）

| 现象 | 本质 | dnsrp 要解决的 |
|---|---|---|
| `fn-reverseproxy` 抢 80、读不到证书 | 不该用系统端口，不该绕过证书系统 | **一律用高位端口，只用 fnOS 证书路径** |
| `certs.map is not a function` | 前端/后端版本错配 | **前后端同包发布，单一数据源** |
| 多域名证书要手跑 Python 脚本 | 没有 GUI | **图形化，一键签发** |
| DDNS 批量添加要手写 SQL | 没有 GUI | **图形化批量管理** |
| 三个工具域名清单各自维护 | 数据分散 | **统一的「域名」主数据模型** |

---

## 三、数据模型设计（核心）

### 3.1 设计原则

**以「域名」为主键，把三件事串起来。**

现有三个工具各自维护域名，容易不一致。dnsrp 引入一张「域名总表」，反代规则/证书/DDNS 都引用它。

### 3.2 主数据：Domain

```
Domain（域名）
├── name            域名，如 app.example.com
├── zone            根域，如 example.com
├── ddns            是否有 DDNS 记录
├── cert_ids[]      覆盖此域名的证书
└── proxy_rules[]   用此域名的反代规则
```

### 3.3 三张功能表（dnsrp 自有，存 SQLite）

**表 1：ddns**（映射到 fnOS 的 `d_dns_record`）

| 字段 | 说明 |
|---|---|
| id | 本地 id |
| domain | 域名（唯一） |
| provider | cloudflare / alidns … |
| fnos_record_id | **对应 fnOS 表里的 id**（关键关联字段） |
| enabled | 是否启用 |
| last_status | 同步 fnOS 的状态（suc/err） |

**设计取舍**：dnsrp **不存凭据**。凭据留在 fnOS 表里，dnsrp 只记录「我用哪条模板记录的凭据」：

```
template_record_id  →  d_dns_record.id（同根域的已有记录）
```

新增记录时复制该模板的 `access_key`/`access_secret`。

**表 2：cert**（映射到 fnOS 的 `cert`）

| 字段 | 说明 |
|---|---|
| id | 本地 id |
| fnos_cert_id | **对应 fnOS cert.id** |
| domains | 逗号分隔（一证多域） |
| key_type | RSA / ECC |
| auto_renew | 是否续签（对应 `cert_renew`） |
| status | 有效 / 即将过期 / 失败 |

**表 3：proxy_rule**（dnsrp 独有）

| 字段 | 说明 |
|---|---|
| id | 本地 id |
| name | 规则名 |
| domains | 匹配的域名（多个） |
| listen_port | 监听端口（**默认 8080，禁止 80/443**） |
| listen_tls | 是否 TLS |
| cert_id | 用哪张证书（可为空=自动按域名匹配） |
| target_scheme/host/port | 后端地址 |
| force_https | 是否 HTTP 跳转（**仅当 listen_port ≠ 80**） |
| enabled | 启用 |

### 3.4 关联关系

```
                    ┌─────────────┐
                    │   Domain    │  （主数据，可以只是逻辑视图）
                    │  itr.x.icu  │
                    └──────┬──────┘
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    ┌────▼────┐      ┌─────▼─────┐     ┌─────▼──────┐
    │  ddns   │      │   cert    │     │ proxy_rule │
    │ 记录    │      │ 证书       │     │ 规则       │
    └────┬────┘      └─────┬─────┘     └─────┬──────┘
         │                 │                 │
         │ 复制凭据         │ DNS-01 需要      │ TLS 需要
         ▼                 ▼                 ▼
   fnOS d_dns_record   fnOS ACME 引擎   fnOS 证书文件
```

**关键约束**：证书签发（DNS-01）依赖 DDNS 里同域的记录提供 DNS 商凭据。
所以**顺序必然是：先 DDNS，再证书，最后反代**。

---

## 四、架构设计

### 4.1 整体分层

```
┌──────────────────────────────────────────────────────────┐
│                    浏览器（fnOS 应用中心内嵌）              │
│  www/index.html  (单页应用，原生 JS，无构建步骤)            │
└───────────────────────┬──────────────────────────────────┘
                        │ /cgi/ThirdParty/dnsrp/index.cgi/api/*
                        ▼
┌──────────────────────────────────────────────────────────┐
│  index.cgi（CGI 网关，bash）                               │
│  - 静态文件服务                                             │
│  - /api/* 转发到 unix socket                                │
└───────────────────────┬──────────────────────────────────┘
                        │ unix socket
                        ▼
┌──────────────────────────────────────────────────────────┐
│  dnrp（主控进程，Python 3）                                 │
│  ┌────────────┬────────────┬────────────┬──────────────┐  │
│  │  API 层     │  反代引擎   │ 证书管理    │  DDNS 管理   │  │
│  │  (HTTP)    │  (asyncio) │  (WS 客户端)│  (psql)     │  │
│  └────────────┴────────────┴────────────┴──────────────┘  │
└──────┬──────────────┬──────────────┬──────────────────────┘
       │              │              │
       ▼              ▼              ▼
   SQLite        监听端口         fnOS 侧
   (自有状态)    (8080+)        ┌──────────────────────┐
                               │ network_gateway_     │
                               │   cert.conf (读)      │
                               │ trim_connect 库      │
                               │   d_dns_record       │
                               │   cert / cert_renew  │
                               │ WebSocket API        │
                               │   cert.upload/replace│
                               │   cert.renew/apply   │
                               └──────────────────────┘
```

### 4.2 为什么用 Python 而不是 Go

| 维度 | Go | Python 3.11 |
|---|---|---|
| 反代性能 | 更好 | 够用（home NAS 场景） |
| fnOS 依赖 | 无 | 系统自带 3.11.2 |
| 复用现有代码 | 需重写 | **直接复用**两个项目 |
| 打包体积 | 二进制 ~10MB | 纯脚本 ~200KB |
| 维护难度 | 需交叉编译 | 改完即生效 |

**决策：Python 3.11 + 标准库**，理由：
1. `fnos-multidomain-cert` 是 Python，直接融合
2. `fnos-ddns` 是 Python，直接融合
3. fnOS 自带 Python 3.11.2，零依赖
4. 反代性能在家庭场景不是瓶颈（并发 < 100）

**唯一例外**：反代数据面如果发现 Python asyncio 性能不足，后续可换成独立的 Go 进程，但对 UI 透明。

### 4.3 反代引擎选型

参考 `ilanyu/ReverseProxy` 的思路（环境变量配置 + 简单路由），但**配置来源改为 fnOS 数据**：

| 方案 | 说明 | 取舍 |
|---|---|---|
| A. 复用现有 `reverseproxy_aarch64` | 直接调用，不改二进制 | ❌ 无法修 `/api/certs`，无法改证书逻辑 |
| B. 自研 Python asyncio 反代 | 完全可控 | ✅ 选中 |
| C. 用 nginx | 性能好但要管配置生成 | 备选（复杂场景） |

**决策：方案 B**，理由：
- 完全可控，能按 fnOS 证书表动态取证书（SNI 路由）
- 不需要额外二进制，减小包体积
- Python `asyncio` + `ssl.SSLContext.set_servername_callback` 支持 SNI 多证书

**技术要点**：
```python
# SNI 动态选证书 —— 注意这个坑
def sni_callback(sslobj, servername, ctx):
    cert_path = resolve(servername)      # 来自 network_gateway_cert.conf
    if cert_path:
        # ✗ 错误：sslobj.context.load_cert_chain(...)
        #   改的是共享上下文，并发连接会串证书（实测踩过）
        # ✓ 正确：给每个连接独立上下文
        new_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        new_ctx.load_cert_chain(cert_path.crt, cert_path.key)
        sslobj.context = new_ctx
```

**实测证据**（nas，详见 [VERIFICATION.md](VERIFICATION.md) §3.1）：
用错方法时，`app.example.com` 拿到的是 `CN=fnOS` 的兜底证书，
而 `nas.fnos.net` 拿到的是上一个请求的证书。改成每连接独立上下文后，
四个 SNI 全部返回正确证书。

### 4.4 证书管理：复用 WebSocket API

直接移植 `03-apply-multidomain-cert.py` 的核心逻辑：

```
单域名：
  cert.apply(domain, renewEmail, relatedDDNSId)
       ↓ 简单，走 fnOS 原生流程

多域名/通配符：
  1. 生成自签多 SAN 种子证书（CA:FALSE！）
  2. cert.upload(cert, key)        → SAN 入库
  3. cert.replace(id, renewal=1, relatedDDNSId=...)
  4. cert.renew(id)                → fnOS ACME 走 DNS-01 签真证书
  5. （可选）读磁盘真证书再 replace 一次，补回备注
```

**关键约束**（来自 NOTES.md 实测）：
- `cert.apply` 只接受**单域名**，且 `domain` 必须 == DDNS 记录 domain（否则 `3000033`）
- 多域名必须走「种子证书」路径
- `relatedDDNSId` 决定用哪个 DNS 商凭据做 DNS-01
- 签名：`base64(HMAC-SHA256(json, secret)) + json`
- 2FA：非交互环境需要 `FNOS_2FA_CODE`，**不适合定时任务**

**设计取舍**：
- **证书过期自动续签交给 fnOS**（`renewal=1`），dnsrp 不做定时续签
- dnsrp 只在「用户主动点签发」时才调 WS API
- 2FA 在 UI 里做一个输入框，用户当场输入

### 4.5 DDNS 管理：写数据库 + 等 fnOS 定时任务

```
用户添加域名
    ↓
dnsrp 校验：同根域是否已有记录（有则取模板凭据）
    ↓
INSERT INTO d_dns_record (...复制模板的 access_key/access_secret...)
    ↓
fnOS 的 gocron 定时任务（按 update_interval，默认 5 分钟）
    ↓
自动检测公网 IP → 调 Cloudflare/AliDNS API 更新
    ↓
dnsrp 轮询 fnOS 表的 status 字段，回显给 UI
```

**已实测验证**（见第六节）：复用同根域凭据可行，1 分钟内生效。

**跨根域限制**（实测自 DDNS 项目 README）：
- 数据库能插入成功
- 但 fnOS 上报会失败（凭据不属于该根域）
- **dnsrp 的 UI 要明确提示**：新根域必须先在 fnOS 原生界面加一条

---

## 五、目录结构设计

```
dnsrp/
├── manifest                    # fnOS 应用清单
├── ICON.PNG / ICON_256.PNG
├── config/
│   ├── privilege               # run-as: package（不抢特权端口）
│   └── resource
├── cmd/                        # fnOS 生命周期脚本
│   ├── common.sh               # 公共库（加组、校验、日志）
│   ├── install_init            # 加 www-data 组（读证书）
│   ├── install_callback        # 初始化 SQLite、自检
│   ├── upgrade_init/callback
│   ├── uninstall_init/callback
│   └── main                    # start|stop|restart|status
├── app/
│   ├── dnrp/                   # ★ 主控程序（Python 包）
│   │   ├── __init__.py
│   │   ├── main.py             # 入口：启动 API + 反代引擎
│   │   ├── config.py           # 配置与路径
│   │   ├── store.py            # SQLite 数据层
│   │   ├── api/                # HTTP API
│   │   │   ├── server.py
│   │   │   ├── domains.py
│   │   │   ├── ddns.py
│   │   │   ├── certs.py
│   │   │   └── proxies.py
│   │   ├── proxy/              # 反代引擎
│   │   │   ├── engine.py       # asyncio + SSL SNI
│   │   │   └── certs.py        # 读 network_gateway_cert.conf
│   │   ├── certs/              # 证书管理
│   │   │   ├── fnos_ws.py      # WebSocket 客户端（移植）
│   │   │   ├── seed.py         # 种子证书生成
│   │   │   └── manager.py      # 单域/多域签发编排
│   │   └── ddns/               # DDNS 管理
│   │       ├── fnos_db.py      # trim_connect 读写
│   │       └── manager.py      # 批量增删改 + 模板凭据
│   ├── www/
│   │   └── index.html          # 单页 UI
│   └── ui/
│       ├── config
│       └── index.cgi           # CGI 网关
├── wizard/
└── docs/
    ├── DESIGN.md               # 本文档
    ├── PROTOCOL.md             # fnOS WebSocket API 协议
    └── TESTING.md
```

---

## 六、可行性验证记录（nas 实测）

### 6.1 环境

```
fnOS:      1.2.1011
kernel:    6.18.18.c1191-trim
Python:    3.11.2
OpenSSL:   3.0.18
psql:      /usr/bin/psql
```

### 6.2 端口

```
:80/:443/:16666/:16667   fnOS nginx 独占
反代可用: 8080+（高位端口）
```

### 6.3 证书现状（nas）

```
cert 表 3 条：
  id=1   fnOS                          自签 fallback
  id=34  nas.fnos.net               YR1 (RSA)  多 SAN
  id=93  nas.example.com          YE2 (ECC)  7 个 SAN，renewal=1

证书目录：/usr/trim/var/trim_connect/ssls/<domain>/<epoch>/
权限：    -rw-rw---- root:www-data    （package 读不到，需加组）
登记表：  /usr/trim/etc/network_gateway_cert.conf
```

### 6.4 DDNS 现状（nas）

```
d_dns_record 共 8 条，全部 cloudflare

id  domain                      status  间隔
1   nas.example.com        suc     5m
2   list.example.com        suc     5m
3   router.example.com        suc     1m
8   app.example.com           suc     5m
9   media.example.com           suc     5m
11  seed.example.com      suc     5m
12  music.example.com        suc     1m
14  *.nas.example.com      suc     5m
```

### 6.5 ★ 关键验证：DDNS 凭据复用（已通过）

**测试方法**：
```sql
INSERT INTO d_dns_record (...) SELECT ..., '$TESTDOM', ...,
       access_key, access_secret FROM d_dns_record
       WHERE domain='list.example.com';
```

**结果**：
```
[20s] init||
[40s] init||
[60s] init||
[80s] suc||203.0.113.10      ← fnOS 自动完成上报
```

**结论：同根域凭据可以复用，fnOS 定时任务会自动生效，约 80 秒。**

**注意**：`access_secret` 密文每条不同（加密时带随机 IV），但**解密后是同一个 Token**，
所以复制密文完全可用。这推翻了「密文必须一致」的猜测。

测试记录已删除，`d_dns_record` 恢复为 8 条。

### 6.6 WebSocket API

```
端点:  wss://<host>:16667/websocket?type=main
认证:  密码登录（RSA-OAEP 换 AES，AES-256-CBC 加密登录帧）
签名:  base64(HMAC-SHA256(json, secret)) + json
```

`16667/websocket` 无认证时返回 502（正常，需完成握手流程）。

*（完整的实测记录，包括反代引擎、SNI、API、DDNS 的验证数据，见
[VERIFICATION.md](VERIFICATION.md)）*

---

## 七、分阶段实施计划

### Phase 1：骨架 + 反代（核心）

- [ ] 项目骨架、manifest、privilege
- [ ] `cmd/` 生命周期脚本（加 www-data 组）
- [ ] SQLite 数据层（proxy_rule、cert、ddns 三张表）
- [ ] 反代引擎（asyncio + SNI 动态证书）
- [ ] 证书路径读取（`network_gateway_cert.conf`）
- [ ] 最小 UI：列出/增删改反代规则
- [ ] nas 实测：用 fnOS 现有证书跑通一个 HTTPS 反代

**验收**：能用 8080 端口反代到内网服务，TLS 用 fnOS 的 `nas.example.com` 证书。

### Phase 2：DDNS 管理

- [ ] `ddns/fnos_db.py`：读写 `d_dns_record`
- [ ] 模板凭据逻辑（同根域复用）
- [ ] 批量添加/删除
- [ ] 状态轮询（读 fnOS 的 status 字段）
- [ ] UI：DDNS 列表 + 批量操作

**验收**：UI 里批量加 3 个域名，fnOS DDNS 列表能看到且状态变 `suc`。

### Phase 3：证书管理

- [ ] 移植 `fnos_ws.py`（WebSocket 客户端）
- [ ] 单域名签发（`cert.apply`）
- [ ] 多域名签发（种子证书 + `cert.renew`）
- [ ] 证书列表（读 fnOS `cert` 表）
- [ ] UI：签发表单（含 2FA 输入框）

**验收**：UI 里签发一张 2 域名 ECC 证书，fnOS 证书管理能看到且 `issuedBy=YE*`。

### Phase 4：融合与打磨

- [ ] 域名主数据视图（一个域名看到 DDNS/证书/规则）
- [ ] 联动检查（无 DDNS 不能签证书、无证书不能开 HTTPS 反代）
- [ ] 一键流程：加域名 → 建 DDNS → 签证书 → 建反代
- [ ] 日志、错误提示、状态可视化

---

## 八、关键设计决策与取舍

| 决策 | 选择 | 理由 | 放弃的方案 |
|---|---|---|---|
| 语言 | Python 3.11 | 复用现有代码，fnOS 自带 | Go（需重写+交叉编译） |
| 反代实现 | 自研 asyncio | 完全可控，SNI 动态证书 | 复用二进制（无法改） |
| 运行身份 | package + www-data 组 | 不抢特权端口，最小权限 | root（权限过大） |
| 监听端口 | 8080+ | 避开 fnOS 的 80/443 | 80/443（冲突） |
| 状态存储 | SQLite | 轻量，fnOS 自带 | 直接用 fnOS PG（耦合太深） |
| 证书续签 | 交给 fnOS | 不重复造轮子 | 自己定时 ACME |
| DDNS 上报 | 交给 fnOS | 不重复造轮子 | 自己实现 IP 检测 |
| DDNS 凭据 | 存 fnOS，不复制到本地 | 避免凭据泄漏风险 | 本地再存一份 |
| 前后端 | 同一包发布 | 避免版本错配（fn-reverseproxy 的教训） | 分离发布 |

---

## 九、风险与对策

| 风险 | 影响 | 对策 |
|---|---|---|
| fnOS 升级导致表结构变化 | DDNS/证书功能失效 | 版本检测 + 降级提示；关键操作前 `pg_dump` |
| fnOS 升级导致 WS 协议变化 | 证书签发失败 | 协议层版本号校验，失败时明确提示 |
| Python asyncio 反代性能 | 大文件传输慢 | 用 `sendfile`/零拷贝；必要时换 Go 数据面 |
| 2FA 阻断自动化 | 无法无人值守签证书 | 只要求「用户点按钮时」输入；续签由 fnOS 做 |
| 跨根域 DDNS | 新根域添加后上报失败 | UI 明确提示「先在 fnOS 原生界面加一条」 |
| 证书文件权限 | package 读不到 | `install_init` 加 `www-data` 组（已验证方案） |
| 直接写 fnOS 数据库 | 非官方方式 | 只写 `d_dns_record`，不碰其他表；操作前备份 |

---

## 十、与三个现有项目的关系

```
fn-reverseproxy  ──┐
                   │  反代 UI 骨架、index.cgi 思路、生命周期脚本模式
                   ├──▶  dnsrp
fnos-multidomain  ─┤  WS 客户端、证书签发编排、种子证书方案
fnos-ddns        ──┘  d_dns_record 表结构、模板凭据方案

ilanyu/ReverseProxy ──▶  反代设计参考（路由、配置模型）
```

**三个项目全部作为「能力来源」被吸收，不再单独维护。**

---

## 十一、待确认问题

1. **反代是否需要支持 WebSocket 透传？**（fnOS 应用中心内嵌 UI 用不到，但用户后端可能是 ws 服务）
2. **是否需要路径（path）路由？**（fn-reverseproxy 的 `PATH_PROXY_DESIGN.md` 里评估过，工作量中等）
3. **证书签发是否需要支持非 Let's Encrypt 的 CA？**（fnOS 的 `cert_lego_user.platform` 字段提示可能支持多 CA）
4. **DDNS 是否需要支持「手动指定 IP」（非 auto）？**（表里有 `ipv4`/`ipv4_addr` 两个字段）
5. **UI 语言**：仅中文，还是中英双语？（fnOS 支持多语言）

---

*文档版本 v0.1，待与需求方确认后进入 Phase 1 实施。*
