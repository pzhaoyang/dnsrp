# fnOS 内部接口协议备忘

> 本文档记录 DNS-RP 依赖的 fnOS 内部接口，**全部来自 nas 实测**。
> 仅供本项目使用，不保证跨版本稳定。

---

## 一、数据库：`trim_connect`

PostgreSQL 15，`localhost:5432`，用户 `postgres`（peer 认证，需 root 或 `sudo -u postgres`）。

### 1.1 `d_dns_record`（DDNS 记录）

```sql
CREATE TABLE d_dns_record (
    id                bigint      PRIMARY KEY,   -- 序列 d_dns_record_id_seq
    provider          varchar(32) NOT NULL,      -- cloudflare / alidns
    domain            varchar(256) NOT NULL,     -- 唯一索引 uk_domain
    ipv4              varchar(64),               -- 'auto' 或固定 IP
    ipv4_addr         varchar(128),              -- 实际解析到的 IPv4（fnOS 回填）
    ipv6              varchar(128),              -- 'auto' 或固定
    ipv6_addr         varchar(256),              -- 实际 IPv6（fnOS 回填）
    ttl               bigint,
    access_key        varchar(256),              -- 账号标识
    access_secret     varchar(512),              -- ★ 加密的 API Token
    status            text,                      -- init / suc / err
    last_update_time  bigint,                    -- 毫秒时间戳
    update_interval   smallint   NOT NULL DEFAULT 5,  -- 分钟
    query_url         varchar(128),
    last_update_error varchar(1024),
    created_time      bigint,
    updated_time      bigint
);
```

**关键结论（实测）**：

1. `access_secret` 是**加密存储**的，密文长度 128 字符，**每条都不同**（加密带随机 IV）
2. **但复制密文完全可用**——解密后是同一个 Token
3. 实测：复制同根域记录的 `access_secret` 到新记录，**80 秒内 fnOS 定时任务完成上报，status=suc**
4. 跨根域复制：数据库插入成功，但 fnOS 上报会失败（Token 不属于该域名）

**DNS-RP 的用法**：
```sql
-- 新增记录：从同根域的已有记录复制凭据
INSERT INTO d_dns_record
  (provider, domain, ipv4, ipv6, ttl, access_key, access_secret,
   status, last_update_time, update_interval, query_url,
   last_update_error, created_time, updated_time)
SELECT provider, '新域名', ipv4, ipv6, ttl, access_key, access_secret,
   'init', 当前毫秒, update_interval, '', '', 当前毫秒, 当前毫秒
FROM d_dns_record WHERE domain = '同根域的模板记录';
```

### 1.2 `cert`（证书）

```sql
CREATE TABLE cert (
    id                  bigint PRIMARY KEY,
    domain              varchar(1024) NOT NULL,  -- 主域名（CN）
    san                 varchar(1028),           -- 逗号分隔的 SAN
    valid_from          bigint,                  -- 秒时间戳
    valid_to            bigint,                  -- 秒时间戳
    encrypt_type        varchar(16),             -- RSA / ECC
    issued_by           varchar(256),            -- YR1/YR2=RSA链, YE1/YE2=ECC链, 域名=自签
    last_renew_time     bigint NOT NULL,
    des                 varchar(1024),           -- 备注
    is_default          smallint,                -- 1=fallback 证书
    renewal             smallint DEFAULT 0,      -- 1=允许自动续签
    source              varchar(16),
    private_key         varchar(256),            -- 文件路径
    certificate         varchar(256),            -- 文件路径
    issuer_certificate  varchar(256),            -- 中间证书路径
    status              varchar(16),             -- suc / err
    created_time        bigint,
    updated_time        bigint
);
```

**nas 实测数据**：

```
id=1   fnOS                   自签 fallback              is_default=1
id=34  nas.fnos.net        YR1 (RSA)  *.nas.fnos.net
id=93  nas.example.com   YE2 (ECC)  7 个 SAN, renewal=1
```

### 1.3 `cert_renew`（续签配置）

```sql
CREATE TABLE cert_renew (
    id                bigint PRIMARY KEY,
    cert_id           bigint NOT NULL,
    verify_type       varchar(16),               -- dns-01
    renew_email       varchar(256),
    platform          varchar(16) DEFAULT 'letsencrypt',
    ddns_provider     varchar(16),
    access_key        varchar(256),
    access_secret     varchar(256),
    renew_cert_url    varchar(1024),
    ddns_related_id   bigint NOT NULL DEFAULT 0, -- 指向 d_dns_record.id
    last_renew_time   bigint,
    last_renew_error  varchar(1024),
    created_time      bigint,
    updated_time      bigint
);
```

### 1.4 `cert_used_config`（证书服务绑定）

```sql
CREATE TABLE cert_used_config (
    id           bigint PRIMARY KEY,
    cert_id      bigint NOT NULL,
    service_name varchar(64),      -- 如 'reverseproxy'
    created_time bigint,
    updated_time bigint
);
```

nas 实测：**空表**（当前没有服务绑定证书）。

### 1.5 `cert_lego_user`（ACME 账号）

```sql
CREATE TABLE cert_lego_user (
    id           bigint PRIMARY KEY,
    email        varchar(128) NOT NULL,
    platform     varchar(32) NOT NULL,   -- letsencrypt
    eab_kid      varchar(128),
    eab_key      varchar(256),
    private_key  varchar(4012),
    registration varchar(1024),
    status       bigint NOT NULL DEFAULT 1,
    created_time bigint,
    updated_time bigint
);
```

### 1.6 `domain`

```sql
CREATE TABLE domain (
    id           bigint PRIMARY KEY,
    fn_id        varchar(32) NOT NULL,
    domain       varchar(64) NOT NULL,
    source       varchar(16) NOT NULL DEFAULT 'trim',
    created_time bigint,
    updated_time bigint
);
```

---

## 二、文件：证书

### 2.1 目录结构

```
/usr/trim/var/trim_connect/ssls/<domain>/<epoch>/
```

`<epoch>` 是签发时间戳，每次续签都新建目录。

**文件名不统一**（实测 4 种）：
```
fullchain.crt / cert.crt / issued.crt / <domain>.crt
private.key / <domain>.key / fnOS.key
```

### 2.2 权限

```
-rw-rw----  root:www-data    新版本（2026-09 起）
-rw-rw-r--  root:www-data    被手工放宽过
-rwxr-xr-x  root:root        老版本
```

**package 用户读不到 `0640` 的**，需加入 `www-data` 组。

### 2.3 证书登记表

`/usr/trim/etc/network_gateway_cert.conf`

```json
[{"host":"fallback","cert":".../fnOS/<epoch>/fnOS.crt","key":".../fnOS/<epoch>/fnOS.key"},
 {"host":"nas.example.com","cert":".../fullchain.crt","key":"....key"},
 ...]
```

**这是反代取证书的权威来源**（而不是遍历目录）。

fnOS nginx 的用法：
```nginx
trim_cert_cfg_path /usr/trim/etc/network_gateway_cert.conf;
ssl_certificate      $ssl_server_name;   # 握手时按 SNI 取
ssl_certificate_key  $ssl_server_name;
```

---

## 三、WebSocket API

### 3.1 端点

```
wss://<host>:<webui_https_port>/websocket?type=main
```

nas 的 WebUI HTTPS 端口是 **16667**。

### 3.2 认证流程（密码登录）

```
1. 连 WS（无需 Cookie）
2. 发明文帧 {"req":"util.crypto.getRSAPub"}
   ← {pub: PEM, si: 会话ID}
3. 生成随机 32 字节 AES key + 16 字节 IV
4. RSA-OAEP-SHA256 加密 AES key → rsa 字段
5. AES-256-CBC(PKCS7) 加密内层 JSON → aes 字段
6. 发 {"req":"encrypted","iv","rsa","aes","v":1}
7. 内层:
   {"req":"user.login","user":"...","password":"...",
    "deviceName":"...","deviceType":"Browser","stay":true,
    "did":<设备id>,"si":<会话ID>}
   ← {uid, admin, token, longToken, secret, backId, ...}
8. secret 是 AES 加密的:
   base64decode → AES-CBC 解密（用步骤 4 的 aes_key + iv）
   → 去 PKCS7 padding → HMAC 密钥（18 字节）
```

### 3.3 签名帧

```
frame = base64( HMAC-SHA256( json, secret_bytes ) ) + json
```

- `secret_bytes` = 上述 18 字节密钥
- base64 输出**自带 padding，不要额外补 `=`**
- `reqid`：28 位 hex（时间8+随机8+计数器12），无需会话常量

### 3.4 证书相关端点

| 端点 | 作用 | 关键参数 |
|---|---|---|
| `cert.apply` | 申请**单域名**证书 | `domain`, `renewEmail`（必填）, `relatedDDNSId` |
| `cert.upload` | 导入证书+私钥（base64） | SAN 从 X.509 解析 |
| `cert.replace` | 替换证书内容/补续签资格 | `renewal:1`, `relatedDDNSId` |
| `cert.renew` | 触发 fnOS ACME 按全部 SAN 续签 | `id` |
| `cert.list` | 列出证书 | — |

### 3.5 错误码

| errno | 含义 |
|---|---|
| 8192 | 参数错误 |
| 131072 | 用户名或密码错误 |
| 131073 | 用户名不存在 |
| 135168 | 无效凭证 / 2FA 码错误或过期 |
| 3000001 | Invalid Params（字段类型错） |
| 3000033 | Cert Apply Domain Not Match（申请接口单域名校验） |
| 3000034 | Cert Apply DDNS Record Not Found |
| 3000035 | Cert Not Renewable |
| 65534 | 验签失败（会话未绑定 / HMAC 不对） |
| 65535 | 未知错误 |

### 3.6 多域名签发配方

```
1. 生成自签多 SAN 种子证书
   ★ 必须 CA:FALSE（openssl req -x509 默认 CA:TRUE 会导致 renew 报错）
2. cert.upload(cert_pem, key_pem)
3. cert.replace(id, renewal=1, relatedDDNSId=<d_dns_record.id>)
4. cert.renew(id)   → fnOS ACME 按全部 SAN 走 DNS-01 签真证书
5. （可选）读磁盘真证书再 replace 一次，补回备注
```

**约束**：
- 证书域名必须与 `relatedDDNSId` 对应记录的 `domain` 对得上，否则 `3000033`
- 跨 zone 的域名（`a.com` + `b.net`）无法合成一张证书
- 通配符 `*.x` 是**独立**的 DDNS 记录，不是普通记录的映射

---

## 四、端口与冲突

### 4.1 fnOS 占用

```
:80      trim_nginx（HTTP→HTTPS 跳转）
:443     trim_nginx
:16666   WebUI HTTP
:16667   WebUI HTTPS + WebSocket
:5432    PostgreSQL
```

`nginx.conf` 的 `listen 80/443` 是**硬编码在 nginx 二进制里**的，
且每次启动都重新生成配置文件，所以改配置无效。

**唯一官方开关**：`/usr/trim/etc/network_gateway_setting.conf` 的 `redirect` 字段。
设为 `false` 可让 nginx 放弃 80/443，但会**失去 `http://<host>` 跳转**。

### 4.2 DNS-RP 的策略

**不使用 80/443**，只用 8080+。

理由：
- 不与 fnOS 争抢系统端口
- 不需要特权能力（package 身份即可）
- 用户可自行选择端口

---

## 五、加密密钥位置

```
/usr/trim/etc/trim.key.enc      284 字节，root:root 0600
/usr/trim/etc/rsa_private_key.pem  1708 字节，root:root 0600
```

fnOS 用它们加密 `access_secret` 等敏感字段。

**DNS-RP 不解密、不存储这些密钥** —— 直接复制密文即可（已实测可用）。

---

## 六、实测环境快照（nas）

```
fnOS:      1.2.1011
kernel:    6.18.18.c1191-trim
Python:    3.11.2
OpenSSL:   3.0.18

cert 表:     3 条
d_dns_record: 8 条，全部 cloudflare
证书目录:     12 个 domain 子目录
```

---

*本文档基于 nas 实测，fnOS 升级后需复核。*
