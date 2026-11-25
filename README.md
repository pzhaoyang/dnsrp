# dnsrp · 飞牛 OS 反向代理控制台

> 一体化域名控制台：**反向代理 + 证书管理 + DDNS**，全部复用飞牛 OS（fnOS）自有能力。
> 不抢占 80/443、不需要 root、不复制证书、不接管 DDNS 上报。

面向 [飞牛 OS](https://www.fnnas.com/) 的第三方 fpk 应用。运行身份为普通 `package` 用户，
仅使用高位端口，与系统服务零冲突。

---

## 为什么做这个

飞牛 OS 自带证书管理和 DDNS，但缺一个「按域名统一管理入口」的地方：

- 装了多个服务（Transmission、OpenList、qBittorrent…），想用不同域名访问
- 有多个子域名，想用同一张多域名证书
- 想看清「某个域名」的证书、DDNS、反代三者状态

**dnsrp 做的事**：把这三件事放到一个界面里，但底层全部走飞牛 OS——

| 能力 | 实现方式 |
|---|---|
| 反代证书 | 直接读 fnOS 的 `network_gateway_cert.conf`，不复制证书文件 |
| 证书签发 | 调用 fnOS 自己的 ACME 引擎（Let's Encrypt + DNS-01） |
| 证书续期 | 交给 fnOS（`renewal=1`），本应用不做定时任务 |
| DDNS 上报 | 复用 fnOS 的 gocron 定时任务，本应用不检测 IP |

---

## 功能

### 反向代理

- 按域名路由，支持 `*.example.com` 通配
- **TLS 证书实时从 fnOS 证书系统读取**，按 SNI 动态切换
- 一个端口绑多条规则（按域名分流）
- 支持 WebSocket 透传
- **只用高位端口**（默认 8080 起），绝不抢 80/443

### 证书管理

- 按**证书实体**展示（一张多 SAN 证书只算一张，不按域名重复计数）
- 显示覆盖域名、颁发者、有效期、剩余天数
- 支持签发单域名 / 多域名 / 通配符证书，RSA 或 ECC
- 支持删除证书（正在被使用的会阻止）
- 默认隐藏 fnOS 内置证书（自签兜底、FN Connect）

### DDNS

- 查看 / 添加 / 编辑 / 删除记录
- 编辑时可修改检查间隔和 API 凭据
- 状态实时反映 fnOS 的上报结果

### 升级防护

fnOS 的内部接口不是公开 API，可能随版本变化。本应用做了能力探测：

- 启动 / 切换页面时探测各项能力
- 接口失效时**降级提示 + 跳转指引**，不崩溃
- 设置页可手动「重新检测能力」

---

## 安装

### 前置条件

- 飞牛 OS **1.2.0 及以上**
- Python 3.11（fnOS 自带）
- 应用以 `package` 身份运行，无需 root

### 步骤

1. 下载 `dnsrp_x.y.z_all.fpk`
2. 飞牛 OS → **应用中心** → 右上角「手动安装」→ 选择 fpk
3. 安装完成后启动
4. 打开应用 → **设置** → 填写飞牛 OS 用户名和密码
5. 回到各页签，功能即可使用

> **为什么需要填密码？**
> fnOS 的内部接口（`appcgi.netsvr.cert.*` / `ddns.*`）要求请求带有会话密钥的 HMAC 签名，
> 而会话密钥与建立它的 WebSocket 连接绑定，无法跨进程复用。
> 因此应用必须用自己的凭据建立会话。
> 密码保存在应用数据目录（权限 `0600`），仅用于本机调用。

---

## 项目结构

```
dnsrp/
├── manifest               应用元信息（名称、版本、平台）
├── config/
│   ├── privilege          run-as: package，无特权能力
│   └── resource           {}
├── cmd/                   fnOS 生命周期脚本
│   ├── install_init       安装前：检查环境、加入 www-data 组
│   ├── install_callback   安装后：初始化数据库
│   ├── main               start / stop / status
│   ├── start.sh           启动主控进程
│   ├── upgrade_*          升级钩子
│   ├── uninstall_*        卸载钩子
│   └── common.sh          公共函数
├── app/
│   ├── dnrp/              主控程序（Python 3.11，仅标准库）
│   │   ├── main.py        入口：启动反代引擎 + HTTP 服务
│   │   ├── config.py      路径与常量
│   │   ├── store.py       SQLite 本地状态
│   │   ├── capabilities.py 能力探测与降级
│   │   ├── auth.py        凭据解析
│   │   ├── proxy/
│   │   │   ├── engine.py  asyncio 反代引擎
│   │   │   └── certs.py   fnOS 证书读取与 SNI
│   │   ├── certs/
│   │   │   ├── ws_client.py fnOS WebSocket 客户端
│   │   │   ├── manager.py   证书签发编排
│   │   │   └── seed.py      种子证书生成
│   │   ├── ddns/
│   │   │   ├── api_client.py 官方 DDNS API
│   │   │   └── fnos_db.py    数据库直读（备用）
│   │   └── api/
│   │       └── server.py  HTTP API + 静态文件
│   ├── ui/
│   │   ├── config         桌面图标入口（type: url）
│   │   ├── index.cgi      CGI 网关
│   │   └── images/
│   └── www/
│       └── index.html     单页界面
├── docs/
│   ├── DESIGN.md          架构设计
│   ├── PROTOCOL.md        fnOS 接口协议
│   └── VERIFICATION.md    真机验证记录
└── tools/                 开发辅助脚本
    ├── prebuild.sh        本地预检
    ├── verify_fpk.sh      打包后校验
    ├── deploy.sh          部署到设备
    ├── upload_fpk.sh      上传 fpk
    ├── appcenter_install.py   应用中心安装
    ├── appcenter_upgrade2.py  应用中心升级
    ├── get_secret.py      取 fnOS 会话密钥（调试用）
    └── setup_pg_dnrp.py   数据库权限配置（可选，默认不用）
```

---

## 技术要点

### 零第三方依赖

只用 Python 3.11 标准库。HTTP 服务、WebSocket 客户端、TLS 都由标准库实现。
OpenSSL 通过 `subprocess` 调用系统命令（RSA-OAEP 加密、证书生成）。

### 反代引擎

自研 asyncio 实现，没用现成的反代二进制：

```python
# 每个连接独立 SSLContext，避免 SNI 串号
sslobj.context = new_ctx    # 不能改共享的 context
```

> 踩坑记录：Python 的 `SSLObject.context` 是只读属性，
> 直接 `load_cert_chain()` 改的是**共享上下文**，连续连接会串号。

### 证书签发

飞牛 OS 的 `cert.apply` 只支持单域名且只能签 RSA。多域名 / 通配符 / ECC 需要走「种子证书」路径：

```
1. 生成自签多 SAN 种子证书（必须 CA:FALSE）
2. cert.upload 导入（base64 编码的 PEM）
3. cert.replace 赋予续签资格（renewal=1 + relatedDDNSId）
4. cert.renew 触发 fnOS 的 ACME 引擎
5. 轮询 applystatus 等待签发完成
```

**关键约束**：证书主域名必须与某条 DDNS 记录的域名**完全一致**，否则 fnOS 报 `Cert Apply Domain Not Match`。

### DDNS 编辑的坑

`ddns.record.update` 是**全量覆盖**接口：

```python
# 错误：会清空凭据
{"id": 1, "updateInterval": 10}
# 数据库 access_key 变成空，secret 变成 64 字符空密文

# 正确：必须把凭据原样带回
{"id":1, "domain":"x", "provider":"cloudflare",
 "ipv4":"auto", "ipv6":"auto", "updateInterval":10,
 "accessKey":"...", "accessSecret":"..."}
```

`record.list` 不返回凭据，但 `record.detail` 返回**明文**。
所以编辑前必须先 detail 读出、编辑时再回填。

---

## 开发

### 环境

需要 Windows + [fnpack](https://developer.fnnas.com/docs/cli/fnpack/) 打包工具，
以及一台可 SSH 的飞牛 OS 设备用于测试。

### 打包

```bash
# 注意：TMP 必须指向项目目录之外，否则 fnpack 会递归复制
export TMP=/path/outside/project/_build_tmp
cd /path/to/fn_fpk_packages
./fnpack.exe build --directory /path/to/dnsrp
```

### 预检

```bash
bash tools/prebuild.sh      # Python/Shell 语法、换行符、manifest 格式
bash tools/verify_fpk.sh    # 打包后校验内容完整性
```

---

## 已知限制

| 项 | 说明 |
|---|---|
| **需要填 fnOS 密码** | 内部接口要求会话级 HMAC 签名，无法复用网页会话（`errno=65534`） |
| **依赖未公开 API** | `appcgi.netsvr.*` 不是官方开放接口，fnOS 升级可能失效。已做能力探测降级 |
| **不支持 HTTP/2** | 反代只实现 HTTP/1.1 + TLS |
| **DDNS 凭据不能自动继承** | 添加新域名必须填该根域的 DNS 服务商凭据 |
| **2FA 影响签发** | 账号开了双重验证时，签发需现输验证码 |

---

## 免责声明

本项目为第三方应用，**与飞牛官方无关**。

它调用了 fnOS 的**未公开内部接口**，这些接口可能随系统版本变化而失效。
应用已尽力做降级处理（能力探测 + 明确提示），但**不保证在未来的 fnOS 版本上始终可用**。

使用前请确认你理解这一点。生产环境请自行评估风险。

---

## 许可

MIT License，详见 [LICENSE](LICENSE)。
