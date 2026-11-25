#!/bin/bash
#
# DNS-RP 公共函数库
#
# 设计前提（均已实测）：
#   1. 应用以 package 身份运行，不使用 root、不申请特权能力
#   2. 只使用高位端口（默认 8080），不碰 80/443/16666/16667
#   3. 读 fnOS 证书需要 www-data 组（证书是 root:www-data 0640）
#   4. 写 fnOS DDNS 表需要以 postgres 用户执行 psql（peer 认证）
#
# 本文件只定义函数，不产生副作用。

APP_NAME="DNS-RP"
APP_USER="DNS-RP"
APP_GROUP="www-data"

FNOS_SSL_ROOT="/usr/trim/var/trim_connect/ssls"
FNOS_CERT_REGISTRY="/usr/trim/etc/network_gateway_cert.conf"

dnrp_log() { echo "[DNS-RP] $*"; }

# ---------------------------------------------------------------- 目录推导

dnrp_pkgvar() {
    printf '%s' "${TRIM_PKGVAR:-/var/apps/${APP_NAME}/var}"
}

dnrp_appdest() {
    printf '%s' "${TRIM_APPDEST:-/var/apps/${APP_NAME}/target}"
}

# ---------------------------------------------------------------- 运行用户

# 探测本应用实际以哪个用户运行。
# fnOS 以 package 身份运行时，用户名通常等于 appname。
dnrp_detect_user() {
    local guess="${1:-$APP_USER}"

    # 1) 显式指定
    if [ -n "$guess" ] && id "$guess" >/dev/null 2>&1; then
        printf '%s' "$guess"
        return 0
    fi

    # 2) appname 原样（fnOS 通常用 appname 作为用户名，保留大小写）
    if id "$APP_NAME" >/dev/null 2>&1; then
        printf '%s' "$APP_NAME"
        return 0
    fi

    # 3) appname 小写
    local lower
    lower=$(printf '%s' "$APP_NAME" | tr '[:upper:]' '[:lower:]')
    if id "$lower" >/dev/null 2>&1; then
        printf '%s' "$lower"
        return 0
    fi

    # 4) 从应用目录属主反查（fnOS 会 chown 到应用用户）
    local dest owner
    dest=$(dnrp_appdest)
    if [ -d "$dest" ]; then
        owner=$(stat -c '%U' "$dest" 2>/dev/null)
        if [ -n "$owner" ] && [ "$owner" != "root" ] && id "$owner" >/dev/null 2>&1; then
            printf '%s' "$owner"
            return 0
        fi
    fi

    # 5) 从 /etc/passwd 里找名字含 appname（忽略大小写）的用户
    local cand
    cand=$(awk -F: -v n="$(printf '%s' "$APP_NAME" | tr '[:upper:]' '[:lower:]')" \
           'tolower($1) == n {print $1; exit}' /etc/passwd 2>/dev/null)
    if [ -n "$cand" ] && id "$cand" >/dev/null 2>&1; then
        printf '%s' "$cand"
        return 0
    fi

    return 1
}

# ---------------------------------------------------------------- 证书权限

dnrp_ensure_wwwdata() {
    local user="$1"
    [ -n "$user" ] || return 1

    if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx "$APP_GROUP"; then
        dnrp_log "用户 $user 已在组 $APP_GROUP"
        return 0
    fi

    if ! getent group "$APP_GROUP" >/dev/null 2>&1; then
        dnrp_log "警告：系统里没有 $APP_GROUP 组，跳过"
        return 1
    fi

    if usermod -aG "$APP_GROUP" "$user" 2>/dev/null; then
        dnrp_log "已将 $user 加入 $APP_GROUP 组（读 fnOS 证书所需）"
        return 0
    fi

    dnrp_log "加入组失败：$user -> $APP_GROUP"
    return 1
}

# 验证当前用户能否读到证书（以目标用户身份试读）
dnrp_verify_cert_access() {
    local user="${1:-}"
    [ -f "$FNOS_CERT_REGISTRY" ] || { dnrp_log "证书登记表不存在"; return 1; }

    local total=0 ok=0
    local tmp
    tmp=$(mktemp)
    python3 - "$FNOS_CERT_REGISTRY" > "$tmp" 2>/dev/null <<'PYEOF'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
seen = set()
for item in data if isinstance(data, list) else []:
    for k in ("cert", "key"):
        v = item.get(k)
        if v and v not in seen:
            seen.add(v)
            print(v)
PYEOF

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        [ -f "$f" ] || continue
        total=$((total + 1))
        if [ -n "$user" ] && [ "$(id -u)" = "0" ]; then
            su -s /bin/sh "$user" -c "head -c 1 '$f' >/dev/null 2>&1" && ok=$((ok + 1))
        else
            head -c 1 "$f" >/dev/null 2>&1 && ok=$((ok + 1))
        fi
    done < "$tmp"
    rm -f "$tmp"

    dnrp_log "证书可读性: $ok/$total"
    [ "$total" -gt 0 ] && [ "$ok" -eq "$total" ]
}

# ---------------------------------------------------------------- DDNS 权限

# 验证能否以 postgres 用户访问 trim_connect
dnrp_verify_ddns_access() {
    if sudo -n -u postgres psql -d trim_connect -t -A \
         -c "SELECT count(*) FROM d_dns_record;" >/dev/null 2>&1; then
        local n
        n=$(sudo -n -u postgres psql -d trim_connect -t -A \
              -c "SELECT count(*) FROM d_dns_record;" 2>/dev/null | tr -d ' ')
        dnrp_log "fnOS DDNS 表可访问（$n 条记录）"
        return 0
    fi
    dnrp_log "无法访问 fnOS DDNS 表（需要 postgres 用户权限，DDNS 功能将不可用）"
    return 1
}

# ---------------------------------------------------------------- Python

dnrp_python() {
    if command -v python3 >/dev/null 2>&1; then
        command -v python3
        return 0
    fi
    return 1
}

dnrp_check_python() {
    local py
    py=$(dnrp_python) || { dnrp_log "错误：找不到 python3"; return 1; }
    local ver
    ver=$("$py" -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
    dnrp_log "Python $ver ($py)"
    case "$ver" in
        3.9|3.1[0-9]|3.[2-9][0-9]) return 0 ;;
        *) dnrp_log "警告：建议 Python 3.9+，当前 $ver"; return 1 ;;
    esac
}
