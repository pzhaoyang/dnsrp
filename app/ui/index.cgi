#!/bin/bash
# DNS-RP 的 CGI 网关
#
# 职责：
#   1. /api/*  → 转发到本地 unix socket（dnrp 主控进程）
#   2. 其他     → 从 www/ 提供静态文件
#
# 设计参考 fn-reverseproxy 的 index.cgi，但做了精简：
#   - 新增 /api/certs 等路由由 dnrp 统一处理，网关只做透传
#   - 静态文件不缓存（UI 频繁迭代）

set -u

APP_ROOT="${TRIM_APPDEST:-/var/apps/DNS-RP/target}"
BASE_PATH="${APP_ROOT}/www"
SOCKET="${TRIM_PKGVAR:-/var/apps/DNS-RP/var}/dnrp.sock"

REQUEST_METHOD="${REQUEST_METHOD:-GET}"
REQUEST_URI="${REQUEST_URI:-/}"

BODY_TMP=""
HDR_TMP=""
OUT_BODY=""

cleanup() { rm -f "$BODY_TMP" "$HDR_TMP" "$OUT_BODY" 2>/dev/null; }
trap cleanup EXIT

cgi_header() { printf '%s\r\n' "$1"; }

send_text() {
    local status="$1" body="${2:-}"
    cgi_header "Status: $status"
    cgi_header "Content-Type: text/plain; charset=utf-8"
    cgi_header "Content-Length: ${#body}"
    cgi_header ""
    [ "$REQUEST_METHOD" != "HEAD" ] && [ -n "$body" ] && printf '%s' "$body"
    exit 0
}

detect_mime() {
    local ext="${1##*.}"
    ext="$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')"
    case "$ext" in
        html|htm) printf 'text/html; charset=utf-8' ;;
        css)      printf 'text/css; charset=utf-8' ;;
        js)       printf 'application/javascript; charset=utf-8' ;;
        json)     printf 'application/json; charset=utf-8' ;;
        svg)      printf 'image/svg+xml' ;;
        png)      printf 'image/png' ;;
        jpg|jpeg) printf 'image/jpeg' ;;
        gif)      printf 'image/gif' ;;
        ico)      printf 'image/x-icon' ;;
        webp)     printf 'image/webp' ;;
        woff)     printf 'font/woff' ;;
        woff2)    printf 'font/woff2' ;;
        ttf)      printf 'font/ttf' ;;
        *)        printf 'application/octet-stream' ;;
    esac
}

resolve_rel_path() {
    local uri="${REQUEST_URI%%\?*}"
    local rel="/"
    case "$uri" in
        *index.cgi*) rel="${uri#*index.cgi}" ;;
    esac
    [ -z "$rel" ] && rel="/"
    [ "$rel" = "/" ] && rel="/index.html"
    [ "${rel#/}" = "$rel" ] && rel="/$rel"
    case "$rel" in */) rel="${rel}index.html" ;; esac
    printf '%s' "$rel"
}

# ---------- 从 Cookie 提取 fnOS 会话凭证 ----------
#
# 用户在飞牛 OS 网页里登录后，浏览器带着 fnos-token / fnos-Secret。
# 这些值通过 HTTP_COOKIE 环境变量进入 CGI，本函数把它们转成 JSON，
# 让后端不需要用户再填一次密码。
#
# 输出示例：
#   {"token":"xxx","secret":"yyy","device":"zzz"}
# 任何一项都没有时返回空串。
extract_fnos_creds() {
    local cookie="${HTTP_COOKIE:-}"
    [ -n "$cookie" ] || return 0

    local token="" secret="" device=""
    local saved_ifs="$IFS"
    local IFS=';'
    local item k v
    for item in $cookie; do
        # 去首尾空白
        item="${item#"${item%%[![:space:]]*}"}"
        item="${item%"${item##*[![:space:]]}"}"
        [ -n "$item" ] || continue
        k="${item%%=*}"
        v="${item#*=}"
        case "$k" in
            fnos-token)  token="$v" ;;
            fnos-Secret) secret="$v" ;;
            fnos-device) device="$v" ;;
        esac
    done
    IFS="$saved_ifs"

    [ -n "$token" ] || [ -n "$secret" ] || return 0

    # 手工拼 JSON（值只可能是 base64/十六进制，不含需要转义的字符）
    printf '{"token":"%s","secret":"%s","device":"%s"}' \
        "$token" "$secret" "$device"
}

# ---------- API 透传 ----------
proxy_api() {
    local rel="$1"
    local url="http://localhost${rel}"
    [ -n "${QUERY_STRING:-}" ] && url="${url}?${QUERY_STRING}"

    HDR_TMP="$(mktemp)" || send_text "500 Internal Server Error" "mktemp failed"
    OUT_BODY="$(mktemp)" || send_text "500 Internal Server Error" "mktemp failed"

    local args=(-sS --http1.1 --connect-timeout 5 --max-time 300
                -D "$HDR_TMP" -o "$OUT_BODY" -X "$REQUEST_METHOD"
                -H "Connection: close")

    # 透传常用请求头
    for pair in \
        "CONTENT_TYPE:Content-Type" \
        "HTTP_ACCEPT:Accept" \
        "HTTP_AUTHORIZATION:Authorization" \
        "HTTP_COOKIE:Cookie" \
        "HTTP_USER_AGENT:User-Agent" \
        "HTTP_REFERER:Referer"
    do
        env_name="${pair%%:*}"
        hdr_name="${pair#*:}"
        val="${!env_name:-}"
        [ -n "$val" ] && args+=(-H "${hdr_name}: ${val}")
    done

    # ★ 前端从 localStorage 读到的 fnOS 凭证，通过 X-Dnrp-* 头传进来。
    #   这在「legacy 模式」（凭证不在 Cookie 里）下是唯一来源。
    for pair in \
        "HTTP_X_DNRP_TOKEN:X-Dnrp-Token" \
        "HTTP_X_DNRP_SECRET:X-Dnrp-Secret" \
        "HTTP_X_DNRP_DEVICE:X-Dnrp-Device"
    do
        env_name="${pair%%:*}"
        hdr_name="${pair#*:}"
        val="${!env_name:-}"
        [ -n "$val" ] && args+=(-H "${hdr_name}: ${val}")
    done

    # ★ 关键：把浏览器的 fnOS 会话凭证单独抽出来，用自定义头送给后端。
    #
    # 为什么不用 HTTP_COOKIE 就够：
    #   后端是常驻进程（不是 CGI），读不到 CGI 的环境变量。
    #   Cookie 虽然透传了，但后端解析整串 Cookie 容易受其他应用干扰，
    #   所以这里精准提取 fnos-token / fnos-Secret / fnos-device，
    #   拼成 JSON 放进 X-Dnrp-Creds 头。
    #
    # ★ 安全性：
    #   * 只走本机 unix socket，不出机器
    #   * 后端只在内存里用，绝不落盘、不写日志明文
    local creds_json
    creds_json="$(extract_fnos_creds)" || creds_json=""
    [ -n "$creds_json" ] && args+=(-H "X-Dnrp-Creds: ${creds_json}")

    # 请求体
    case "$REQUEST_METHOD" in
        POST|PUT|PATCH|DELETE)
            if [ -n "${CONTENT_LENGTH:-}" ] && [ "${CONTENT_LENGTH:-0}" -gt 0 ] 2>/dev/null; then
                BODY_TMP="$(mktemp)"
                dd bs=1 count="$CONTENT_LENGTH" of="$BODY_TMP" 2>/dev/null || cat >"$BODY_TMP"
                [ -s "$BODY_TMP" ] && args+=(--data-binary "@$BODY_TMP")
            fi
            ;;
    esac

    # 后端未启动时给出可读提示，而不是裸 502
    if [ ! -S "$SOCKET" ]; then
        send_text "503 Service Unavailable" \
            "DNS-RP 主控进程未运行（socket 不存在：$SOCKET）。请在应用中心启动本应用。"
    fi

    curl --unix-socket "$SOCKET" "${args[@]}" "$url"
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        if [ "$rc" -eq 7 ]; then
            send_text "503 Service Unavailable" "无法连接主控进程（socket 存在但拒绝连接）。"
        fi
        send_text "502 Bad Gateway" "后端请求失败（curl exit=$rc）"
    fi

    # 解析后端响应头
    local status="502" ctype="application/json; charset=utf-8"
    local -a extra=()
    local line
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        [ -z "$line" ] && continue
        case "$line" in
            HTTP/*) set -- $line; status="${2:-502}" ;;
            [Cc]ontent-[Tt]ype:*)
                ctype="${line#*: }"; ctype="${ctype%$'\r'}" ;;
            # Cache-Control 统一由下面输出，避免重复
            [Cc]ache-[Cc]ontrol:*) ;;
            [Ss]et-[Cc]ookie:*|[Ll]ocation:*) extra+=("$line") ;;
        esac
    done < "$HDR_TMP"

    cgi_header "Status: $status"
    cgi_header "Content-Type: $ctype"
    cgi_header "Cache-Control: no-store"
    for h in "${extra[@]}"; do cgi_header "$h"; done
    cgi_header "Content-Length: $(wc -c < "$OUT_BODY" 2>/dev/null || echo 0)"
    cgi_header ""

    [ "$REQUEST_METHOD" != "HEAD" ] && [ -f "$OUT_BODY" ] && cat "$OUT_BODY"
    exit 0
}

# ---------- 静态文件 ----------
serve_static() {
    local rel="$1"

    # 路径穿越防护
    case "$rel" in
        *../*|*/..|..) send_text "400 Bad Request" "path traversal" ;;
    esac

    local target="${BASE_PATH}${rel}"
    if [ ! -f "$target" ] || [ ! -r "$target" ]; then
        send_text "404 Not Found" "404 Not Found: $rel"
    fi

    local mime size
    mime="$(detect_mime "$target")"
    size="$(wc -c < "$target")"

    cgi_header "Content-Type: $mime"
    cgi_header "Content-Length: $size"
    # UI 迭代频繁，禁用缓存避免出现「改了没生效」的错觉
    cgi_header "Cache-Control: no-store, must-revalidate"
    cgi_header ""

    [ "$REQUEST_METHOD" != "HEAD" ] && cat "$target"
    exit 0
}

REL_PATH="$(resolve_rel_path)"

case "$REL_PATH" in
    /api|/api/*) proxy_api "$REL_PATH" ;;
    *)           serve_static "$REL_PATH" ;;
esac
