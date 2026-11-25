#!/bin/bash
#
# dnsrp 启动/停止脚本
#
# 用法: main {start|stop|restart|status}
#
# 由 fnOS 应用中心调用；也可手动执行便于调试。

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "${HERE}/common.sh" 2>/dev/null || {
    echo "[dnsrp] 无法加载 common.sh"
    exit 1
}

PKGVAR=$(dnrp_pkgvar)
APPDEST=$(dnrp_appdest)
PID_FILE="${PKGVAR}/dnrp.pid"
LOG_FILE="${PKGVAR}/dnrp.log"
SOCKET="${PKGVAR}/dnrp.sock"

is_running() {
    [ -f "$PID_FILE" ] || return 1
    local pid
    pid=$(head -n1 "$PID_FILE" 2>/dev/null | tr -d '[:space:]')
    [ -n "$pid" ] || return 1
    kill -0 "$pid" 2>/dev/null
}

do_start() {
    if is_running; then
        dnrp_log "已在运行 (PID $(cat "$PID_FILE"))"
        return 0
    fi

    dnrp_log "========== 启动 =========="
    mkdir -p "$PKGVAR" 2>/dev/null || {
        dnrp_log "错误：无法创建 $PKGVAR"
        return 1
    }

    local py
    py=$(dnrp_python) || { dnrp_log "错误：找不到 python3"; return 1; }

    local app_py="${APPDEST}/dnrp"
    if [ ! -d "$app_py" ]; then
        dnrp_log "错误：程序目录不存在 $app_py"
        return 1
    fi

    # 以 python 模块方式启动，PYTHONPATH 指向 app 目录
    cd "${APPDEST}" || return 1

    nohup env \
        PYTHONPATH="${APPDEST}" \
        TRIM_PKGVAR="$PKGVAR" \
        TRIM_APPDEST="$APPDEST" \
        PYTHONUNBUFFERED=1 \
        "$py" -m dnrp.main >> "$LOG_FILE" 2>&1 &

    local pid=$!
    printf '%s' "$pid" > "$PID_FILE"
    dnrp_log "进程已拉起 PID=$pid，等待就绪..."

    # 最多等 15 秒，等 unix socket 出现
    local i=0
    while [ "$i" -lt 15 ]; do
        sleep 1
        if [ -S "$SOCKET" ]; then
            dnrp_log "已就绪（socket: $SOCKET）"
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            dnrp_log "进程启动后立即退出，请查看日志: $LOG_FILE"
            tail -n 20 "$LOG_FILE" 2>/dev/null
            rm -f "$PID_FILE"
            return 1
        fi
        i=$((i + 1))
    done

    dnrp_log "等待超时，但进程仍在运行（PID=$pid）。查看日志: $LOG_FILE"
    return 0
}

do_stop() {
    if ! is_running; then
        dnrp_log "未在运行"
        rm -f "$PID_FILE"
        return 0
    fi

    local pid
    pid=$(cat "$PID_FILE" | tr -d '[:space:]')
    dnrp_log "停止 PID=$pid"
    kill "$pid" 2>/dev/null

    local i=0
    while [ "$i" -lt 10 ] && kill -0 "$pid" 2>/dev/null; do
        sleep 1
        i=$((i + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        dnrp_log "SIGTERM 超时，发送 SIGKILL"
        kill -9 "$pid" 2>/dev/null
    fi

    rm -f "$PID_FILE" "$SOCKET"
    dnrp_log "已停止"
    return 0
}

case "${1:-}" in
    start)   do_start ;;
    stop)    do_stop ;;
    restart) do_stop; sleep 1; do_start ;;
    status)
        if is_running; then
            echo "Running (PID $(cat "$PID_FILE"))"
            exit 0
        fi
        echo "Not running"
        exit 3
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}" >&2
        exit 1
        ;;
esac
