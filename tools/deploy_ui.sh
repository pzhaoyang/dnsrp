#!/usr/bin/env bash
#
# 部署界面改动到设备（不走应用中心，快速迭代用）
#
# 用法：
#   export DNRP_HOST=192.168.1.10
#   export DNRP_USER=your-user
#   export DNRP_SSH_PORT=2705
#   export DNRP_SSH_PASS=your-password      # 或配好 SSH 密钥
#   bash tools/deploy_ui.sh
#
# 说明：
#   本脚本把 app/dnrp 和 app/www 打包后传到设备并重启进程，
#   用于开发期快速验证。正式发布请用 tools/appcenter.py upgrade。

set -euo pipefail

HOST="${DNRP_HOST:?请设置 DNRP_HOST}"
USER="${DNRP_USER:?请设置 DNRP_USER}"
PORT="${DNRP_SSH_PORT:-2705}"
APP="/vol1/@appcenter/${DNRP_APPNAME:-dnsrp}"
VAR="/vol1/@appdata/${DNRP_APPNAME:-dnsrp}"
PKGNAME="${DNRP_APPNAME:-dnsrp}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMPTGZ="$(mktemp -t dnrp-XXXXXX.tgz)"
trap 'rm -f "$TMPTGZ"' EXIT

echo "=== 1. 打包代码 ==="
( cd "$ROOT/app" && tar czf "$TMPTGZ" \
    --exclude='__pycache__' --exclude='*.pyc' dnrp www )
echo "  $(stat -c %s "$TMPTGZ") 字节"

echo
echo "=== 2. 上传 ==="
if [ -n "${DNRP_SSH_PASS:-}" ]; then
  # 用 sshpass（若已安装）
  if command -v sshpass >/dev/null 2>&1; then
    sshpass -p "$DNRP_SSH_PASS" scp -P "$PORT" -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      "$TMPTGZ" "$USER@$HOST:/tmp/dnrp-ui.tgz"
  else
    echo "  未安装 sshpass，改用交互式 scp（会提示输密码）"
    scp -P "$PORT" "$TMPTGZ" "$USER@$HOST:/tmp/dnrp-ui.tgz"
  fi
else
  scp -P "$PORT" "$TMPTGZ" "$USER@$HOST:/tmp/dnrp-ui.tgz"
fi
echo "  完成"

echo
echo "=== 3. 远端解包并重启 ==="
REMOTE_CMD=$(cat <<EOS
set -e
APP="$APP"
VAR="$VAR"
cd "\$APP"
tar xzf /tmp/dnrp-ui.tgz
rm -f /tmp/dnrp-ui.tgz
sudo -n chown -R ${PKGNAME}:${PKGNAME} "\$APP" 2>/dev/null || true
sudo -n pkill -9 -f 'dnrp.main' 2>/dev/null || true
sleep 3
sudo -n -u ${PKGNAME} bash -c "cd \$APP && PYTHONPATH=\$APP \
  TRIM_PKGVAR=\$VAR TRIM_APPDEST=\$APP \
  nohup python3 -m dnrp.main >> \$VAR/dnrp.log 2>&1 &"
sleep 8
echo "  pid=\$(pgrep -f 'dnrp.main' | head -1)"
EOS
)

if [ -n "${DNRP_SSH_PASS:-}" ] && command -v sshpass >/dev/null 2>&1; then
  sshpass -p "$DNRP_SSH_PASS" ssh -p "$PORT" -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null "$USER@$HOST" "$REMOTE_CMD"
else
  ssh -p "$PORT" "$USER@$HOST" "$REMOTE_CMD"
fi

echo
echo "=== 4. 验证 ==="
curl -s --max-time 20 "http://$HOST:8765/api/health" || echo "  （若端口不是 8765，请改这里）"
echo
