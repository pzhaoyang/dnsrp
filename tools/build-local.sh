#!/usr/bin/env bash
# 本地构建 fpk —— 等价于 .github/workflows/build-release.yml 的「预检 + 打包 + 校验」部分
#
# 与 GitHub Actions 的区别：
#   - 跳过 actions/checkout / setup-python（本地已有代码和 Python）
#   - 跳过 Create Release（只在 GitHub 上创建）
#   - 其余步骤（必需文件/语法/LF 检查 → 下载 fnpack → 打包 → 校验）完全一致
#
# 用法：
#   bash tools/build-local.sh
#   TMPDIR=/custom/tmp bash tools/build-local.sh

set -euo pipefail

# 项目根目录（脚本所在目录的上一级）
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OUT="${BUILD_OUT:-$ROOT/dist}"
WORK="${TMPDIR:-/tmp}/dnrp-build-$$"
mkdir -p "$OUT" "$WORK"
trap 'rm -rf "$WORK"' EXIT

echo "=========================================="
echo " dnsrp 本地构建"
echo " 项目: $ROOT"
echo " 输出: $OUT"
echo "=========================================="

# ---------- 1. 读版本 ----------
VERSION=$(grep '^version' manifest | awk -F= '{print $2}' | xargs)
echo
echo "[1/5] 版本: $VERSION"

# ---------- 2. 预检 ----------
echo
echo "[2/5] 预检"
for f in manifest ICON.PNG ICON_256.PNG config/privilege config/resource \
         app/ui/config app/ui/index.cgi app/ui/images/icon_64.png \
         app/ui/images/icon_256.png app/www/index.html \
         cmd/main cmd/start.sh cmd/common.sh; do
  [ -f "$f" ] || { echo "  ✗ 缺失: $f"; exit 1; }
done
echo "  ✓ 必需文件齐全"

python3 -m compileall -q app/dnrp
find app -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
echo "  ✓ Python 语法"

for f in cmd/*; do
  [ -f "$f" ] || continue
  bash -n "$f" || exit 1
done
echo "  ✓ Shell 语法"

if grep -rl $'\r' manifest config cmd app --include='*.py' \
           --include='*.sh' --include='*.cgi' 2>/dev/null; then
  echo "  ✗ 发现 CRLF，终止"; exit 1
fi
echo "  ✓ 全部 LF"

# ---------- 3. fnpack ----------
echo
echo "[3/5] fnpack"
if [ -x "$WORK/fnpack" ]; then
  echo "  ✓ 复用已有"
else
  curl -fsSL --retry 3 \
    "https://static2.fnnas.com/fnpack/fnpack-1.0.4-linux-amd64" \
    -o "$WORK/fnpack"
  chmod +x "$WORK/fnpack"
  echo "  ✓ 已下载官方 fnpack"
fi

# ---------- 4. 打包 ----------
echo
echo "[4/5] 打包"
cd "$WORK"
export TMPDIR="$WORK/tmp"
mkdir -p "$TMPDIR"
"$WORK/fnpack" build --directory "$ROOT" >/dev/null
FPK="dnsrp_${VERSION}_all.fpk"
mv dnsrp.fpk "$FPK"
mv "$FPK" "$OUT/"
FPK="$OUT/$FPK"
echo "  ✓ 产物: $FPK ($(stat -c %s "$FPK") 字节)"

# ---------- 5. 校验 ----------
echo
echo "[5/5] 校验"
gzip -t "$FPK" && echo "  ✓ gzip"
echo "  manifest:"
tar xzOf "$FPK" manifest | grep -E '^(appname|version|display_name)' | sed 's/^/    /'
mkdir -p "$WORK/check"
# --warning=no-timestamp 抑制 WSL/Windows 时钟微差导致的"未来时间戳"告警
tar --warning=no-timestamp -xzf "$FPK" -C "$WORK/check" app.tgz
echo "  关键文件:"
tar --warning=no-timestamp -tzf "$WORK/check/app.tgz" \
  | grep -E 'dnrp/proxy/engine.py|www/index.html|config/privilege|certs/_aes.py' \
  | sed 's/^/    /'
echo "  SHA256: $(sha256sum "$FPK" | awk '{print $1}')"

echo
echo "=========================================="
echo " 构建完成: $FPK"
echo "=========================================="
