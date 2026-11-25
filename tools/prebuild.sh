#!/bin/bash
# 打包 DNS-RP 为 fnOS fpk

set -eu
W=/mnt/c/work/dsh-workspace/DNS-RP
OUT=/mnt/c/work/dsh-workspace

cd "$W"

echo "=== 1. 清理构建产物 ==="
rm -rf app/dnrp/__pycache__ app/dnrp/*/__pycache__ 2>/dev/null || true
find app -name '*.pyc' -delete 2>/dev/null || true
find app -name 'test_*.py' -delete 2>/dev/null || true
rm -rf _tmp 2>/dev/null || true

echo "=== 2. 检查必需文件 ==="
for f in manifest ICON.PNG ICON_256.PNG config/privilege app/ui/config \
         app/ui/index.cgi app/ui/images/icon_64.png app/ui/images/icon_256.png \
         app/www/index.html cmd/main cmd/start.sh cmd/common.sh; do
  if [ -f "$f" ]; then
    printf '  ✓ %s\n' "$f"
  else
    printf '  ✗ 缺失: %s\n' "$f"
    exit 1
  fi
done

echo
echo "=== 3. 语法检查 ==="
for f in cmd/*; do
  [ -f "$f" ] || continue
  bash -n "$f" || { echo "  语法错误: $f"; exit 1; }
done
echo "  cmd/ 全部通过"

for f in $(find app/dnrp -name '*.py'); do
  python3 -m py_compile "$f" 2>/dev/null || { echo "  语法错误: $f"; exit 1; }
done
find app -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
echo "  app/ 全部通过"

echo
echo "=== 4. 换行符检查 ==="
bad=0
for f in manifest config/privilege app/ui/config cmd/* app/ui/index.cgi; do
  [ -f "$f" ] || continue
  if grep -q $'\r' "$f" 2>/dev/null; then echo "  CRLF: $f"; bad=1; fi
done
for f in $(find app/dnrp -name '*.py'); do
  if grep -q $'\r' "$f" 2>/dev/null; then echo "  CRLF: $f"; bad=1; fi
done
[ "$bad" = "0" ] && echo "  全部 LF"

echo
echo "=== 5. 文件清单 ==="
find . -type f -not -path './scripts/*' -not -path './docs/*' \
  -not -path './.git/*' -not -name '*.pyc' | sort
