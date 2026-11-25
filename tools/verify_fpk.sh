set -u
FPK=/mnt/c/work/dsh-workspace/RP/fn_fpk_packages/dnsrp.fpk

echo "=== 产物 ==="
ls -la "$FPK"
echo "  大小: $(du -h "$FPK" | cut -f1)"
echo "  SHA256: $(sha256sum "$FPK" | awk '{print $1}')"

echo
echo "=== 内容清单 ==="
tar tzf "$FPK" | sort | sed 's/^/  /'

echo
echo "=== 包内 app.tgz 里的 Python 文件 ==="
mkdir -p /tmp/fpkchk
tar xzf "$FPK" -C /tmp/fpkchk app.tgz 2>/dev/null
tar tzf /tmp/fpkchk/app.tgz 2>/dev/null | grep '\.py$' | sort | sed 's/^/  /'
echo "  --- 统计 ---"
echo "  py 文件数: $(tar tzf /tmp/fpkchk/app.tgz 2>/dev/null | grep -c '\.py$')"

echo
echo "=== 关键内容校验 ==="
tar xzf /tmp/fpkchk/app.tgz -C /tmp/fpkchk 2>/dev/null
for pair in \
  "config/privilege:run-as\"\?:\? *\"\?package" \
  "dnrp/capabilities.py:def probe" \
  "dnrp/auth.py:def from_cgi_env" \
  "ui/config:\"type\": \"url\"" ; do
  f="${pair%%:*}"; pat="${pair#*:}"
  if [ -f "/tmp/fpkchk/$f" ]; then
    if grep -qE "$pat" "/tmp/fpkchk/$f" 2>/dev/null; then
      echo "  ✓ $f 含关键内容"
    else
      echo "  ✗ $f 关键内容缺失"
    fi
  else
    echo "  ✗ $f 不存在"
  fi
done

echo
echo "=== config/privilege 内容 ==="
cat /tmp/fpkchk/config/privilege 2>/dev/null | sed 's/^/  /'

echo
echo "=== ui/config ==="
cat /tmp/fpkchk/ui/config 2>/dev/null | sed 's/^/  /'

echo
echo "=== manifest ==="
head -5 /tmp/fpkchk/manifest 2>/dev/null | sed 's/^/  /'

rm -rf /tmp/fpkchk /tmp/dnrp-sync.tgz
