set -eu
R="$HOME/.dnrp-bin/rssh.sh"
FPK=/mnt/c/work/dsh-workspace/RP/fn_fpk_packages/DNS-RP.fpk

echo "=== 1. 上传 fpk 到 imedia ==="
cat "$FPK" | "$R" "cat > /tmp/DNS-RP.fpk"
echo "上传完成"

echo
echo "=== 2. 校验 md5 ==="
local_md5=$(md5sum "$FPK" | awk '{print $1}')
remote_md5=$("$R" "md5sum /tmp/DNS-RP.fpk" | awk '{print $1}')
echo "  本地: $local_md5"
echo "  远端: $remote_md5"
if [ "$local_md5" = "$remote_md5" ]; then
  echo "  ✓ 一致"
else
  echo "  ✗ 不一致"
  exit 1
fi

echo
echo "=== 3. 远端文件 ==="
"$R" "ls -la /tmp/DNS-RP.fpk"
