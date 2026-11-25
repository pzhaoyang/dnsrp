set -u
cd /mnt/c/work/dsh-workspace/DNS-RP || exit 1

git add -A
git commit -q -m "chore: 版本 0.1.27（修复反代状态按钮渲染）" 2>&1
echo "  已提交"

echo
echo "=== 状态 ==="
git log --oneline -3 | sed 's/^/  /'
echo "  未推送: $(git rev-list --count '@{upstream}..HEAD' 2>/dev/null) 个"
