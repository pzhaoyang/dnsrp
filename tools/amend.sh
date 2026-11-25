set -u
cd /mnt/c/work/dsh-workspace/DNS-RP || exit 1

rm -f tools/deploy_toggle_fix.sh tools/verify_fix_toggle.sh 2>/dev/null

find . -name '__pycache__' -type d -print0 2>/dev/null | xargs -0 rm -rf 2>/dev/null
find . -name '*.pyc' -delete 2>/dev/null

echo "=== amend 修复到未推送的提交 ==="
git add -A
git commit -q --amend --no-edit 2>&1
echo "  已 amend"

echo
echo "=== 状态 ==="
git log --oneline -2 | sed 's/^/  /'
echo "  未推送: $(git rev-list --count '@{upstream}..HEAD' 2>/dev/null) 个"
[ -z "$(git status --short)" ] && echo "  工作区: ✓ 干净"

echo
echo "=== 确认修复在提交里 ==="
git show HEAD:app/www/index.html | grep -q "toggleRule(\${esc(r.id)}, \${r.enabled" \
  && echo "  ✓ 正确的模板字符串" || echo "  ? 检查"
git show HEAD:app/www/index.html | grep -q "toggleRule.*+ '" \
  && echo "  ✗ 仍有错误拼接" || echo "  ✓ 无错误拼接"
