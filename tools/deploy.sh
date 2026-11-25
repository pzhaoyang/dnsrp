set -eu
R="$HOME/.dnrp-bin/rssh.sh"
W=/mnt/c/work/dsh-workspace/DNS-RP
D=/tmp/dnrp-full

echo "=== 1. 重建目录 ==="
"$R" "rm -rf $D && mkdir -p $D/app/dnrp/api $D/app/dnrp/proxy $D/app/dnrp/certs $D/app/dnrp/ddns $D/www $D/ui $D/var && echo ok"

echo "=== 2. 打包上传整个 app/dnrp ==="
cd "$W"
tar czf /tmp/dnrp-src.tgz --exclude='__pycache__' --exclude='*.pyc' --exclude='test_*.py' app/dnrp
cat /tmp/dnrp-src.tgz | "$R" "cat > /tmp/src.tgz"
"$R" "cd $D && tar xzf /tmp/src.tgz && rm -f /tmp/src.tgz && echo extracted"

echo "=== 3. 上传静态资源 ==="
cat "$W/app/www/index.html" | "$R" "cat > $D/www/index.html"
cat "$W/app/ui/index.cgi"   | "$R" "cat > $D/ui/index.cgi"
cat "$W/app/ui/config"      | "$R" "cat > $D/ui/config"

echo "=== 4. 结构 ==="
"$R" "cd $D && find app -name '*.py' | sort && echo '--- www/ui ---' && ls www ui"
