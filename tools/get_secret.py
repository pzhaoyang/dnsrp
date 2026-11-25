"""读取 fnOS 的 WebSocket 会话密钥（调试用）。

★ 用途：
  手动调用 fnOS 的 appcgi 接口做排查时，需要会话密钥做 HMAC 签名。
  本脚本用账号密码登录一次，把 secret 以 base64 输出到 stdout。

★ 注意：
  1. 该 secret 与建立它的 WebSocket 连接绑定，**不能跨进程复用**
     （拿到别的进程用会报 errno=65534 验签失败）。
  2. 本脚本只用于单进程内自测，实际应用请让 ws_client 自己登录。

★ 凭据从环境变量读取：
    export DNRP_HOST=127.0.0.1
    export DNRP_USER=your-user
    export DNRP_PASS=your-password
"""

import base64
import os
import sys

# 假定应用已安装在默认位置；也可通过 PYTHONPATH 指定
sys.path.insert(0, os.environ.get("DNRP_APP", "/vol1/@appcenter/DNS-RP"))

from dnrp.certs.ws_client import FnosClient   # noqa: E402


def main() -> int:
    host = os.environ.get("DNRP_HOST", "127.0.0.1")
    port = int(os.environ.get("DNRP_WS_PORT", "16667"))
    user = os.environ.get("DNRP_USER", "")
    password = os.environ.get("DNRP_PASS", "")

    if not user or not password:
        print("请设置 DNRP_USER 和 DNRP_PASS 环境变量", file=sys.stderr)
        return 1

    cli = FnosClient(host=host, port=port,
                     username=user, password=password)
    cli.connect()
    try:
        if not cli.secret:
            print("登录成功但没有拿到 secret", file=sys.stderr)
            return 1
        sys.stdout.write(base64.b64encode(cli.secret).decode())
        return 0
    finally:
        cli.close()


if __name__ == "__main__":
    raise SystemExit(main())
