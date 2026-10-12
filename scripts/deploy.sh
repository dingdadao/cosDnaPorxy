#!/bin/bash
# 本地一键部署 dnsproxy 到远端服务器
# 流程：交叉编译 Linux 二进制 → 上传二进制与远端脚本 → 远端执行 deploy_remote.sh（备份/覆盖/重启/自检）
#
# 用法：
#   bash scripts/deploy.sh                      # 默认用密钥 ~/.ssh/proxydns 免密部署
#   DEPLOY_PASS='<ssh密码>' bash scripts/deploy.sh   # 无密钥时回退密码认证
#
# 可选环境变量：
#   DEPLOY_HOST  目标主机（默认 10.0.0.30）
#   DEPLOY_USER  登录用户（默认 root）
#   DEPLOY_PORT  SSH 端口（默认 22）
#   DEPLOY_DIR   远端部署目录（默认 /opt/dnsProxy）
#   DEPLOY_KEY   私钥路径（默认 ~/.ssh/proxydns）
#
# 认证优先级：密钥 → sshpass（密码）→ expect（密码回退）。
# 密码只经环境变量传入，不写入仓库，避免凭据入库。
set -euo pipefail

HOST=${DEPLOY_HOST:-10.0.0.30}
REMOTE_USER=${DEPLOY_USER:-root}
PORT=${DEPLOY_PORT:-22}
DIR=${DEPLOY_DIR:-/opt/dnsProxy}
KEY=${DEPLOY_KEY:-$HOME/.ssh/proxydns}
PASS=${DEPLOY_PASS:-}
TARGET="${REMOTE_USER}@${HOST}"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN_LOCAL="$ROOT/build/dnsproxy-linux-amd64"
REMOTE_SCRIPT="$ROOT/scripts/deploy_remote.sh"
[ -f "$REMOTE_SCRIPT" ] || { echo "错误：缺少 $REMOTE_SCRIPT"; exit 1; }

SSH_BASE=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15)

# ---- 认证执行器：密钥优先，其次 sshpass，最后 expect ----
if [ -f "$KEY" ]; then
  AUTH=(-i "$KEY" -o BatchMode=yes -o PreferredAuthentications=publickey)
  scp_put() { scp "${SSH_BASE[@]}" "${AUTH[@]}" -P "$PORT" "$1" "$2"; }
  ssh_run() { ssh "${SSH_BASE[@]}" "${AUTH[@]}" -p "$PORT" "$TARGET" "$1"; }
elif [ -n "$PASS" ] && command -v sshpass >/dev/null 2>&1; then
  scp_put() { sshpass -p "$PASS" scp "${SSH_BASE[@]}" -P "$PORT" "$1" "$2"; }
  ssh_run() { sshpass -p "$PASS" ssh "${SSH_BASE[@]}" -p "$PORT" "$TARGET" "$1"; }
elif [ -n "$PASS" ] && command -v expect >/dev/null 2>&1; then
  export DEPLOY_PASS="$PASS" DEPLOY_TARGET="$TARGET" DEPLOY_SSH_PORT="$PORT"
  scp_put() {
    SRC="$1" DST="$2" expect <<'EOF'
set timeout 900
spawn scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -P $env(DEPLOY_SSH_PORT) $env(SRC) $env(DST)
expect { -re "(?i)password" { send -- "$env(DEPLOY_PASS)\r"; exp_continue } eof }
catch wait r; exit [lindex $r 3]
EOF
  }
  ssh_run() {
    REMOTE_CMD="$1" expect <<'EOF'
set timeout 900
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $env(DEPLOY_SSH_PORT) $env(DEPLOY_TARGET) $env(REMOTE_CMD)
expect { -re "(?i)password" { send -- "$env(DEPLOY_PASS)\r"; exp_continue } eof }
catch wait r; exit [lindex $r 3]
EOF
  }
else
  echo "错误：$KEY 不存在，且未提供可用密码认证（DEPLOY_PASS）"; exit 1
fi

echo "== 1/4 交叉编译 Linux/amd64 =="
( cd "$ROOT" && GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.Version=${VERSION:-1.0.0} -X main.BuildTime=$(date +%FT%T%z)" \
    -o "$BIN_LOCAL" main.go )
echo "   产物: $BIN_LOCAL ($(wc -c <"$BIN_LOCAL") 字节)"
echo "   sha256: $(shasum -a 256 "$BIN_LOCAL" | awk '{print $1}')"

echo "== 2/4 上传到 $TARGET:$DIR =="
ssh_run "cd $DIR && [ -f deploy_remote.sh ] && cp -a deploy_remote.sh deploy_remote.sh.bak.\$(date +%Y%m%d%H%M%S) || true"
scp_put "$BIN_LOCAL" "$TARGET:$DIR/dnsproxy.new"
scp_put "$REMOTE_SCRIPT" "$TARGET:$DIR/deploy_remote.sh"

echo "== 3/4 远端备份/覆盖/重启/自检 =="
ssh_run "cd $DIR && bash deploy_remote.sh"

echo "== 4/4 回滚提示 =="
ssh_run "ls -1t $DIR/dnsproxy.bak.* 2>/dev/null | head -1 | sed 's/^/最近备份: /'" || true
echo "回滚命令：ssh -i $KEY $TARGET 'cp -a <备份文件> $DIR/dnsproxy && systemctl restart dnsproxy'"