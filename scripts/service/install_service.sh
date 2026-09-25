#!/usr/bin/env bash
# 把 cosDnaProxy 安装成系统服务（自动识别 init 系统）
#
# 用法:
#   sudo bash scripts/service/install_service.sh              # 安装/更新单元并设为开机自启
#   sudo APP_DIR=/opt/dnsProxy SERVICE_NAME=dnsproxy bash scripts/service/install_service.sh
#
# 行为:
#   - 先备份已存在的同名单元文件
#   - 写入单元 -> daemon-reload -> enable（开机自启）
#   - 默认【不重启】正在运行的服务（生产 DNS 不主动断开），并在末尾给出立即生效的命令
#     需要立刻重启时加 RESTART=1
#
# 说明: 端口/上游/分流规则都在 ./data/config.db 里，本脚本不碰配置，只装服务定义。
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/dnsProxy}"
SERVICE_NAME="${SERVICE_NAME:-dnsproxy}"
BIN_NAME="${BIN_NAME:-dnsproxy}"
RESTART="${RESTART:-0}"

TEMPLATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT_SRC="$TEMPLATE_DIR/$BIN_NAME.service"

die()  { printf '  ✘ %s\n' "$*" >&2; exit 1; }
ok()   { printf '  ✔ %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
say()  { printf '%s\n' "$*"; }

# ---------- 前置检查 ----------
say "== 前置检查 =="
[ "$(id -u)" = "0" ] || die "需要 root 权限运行（请用 sudo）"
ok "以 root 运行"

if [ ! -f "$UNIT_SRC" ]; then
  die "找不到单元模板 $UNIT_SRC"
fi
ok "找到单元模板: $UNIT_SRC"

[ -d "$APP_DIR" ] || die "安装目录不存在: $APP_DIR（请先把二进制放好）"
if [ -x "$APP_DIR/$BIN_NAME" ]; then
  ok "二进制可执行: $APP_DIR/$BIN_NAME"
else
  say "  ⚠ 未找到可执行文件 $APP_DIR/$BIN_NAME —— 单元仍会安装，但启动会失败，请先上传二进制"
fi

# ---------- 识别 init 系统 ----------
detect_init() {
  # 容器里可能装了 systemctl 但 systemd 不是 PID 1，故以 /run/systemd/system 为准
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then echo systemd; return; fi
  if [ -f /etc/openwrt_release ]; then echo procd; return; fi
  if command -v rc-service >/dev/null 2>&1; then echo openrc; return; fi
  if [ -d /etc/init.d ]; then echo sysv; return; fi
  echo unknown
}

INIT="$(detect_init)"
say ""
say "== 识别 init 系统 =="
info "检测结果: $INIT"
info "安装目录: $APP_DIR"
info "服务名:   $SERVICE_NAME"
info "重启生效: $( [ "$RESTART" = "1" ] && echo 是 || echo '否（仅装单元）' )"

case "$INIT" in
  systemd) ;;
  openrc|procd|sysv)
    # 模板只需按同样方式补一个 <bin>.service 之外的 init 脚本，再加一个 install_<init>() 分支即可
    die "检测到 $INIT，但当前只提供了 systemd 模板；需要支持该 init 系统请补对应模板后再运行"
    ;;
  *)
    die "无法识别 init 系统；请手动安装 $UNIT_SRC 或告知我补对应模板"
    ;;
esac

UNIT_DST="/etc/systemd/system/$SERVICE_NAME.service"

# ---------- 安装单元 ----------
say ""
say "== 安装单元 =="
if [ -f "$UNIT_DST" ]; then
  BAK="$UNIT_DST.bak.$(date +%Y%m%d%H%M%S)"
  cp -a "$UNIT_DST" "$BAK"
  ok "已备份原单元: $BAK"
fi

# 模板里写的是默认路径/服务名，按入参替换（未改入参时等价于原样拷贝）
sed -e "s#/opt/dnsProxy#$APP_DIR#g" \
    -e "s#^SyslogIdentifier=.*#SyslogIdentifier=$SERVICE_NAME#" \
    "$UNIT_SRC" > "$UNIT_DST"
ok "已写入 $UNIT_DST"

systemctl daemon-reload
ok "systemctl daemon-reload"

systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
ok "已设为开机自启"

# ---------- 重启（可选）----------
say ""
say "== 应用方式 =="
if [ "$RESTART" = "1" ]; then
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    systemctl restart "$SERVICE_NAME"
    ok "已重启 $SERVICE_NAME"
  else
    systemctl start "$SERVICE_NAME"
    ok "已启动 $SERVICE_NAME"
  fi
else
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    info "服务当前在运行，旧单元继续有效到下次重启为止"
    info "立即生效请执行: systemctl restart $SERVICE_NAME"
  else
    info "服务未运行，启动请执行: systemctl start $SERVICE_NAME"
  fi
fi

# ---------- 状态确认 ----------
say ""
say "== 状态确认 =="
info "is-enabled: $(systemctl is-enabled "$SERVICE_NAME" 2>&1 || true)"
info "is-active:  $(systemctl is-active  "$SERVICE_NAME" 2>&1 || true)"
if systemctl is-active --quiet "$SERVICE_NAME"; then
  systemd-analyze verify "$UNIT_DST" >/dev/null 2>&1 && ok "单元语法校验通过" || info "systemd-analyze verify 有告警，可执行 systemd-analyze verify $UNIT_DST 查看"
  systemctl show -p MainPID -p NRestarts -p WorkingDirectory -p Restart "$SERVICE_NAME" | sed 's/^/    /'
  if command -v ss >/dev/null 2>&1; then
    info "监听端口:"
    ss -lntup 2>/dev/null | grep -E "pid=$(systemctl show -p MainPID --value "$SERVICE_NAME")" | sed 's/^/      /' || true
  fi
else
  info "服务未运行，单元已就位；启动后可用 systemctl status $SERVICE_NAME 查看"
fi