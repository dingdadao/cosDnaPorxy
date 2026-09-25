#!/bin/bash
# 在 10.0.0.30 上执行：备份/覆盖 dnsproxy 二进制 → 重启 → 验证
# 用法: bash deploy_remote.sh
# 不做哈希强校验：待部署文件的 sha256 只打印出来供人工核对。
# 若上传不完整导致起不来，末尾的自检会报失败，可用同目录的 dnsproxy.bak.<时间戳> 回滚。
set -u
DIR=/opt/dnsProxy
NEW="$DIR/dnsproxy.new"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); echo "  ✔ $1"; }
bad(){ FAIL=$((FAIL+1)); echo "  ✘ $1"; }
chk(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }
list_un(){ if command -v ss >/dev/null 2>&1; then ss -lun; else netstat -lun; fi; }
list_tn(){ if command -v ss >/dev/null 2>&1; then ss -ltn; else netstat -ltn; fi; }
# 从配置库读取字段值（无 sqlite3 CLI，用 python3 的 sqlite3 模块）
read_cfg(){ python3 - "$1" <<'PY' 2>/dev/null
import json, sqlite3, sys
try:
    conn = sqlite3.connect("data/config.db")
    row = conn.execute("SELECT value FROM settings WHERE key='config'").fetchone()
    cfg = json.loads(row[0]) if row else {}
    print(cfg.get(sys.argv[1], ""))
except Exception:
    pass
PY
}

cd "$DIR" || { echo "无法进入 $DIR"; exit 1; }

# 监听地址以配置库为准，避免与生产实际配置脱节
WEB_ADDR=$(read_cfg web_addr); [ -n "$WEB_ADDR" ] || WEB_ADDR=":5380"
LISTEN_PORT=$(read_cfg listen_port); [ -n "$LISTEN_PORT" ] || LISTEN_PORT=53
WEB_PORT=${WEB_ADDR##*:}
WEB_HOST=${WEB_ADDR%:*}
case "$WEB_HOST" in ""|"0.0.0.0"|"[::]"|"::") WEB_HOST=127.0.0.1;; esac
echo "== 配置库监听地址 =="
echo "    web_addr=$WEB_ADDR  listen_port=$LISTEN_PORT（探测 $WEB_HOST:$WEB_PORT）"

echo "== 校验上传文件 =="
if [ ! -f "$NEW" ]; then bad "缺少 $NEW（请先 scp 上传）"; exit 1; fi
ok "待部署文件: $NEW ($(wc -c <"$NEW") 字节)"
echo "    sha256: $(sha256sum "$NEW" | awk '{print $1}')"

BIN="$DIR/dnsproxy"
if [ ! -f "$BIN" ]; then
  BIN=$(systemctl show -p ExecStart --value dnsproxy | grep -o '/[^ ]*dnsproxy' | head -1)
fi
[ -n "$BIN" ] && [ -f "$BIN" ]; chk $? "定位现有二进制: $BIN"
[ -f "$BIN" ] || exit 1

echo "== 备份并覆盖 =="
echo "重启前 MainPID=$(systemctl show -p MainPID --value dnsproxy)"
STAMP=$(date +%Y%m%d%H%M%S)
cp -a "$BIN" "$BIN.bak.$STAMP"; chk $? "已备份 $BIN.bak.$STAMP"
install -m 755 "$NEW" "$BIN"; chk $? "覆盖 $BIN"
rm -f "$NEW"

echo "== 重启服务 =="
systemctl restart dnsproxy; chk $? "systemctl restart dnsproxy"
# 进程启动到绑定端口需约5s（要加载云IP库与分流列表），等待端口就绪再断言，避免误报
for _ in $(seq 1 20); do
  if list_un | grep -q ":$LISTEN_PORT "; then break; fi
  sleep 1
done
for _ in $(seq 1 20); do
  if list_tn | grep -q ":$WEB_PORT "; then break; fi
  sleep 1
done
systemctl is-active dnsproxy >/dev/null; chk $? "服务 is-active"
NEW_PID=$(systemctl show -p MainPID --value dnsproxy)
NR=$(systemctl show -p NRestarts --value dnsproxy)
echo "重启后 MainPID=$NEW_PID  NRestarts=$NR"
[ -n "$NEW_PID" ] && [ "$NEW_PID" != "0" ]; chk $? "MainPID 有效"

echo "== 端口与解析 =="
list_un | grep -q ":$LISTEN_PORT "; chk $? "$LISTEN_PORT UDP 监听"
list_tn | grep -q ":$LISTEN_PORT "; chk $? "$LISTEN_PORT TCP 监听"
list_tn | grep -q ":$WEB_PORT "; chk $? "$WEB_PORT TCP 监听"
dig +short +time=3 +tries=1 @127.0.0.1 -p "$LISTEN_PORT" www.baidu.com >/dev/null 2>&1; chk $? "dig @127.0.0.1 -p $LISTEN_PORT www.baidu.com"
HTTP=$(curl -s -o /dev/null -w '%{http_code}' "http://$WEB_HOST:$WEB_PORT/"); [ "$HTTP" = "200" ]; chk $? "$WEB_PORT 首页 HTTP $HTTP"

echo "== 解析日志（本次新增） =="
if ls "$DIR"/data/query_log.db >/dev/null 2>&1; then
  ok "日志库已生成: $(ls -l "$DIR"/data/query_log.db* | tr '\n' ' ')"
else
  bad "未生成 $DIR/data/query_log.db"
fi
LCODE=$(curl -s -o /dev/null -w '%{http_code}' "http://$WEB_HOST:$WEB_PORT/api/logs?limit=3"); [ "$LCODE" = "200" ]; chk $? "GET /api/logs HTTP $LCODE"
echo "--- /api/logs 样本 ---"
curl -s "http://$WEB_HOST:$WEB_PORT/api/logs?limit=3"
echo
echo "== 结果: $PASS 通过 / $FAIL 失败 =="