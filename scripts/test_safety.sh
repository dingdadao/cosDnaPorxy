#!/usr/bin/env bash
# 安全/稳定性测试（针对运行中的实例，非破坏性）：
#   1) 协议守卫: FORMERR/NOTIMP
#   2) 畸形报文防护: 空包/截断/超长label/超长域名/压缩指针炸弹/垃圾包/TCP半包 → 发后服务必须存活
#   3) 域名篡改最高优先级: 临时规则用RFC2606保留域example.com（绝不污染真实解析），测完即删
#   4) 并发安全: 200次合法域名查询/16并发，要求100% NOERROR
#   5) 内存泄漏: 压测前后RSS对比（上限 MEM_LIMIT_MB）
# 仅使用合法域名与畸形报文，不解析任何违法/不良域名
# 用法: bash scripts/test_safety.sh   （默认 127.0.0.1:53 / :5380，可用 DNS_PORT/WEB_PORT 覆盖）
set -u

DNS_PORT="${DNS_PORT:-53}"
WEB_PORT="${WEB_PORT:-5380}"
API="http://127.0.0.1:$WEB_PORT"
PROBE="www.qq.com"                  # 存活探针（合法域名，走缓存快）
OV_DOMAIN="safety-test.example.com" # 篡改测试目标（RFC2606保留域）
MEM_LIMIT_MB=30                     # 压测期间RSS增长上限(MB)
PASS=0; FAIL=0; OV_ID=""

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✔ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✘ $1"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

cleanup() { [ -n "$OV_ID" ] && curl -s -o /dev/null -X DELETE "$API/api/overrides/$OV_ID"; }
trap cleanup EXIT

dns_pid() { lsof -iTCP:"$DNS_PORT" -sTCP:LISTEN -P -n 2>/dev/null | awk 'NR>1{print $2; exit}'; }

rss_mb() { # 进程RSS(MB)，macOS top（ps 对该进程读不到内存值）
  top -l 1 -pid "$1" -stats pid,mem 2>/dev/null | awk -v pid="$1" '
    $1==pid { v=substr($2,1,length($2)-1)+0; u=substr($2,length($2));
      if (u=="G") v*=1024; else if (u=="K") v/=1024; printf "%.0f", v }'
}

alive() { dig @127.0.0.1 -p "$DNS_PORT" +time=2 +tries=1 "$PROBE" A 2>/dev/null | grep -q 'status: NOERROR'; }

# 原始UDP包取rcode（协议守卫）
rawq() { python3 -c "
import socket, sys
flags, qdcount = int(sys.argv[1]), int(sys.argv[2])
q = b'\x03www\x02qq\x03com\x00' + b'\x00\x01\x00\x01'
pkt = b'\x12\x34' + flags.to_bytes(2,'big') + qdcount.to_bytes(2,'big') + b'\x00\x00\x00\x00\x00\x00'
if qdcount: pkt += q * qdcount
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.sendto(pkt, ('127.0.0.1', $DNS_PORT))
resp, _ = s.recvfrom(512)
print(resp[3] & 0x0F if resp[:2] == b'\x12\x34' else -1)
" "$1" "$2" 2>/dev/null; }

# 畸形报文（不求响应，判据=发后服务存活）
mangle() { python3 -c "
import os, socket, sys
port, kind = int(sys.argv[1]), sys.argv[2]
hdr = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
qtail = b'\x00\x01\x00\x01'
if kind == 'tcp_trunc':  # TCP声明65535字节只发半包
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1)
    s.connect(('127.0.0.1', port)); s.sendall(b'\xff\xff\x12\x34\x01\x00')
else:
    pkt = {
        'empty':       b'',
        'trunc':       b'\x12\x34',
        'long_label':  hdr + b'\x64' + b'a'*100 + b'\x00' + qtail,          # label超63字节
        'long_name':   hdr + b''.join(b'\x3f' + b'b'*63 for _ in range(5)) + b'\x00' + qtail,  # QNAME>255
        'ptr_loop':    hdr + b'\xc0\x0c' + qtail,                           # 压缩指针自指(解析炸弹)
        'garbage':     os.urandom(512),
    }[kind]
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
    try:
        s.sendto(pkt, ('127.0.0.1', port)); s.recvfrom(512)
    except Exception:
        pass
" "$DNS_PORT" "$1" 2>/dev/null; }

say "== 0. 基线 =="
PID=$(dns_pid)
[ -n "$PID" ]; check $? "DNS服务在端口 $DNS_PORT 监听"
alive; check $? "探针 $PROBE → NOERROR"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/config")" = "200" ]; check $? "Web管理API 200"
if [ -z "$PID" ]; then say "服务未运行，终止测试"; exit 1; fi
RSS_BEFORE=$(rss_mb "$PID")
[ -n "$RSS_BEFORE" ]; check $? "RSS采样可用（基线 ${RSS_BEFORE:-读取失败}MB，PID ${PID}）"

say "== 1. 协议守卫 =="
[ "$(rawq 256 0)" = "1" ]; check $? "QDCOUNT=0 → FORMERR(1)"
[ "$(rawq 256 2)" = "1" ]; check $? "QDCOUNT=2 → FORMERR(1)"
[ "$(rawq 2304 1)" = "4" ]; check $? "Opcode=STATUS → NOTIMP(4)"

say "== 2. 畸形报文防护（判据：发后服务存活） =="
for c in empty trunc long_label long_name ptr_loop garbage tcp_trunc; do
  mangle "$c"
  alive; check $? "畸形包[$c] 后服务存活"
done

say "== 3. 域名篡改最高优先级（RFC2606保留域，测完即删） =="
curl -s -o /dev/null -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d "{\"domain\":\"$OV_DOMAIN\",\"qtype\":\"A\",\"value\":\"127.0.0.1\",\"ttl\":60,\"enabled\":true}"
OV_ID=$(curl -s "$API/api/overrides" | python3 -c "
import json, sys
for o in json.load(sys.stdin).get('overrides', []):
    if o['domain'] == '$OV_DOMAIN':
        print(o['id']); break
" 2>/dev/null)
[ -n "$OV_ID" ]; check $? "临时篡改规则创建(id=${OV_ID:-未找到})"
[ "$(dig +short @127.0.0.1 -p "$DNS_PORT" +time=2 +tries=1 "$OV_DOMAIN" A)" = "127.0.0.1" ]; check $? "篡改优先于缓存/上游 → 127.0.0.1"
if [ -n "$OV_ID" ]; then
  curl -s -o /dev/null -X DELETE "$API/api/overrides/$OV_ID"; OV_ID=""
fi
[ "$(dig +short @127.0.0.1 -p "$DNS_PORT" +time=2 +tries=1 "$OV_DOMAIN" A)" != "127.0.0.1" ]; check $? "规则删除后篡改失效"
alive; check $? "篡改测试后服务存活"

say "== 4. 并发安全（200次/16并发，合法域名） =="
QLIST=()
for _ in $(seq 1 50); do QLIST+=(www.qq.com github.com www.taobao.com www.bilibili.com); done
LOAD_OUT=$(printf '%s\n' "${QLIST[@]}" | xargs -P 16 -I{} sh -c \
  "dig @127.0.0.1 -p $DNS_PORT +time=3 +tries=1 \"\$1\" A 2>/dev/null | grep -q 'status: NOERROR' && echo OK || echo FAIL" _ {})
OK_N=$(printf '%s' "$LOAD_OUT" | grep -c '^OK')
[ "$OK_N" = "200" ]; check $? "并发压测 200/200 NOERROR（实际 $OK_N/200）"

say "== 5. 内存泄漏检查 =="
RSS_AFTER=$(rss_mb "$PID")
if [ -n "$RSS_BEFORE" ] && [ -n "$RSS_AFTER" ]; then
  DELTA=$((RSS_AFTER - RSS_BEFORE))
  say "  压测后RSS: ${RSS_AFTER}MB（增长 ${DELTA}MB，上限 ${MEM_LIMIT_MB}MB）"
  [ "$DELTA" -lt "$MEM_LIMIT_MB" ]; check $? "RSS增长 ${DELTA}MB < ${MEM_LIMIT_MB}MB"
else
  bad "RSS采样失败（before='$RSS_BEFORE' after='$RSS_AFTER'），无法判定泄漏"
fi
alive; check $? "压测后服务存活"
[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/config")" = "200" ]; check $? "Web管理API仍200"

say ""
say "结果: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" = "0" ]; then say "✅ 安全检查全部通过"; else say "❌ 存在 $FAIL 项未通过"; fi
[ "$FAIL" = "0" ]
