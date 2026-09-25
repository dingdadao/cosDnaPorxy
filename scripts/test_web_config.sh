#!/usr/bin/env bash
# 端到端测试：Web配置(SQLite) + 本地域名篡改 + 热更新 + 信号处理
# 用法: bash scripts/test_web_config.sh
# 说明: 在临时目录运行服务并预播种测试端口配置，不污染项目 data/config.db
#       DNS端口15354，Web端口15380（可用 DNS_PORT/WEB_PORT 覆盖）
set -u

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DNS_PORT="${DNS_PORT:-15354}"
WEB_PORT="${WEB_PORT:-15380}"
WORK_DIR="$(mktemp -d /tmp/cosdns-test.XXXXXX)"
BIN="$WORK_DIR/cosdns-test"
LOG="$WORK_DIR/run.log"
PASS=0; FAIL=0; PID=""

cleanup() {
  [ "${KEEP:-0}" = "1" ] && { say "保留测试现场: $WORK_DIR"; return; }
  [ -n "$PID" ] && kill -TERM "$PID" 2>/dev/null
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT

say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); say "  ✔ $1"; }
bad()  { FAIL=$((FAIL+1)); say "  ✘ $1"; }
check(){ if [ "$1" = "0" ]; then ok "$2"; else bad "$2"; fi; }

API="http://127.0.0.1:$WEB_PORT"

wait_web() {
  for _ in $(seq 1 40); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$API/api/config")" = "200" ] && return 0
    sleep 0.3
  done
  return 1
}

api_cfg()  { curl -s "$API/api/config"; }
api_put()  { curl -s -w '\n%{http_code}' -X PUT "$API/api/config" -H 'Content-Type: application/json' -d "$1"; }
api_get()  { curl -s "$@"; }                                # 纯JSON响应
api_req()  { curl -s -o /dev/null -w '%{http_code}' "$@"; } # 只要状态码
digq()     { dig +short +time=2 +tries=1 "$@" @127.0.0.1 -p "$DNS_PORT"; }
jqpy()     { python3 -c "import json,sys; $1"; }

# 定位 Go ≥1.23（PATH优先，回退goenv与常见安装路径）
find_go() {
  local v candidates=""
  if command -v go >/dev/null 2>&1; then
    v=$(go version 2>/dev/null | sed -E 's/.*go([0-9.]+).*/\1/')
    [ "$(printf '%s\n1.23\n' "$v" | sort -V | tail -1)" = "$v" ] && { command -v go; return; }
  fi
  for v in "$HOME"/.goenv/versions/*/bin/go /usr/local/go/bin/go /opt/homebrew/bin/go; do
    [ -x "$v" ] && candidates="$candidates$v
"
  done
  [ -z "$candidates" ] && return 1
  # 取版本最高的一个
  printf '%s' "$candidates" | while read -r g; do
    [ -n "$g" ] && echo "$( "$g" version | sed -E 's/.*go([0-9.]+).*/\1/')	$g"
  done | sort -V | tail -1 | cut -f2
}

say "== 构建与启动 =="
GO_BIN=$(find_go) || { say "未找到Go ≥1.23"; exit 1; }
say "使用Go: $GO_BIN"
export TMPDIR="$WORK_DIR" # go build临时目录收进测试目录，避免权限问题
(cd "$PROJECT_DIR" && "$GO_BIN" build -o "$BIN" .) || { say "构建失败"; exit 1; }

# 预播种配置库：服务从SQLite读取端口，需与测试端口一致；其余时长字段留空自动回退默认值
mkdir -p "$WORK_DIR/data"
python3 - "$WORK_DIR/data/config.db" "$DNS_PORT" "$WEB_PORT" <<'EOF'
import json, sqlite3, sys
db, dns_port, web_port = sys.argv[1], int(sys.argv[2]), sys.argv[3]
cfg = {"listen_port": dns_port, "web_addr": ":" + web_port,
       "upstream": ["udp://223.5.5.5:53", "https://223.5.5.5/dns-query"],
       # 旧版两组硬编码分流字段（无 URL，避免测试期真实下载）：验证启动时迁移为 split_lists
       "default_dns": "udp://223.6.6.6:53", "designated_domain": "./data/designated.yaml",
       "designated_refresh": "30m",
       "china_dns": "udp://223.5.5.5:53", "china_domain_file": "./data/china_domains.yaml",
       "china_domain_refresh": "24h", "enable_china_domain_check": True}
con = sqlite3.connect(db)
con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
con.execute("INSERT INTO settings(key, value) VALUES('config', ?)", (json.dumps(cfg),))
con.commit()
EOF

cd "$WORK_DIR"
"$BIN" >"$LOG" 2>&1 & PID=$!
if ! wait_web; then
  bad "服务未在${WEB_PORT}端口就绪，run.log:"
  cat "$LOG"
  exit 1
fi
ok "服务启动并监听Web端口$WEB_PORT"

say "== 配置 API =="
api_cfg | jqpy "c=json.load(sys.stdin)['config']; sys.exit(0 if c['listen_port']==$DNS_PORT else 1)"
check $? "GET /api/config 返回预播种配置(port=$DNS_PORT)"

# 热字段: replace_cache_time → restart_required=false（勿改log_level，否则后续Info日志被过滤）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['replace_cache_time']='45m'; print(json.dumps(c))")
resp=$(api_put "$req"); code=$(echo "$resp" | tail -1)
echo "$resp" | head -1 | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "热字段(replace_cache_time)保存 → ok 且 restart_required=false (http=$code)"

# 重启字段: listen_port 变更 → restart_required=true（改后马上改回，避免占用测试端口）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['listen_port']=$DNS_PORT+1; print(json.dumps(c))")
resp=$(api_put "$req")
echo "$resp" | head -1 | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is True else 1)"
check $? "重启字段(listen_port)变更 → restart_required=true"
req=$(echo "$cur" | jqpy "print(json.dumps(json.load(sys.stdin)['config']))")
api_put "$req" >/dev/null

# 校验: 空上游 400
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['upstream']=[]; print(json.dumps(c))")
code=$(api_put "$req" | tail -1)
[ "$code" = "400" ]; check $? "空upstream被拒绝 (http=$code, 期望400)"

# 篡改规则端口未被误存（仍为测试端口，下次重启可用）
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['listen_port'])")" = "$DNS_PORT" ]
check $? "配置修改持久化到SQLite"

say "== 域名分流列表 =="
# 旧版两组硬编码字段应迁移为 split_lists（顺序＝匹配优先级）
cur=$(api_cfg)
echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; L=c.get('split_lists')
sys.exit(0 if isinstance(L,list) and len(L)==2
  and L[0]['name']=='定向域名' and L[0]['dns']==['udp://223.6.6.6:53'] and L[0]['refresh']=='30m0s' and L[0]['enabled']
  and L[0]['enable_cloud_check'] is False
  and L[1]['name']=='中国域名' and L[1]['dns']==['udp://223.5.5.5:53'] and L[1]['refresh']=='24h0m0s' and L[1]['enabled']
  and L[1]['enable_cloud_check'] is False else 1)"
check $? "旧版分流字段启动时自动迁移为2条 split_lists(dns 统一为数组)"

# 仅改 DNS → 热更新（多值数组，按顺序失败切换）
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['dns']=['udp://9.9.9.9:53','https://1.1.1.1/dns-query']; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表改为多DNS数组 → 热更新(restart_required=false)"
api_cfg | jqpy "sys.exit(0 if json.load(sys.stdin)['config']['split_lists'][0]['dns']==['udp://9.9.9.9:53','https://1.1.1.1/dns-query'] else 1)"
check $? "多DNS数组已落库"

# 旧写法（单个字符串）仍被接受，落库统一为数组
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['dns']='udp://9.9.9.9:53'; print(json.dumps(c))")
api_put "$req" >/dev/null
api_cfg | jqpy "sys.exit(0 if json.load(sys.stdin)['config']['split_lists'][0]['dns']==['udp://9.9.9.9:53'] else 1)"
check $? "旧写法 dns 单字符串 → 落库归一化为数组"

# 每条列表的「仍做云检测」开关 → 热更新
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][1]['enable_cloud_check']=True; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表开关「仍做云检测」变更 → 热更新(restart_required=false)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['split_lists'][1]['enable_cloud_check'])")" = "True" ]
check $? "开关值已落库(enable_cloud_check=True)"

# 每条列表的 ECS（EDNS Client Subnet）策略 → 热更新（变更后应清空缓存避免新旧策略串味）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['ecs']={'enabled':True,'isp_type':'telecom','subnet':'1.2.3.0/24'}; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表 ECS 策略变更 → 热更新(restart_required=false)"
api_cfg | jqpy "e=json.load(sys.stdin)['config']['split_lists'][0]['ecs']; sys.exit(0 if e=={'enabled':True,'isp_type':'telecom','subnet':'1.2.3.0/24'} else 1)"
check $? "ECS 策略已落库(telecom/1.2.3.0/24)"

# 路由变更后必须清空缓存（日志有落盘缓冲，轮询等待）
found=1
for _ in $(seq 1 10); do
  if grep -aq "SPLIT_ROUTING_CHANGED_CACHE_CLEARED" "$LOG" 2>/dev/null || grep -rq "SPLIT_ROUTING_CHANGED_CACHE_CLEARED" "$WORK_DIR/logs" 2>/dev/null; then
    found=0; break
  fi
  sleep 0.3
done
check $found "ECS 策略变更触发缓存清空日志"

# 关闭 ECS（不传）→ 热更新且不注入
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['ecs']['enabled']=False; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "ECS 关闭 → 热更新(restart_required=false)"
api_cfg | jqpy "e=json.load(sys.stdin)['config']['split_lists'][0]['ecs']; sys.exit(0 if e['enabled'] is False and e['isp_type']=='telecom' and e['subnet']=='1.2.3.0/24' else 1)"
check $? "ECS 关闭后仍保留线路类型与网段(不注入)"

# A/AAAA 偏好档位：列表级 → 热更新并落库（变更后应清缓存，避免新旧档位串味）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['ip_prefer']='only_a'; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表 A/AAAA 偏好档位变更 → 热更新(restart_required=false)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['split_lists'][0]['ip_prefer'])")" = "only_a" ]
check $? "列表档位已落库(only_a)"

# A/AAAA 偏好档位：全局默认 → 热更新并落库
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['ip_prefer']='prefer_a'; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "全局默认偏好档位变更 → 热更新(restart_required=false)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['ip_prefer'])")" = "prefer_a" ]
check $? "全局档位已落库(prefer_a)"

# 档位变更属于路由变更 → 必须清缓存（日志有落盘缓冲，轮询等待）
found=1
for _ in $(seq 1 10); do
  if grep -aq "SPLIT_ROUTING_CHANGED_CACHE_CLEARED" "$LOG" 2>/dev/null || grep -rq "SPLIT_ROUTING_CHANGED_CACHE_CLEARED" "$WORK_DIR/logs" 2>/dev/null; then
    found=0; break
  fi
  sleep 0.3
done
check $found "偏好档位变更触发缓存清空日志"

# 非法档位 → 400（ToConfig 边界校验，配置不落库）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['ip_prefer']='prefer_ipv4'; print(json.dumps(c))")
code=$(api_put "$req" | tail -1)
[ "$code" = "400" ]; check $? "非法列表档位被拒绝 (http=$code, 期望400)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['split_lists'][0]['ip_prefer'])")" = "only_a" ]
check $? "被拒绝的档位未落库(仍为only_a)"

cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['ip_prefer']='only_aaaa'; print(json.dumps(c))")
code=$(api_put "$req" | tail -1)
[ "$code" = "400" ]; check $? "非法全局档位被拒绝 (http=$code, 期望400)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['ip_prefer'])")" = "prefer_a" ]
check $? "被拒绝的全局档位未落库(仍为prefer_a)"

# 复位为「不干预」，避免影响后续解析断言
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['ip_prefer']=''; c['split_lists'][0]['ip_prefer']=''; print(json.dumps(c))")
api_put "$req" >/dev/null
api_cfg | jqpy "c=json.load(sys.stdin)['config']; sys.exit(0 if c['ip_prefer']=='' and c['split_lists'][0]['ip_prefer']=='' else 1)"
check $? "偏好档位已复位为不干预"

# 分流列表「取反」开关 → 热更新
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['invert']=True; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表「取反」开启 → 热更新(restart_required=false)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['split_lists'][0]['invert'])")" = "True" ]
check $? "取反开关已落库"

# 排序：调换两条分流列表顺序 → 热更新（不因顺序变化误判为需重启）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'].reverse(); print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is False else 1)"
check $? "分流列表调换顺序 → 热更新(restart_required=false)"
api_cfg | jqpy "L=json.load(sys.stdin)['config']['split_lists']; sys.exit(0 if L[0]['name']=='中国域名' and L[1]['name']=='定向域名' else 1)"
check $? "新顺序已落库(中国域名在前)"

# 顺序变更需重建匹配器，避免「A 的规则配 B 的 DNS」错配（日志有落盘缓冲，轮询等待）
found=1
for _ in $(seq 1 10); do
  if grep -aq "SPLIT_LIST_REORDERED" "$LOG" 2>/dev/null || grep -rq "SPLIT_LIST_REORDERED" "$WORK_DIR/logs" 2>/dev/null; then
    found=0; break
  fi
  sleep 0.3
done
check $found "顺序变更触发匹配器重建日志"

# 调回原顺序，避免影响后续按下标断言的用例
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'].reverse(); c['split_lists'][0]['invert']=False; print(json.dumps(c))")
api_put "$req" >/dev/null
api_cfg | jqpy "L=json.load(sys.stdin)['config']['split_lists']; sys.exit(0 if L[0]['name']=='定向域名' and L[0]['invert'] is False else 1)"
check $? "顺序与取反已复位"

# 刷新间隔变更 → 需重启
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][1]['refresh']='12h'; print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is True else 1)"
check $? "分流列表刷新间隔变更 → 需重启(restart_required=true)"

# 新增列表 → 需重启
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'].append({'name':'自定义分流','enabled':True,'dns':['udp://1.1.1.1:53'],'domain_file':'./data/custom.yaml','domain_url':'','refresh':'1h'}); print(json.dumps(c))")
echo "$(api_put "$req" | head -1)" | jqpy "r=json.load(sys.stdin); sys.exit(0 if r.get('ok') and r.get('restart_required') is True else 1)"
check $? "新增分流列表 → 需重启(restart_required=true)"

# 非法刷新间隔 → 400（服务端解析失败，配置不落库）
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists'][0]['refresh']='abc'; print(json.dumps(c))")
code=$(api_put "$req" | tail -1)
[ "$code" = "400" ]; check $? "非法刷新间隔被拒绝 (http=$code, 期望400)"
[ "$(api_cfg | jqpy "print(json.load(sys.stdin)['config']['split_lists'][0]['refresh'])")" = "30m0s" ]
check $? "被拒绝的配置未落库(刷新间隔仍为30m0s)"

# 恢复为2条，避免新增列表影响后续解析断言
cur=$(api_cfg)
req=$(echo "$cur" | jqpy "c=json.load(sys.stdin)['config']; c['split_lists']=c['split_lists'][:2]; print(json.dumps(c))")
api_put "$req" >/dev/null

say "== 篡改规则 API =="
code=$(api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"test.example.com","qtype":"A","value":"1.2.3.4","ttl":60,"enabled":true}')
[ "$code" = "200" ]; check $? "新增A规则 (http=$code)"

api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":".ad.com","qtype":"AAAA","value":"2001:db8::1","ttl":120,"enabled":true}' >/dev/null
api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"go.example.org","qtype":"CNAME","value":"real.target.com","ttl":300,"enabled":true}' >/dev/null

code=$(api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"x.com","qtype":"A","value":"999.1.1.1","ttl":60,"enabled":true}')
[ "$code" = "400" ]; check $? "非法IPv4被拒绝 (http=$code, 期望400)"

code=$(api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"x.com","qtype":"MX","value":"mx.com","ttl":60,"enabled":true}')
[ "$code" = "400" ]; check $? "不支持的类型MX被拒绝 (http=$code, 期望400)"

n=$(api_get "$API/api/overrides" | jqpy "print(len(json.load(sys.stdin)['overrides']))")
[ "$n" = "3" ]; check $? "列表查询返回3条规则"

say "== DNS 篡改解析 =="
[ "$(digq A test.example.com)" = "1.2.3.4" ]; check $? "精确A命中 → 1.2.3.4"
[ "$(digq AAAA ad.com)" = "2001:db8::1" ]; check $? "后缀AAAA命中自身(ad.com) → 2001:db8::1"
[ "$(digq AAAA sub.ad.com)" = "2001:db8::1" ]; check $? "后缀AAAA命中子域名(sub.ad.com)"
[ "$(digq CNAME go.example.org | head -1)" = "real.target.com." ]; check $? "CNAME直查命中"
[ "$(digq A go.example.org | head -1)" = "real.target.com." ]; check $? "A查询回退CNAME规则"

say "== 优先级与正常解析 =="
# 先真实解析缓存，再加篡改规则验证优先级
digq A www.qq.com >/dev/null 2>&1
api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"www.qq.com","qtype":"A","value":"6.6.6.6","ttl":60,"enabled":true}' >/dev/null
[ "$(digq A www.qq.com)" = "6.6.6.6" ]; check $? "篡改优先于缓存(www.qq.com) → 6.6.6.6"

# 删除该规则后恢复真实解析（www.qq.com真实解析为CNAME链，非空且非篡改值即通过）
oid=$(api_get "$API/api/overrides" | jqpy "print([o['id'] for o in json.load(sys.stdin)['overrides'] if o['domain']=='www.qq.com'][0])")
api_req -X DELETE "$API/api/overrides/$oid" >/dev/null
sleep 0.5
real=$(digq A www.qq.com | head -1)
if [ -n "$real" ] && [ "$real" != "6.6.6.6" ]; then ok "删除规则后恢复真实解析($real)"; else bad "删除规则后恢复真实解析(得到: $real)"; fi

say "== 管理页与协议守卫 =="
[ "$(curl -s -o /dev/null -w '%{http_code}' "$API/")" = "200" ]; check $? "管理页GET / 返回200"

# 原始UDP包验证协议守卫: 返回响应rcode
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

[ "$(rawq 256 0)" = "1" ]; check $? "QDCOUNT=0 → FORMERR(1)"
[ "$(rawq 256 2)" = "1" ]; check $? "QDCOUNT=2 → FORMERR(1)"
[ "$(rawq 2304 1)" = "4" ]; check $? "Opcode=STATUS → NOTIMP(4)"

say "== 信号处理 =="
kill -HUP $PID; sleep 1
kill -0 $PID 2>/dev/null; check $? "SIGHUP重载后进程存活"
# 日志有落盘缓冲，轮询等待重载日志出现（stdout与文件日志均可能）
found=1
for _ in $(seq 1 10); do
  if grep -aq "CONFIG_RELOADED" "$LOG" 2>/dev/null || grep -rq "CONFIG_RELOADED" "$WORK_DIR/logs" 2>/dev/null; then
    found=0; break
  fi
  sleep 0.3
done
check $found "SIGHUP触发配置重载日志"

say "== 篡改规则热重载(SIGHUP) =="
api_req -X POST "$API/api/overrides" -H 'Content-Type: application/json' \
  -d '{"domain":"hup.example.com","qtype":"A","value":"7.7.7.7","ttl":60,"enabled":true}' >/dev/null
kill -HUP $PID; sleep 1
[ "$(digq A hup.example.com)" = "7.7.7.7" ]; check $? "规则经SIGHUP重载后生效 → 7.7.7.7"

say "== 优雅退出 =="
kill -TERM $PID; sleep 2
if kill -0 $PID 2>/dev/null; then bad "SIGTERM后进程退出"; else ok "SIGTERM后进程退出"; fi

say ""
say "结果: $PASS 通过, $FAIL 失败"
[ "$FAIL" = "0" ]
