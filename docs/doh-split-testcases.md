# DoH 客户端分流 + 云替换多线路 测试用例设计

> 版本：v1.0　　目标环境：线上 `10.0.0.30`（生产，有真实流量）
> 测试类型：功能验证 + 线路隔离验证 + 异常/边界 + 性能基线
> 设计视角：测试工程师视角（等价类 / 边界值 / 状态迁移 / 正交组合 / 风险驱动）
> 配套脚本：`scripts/test_doh_split.py`（功能）、`scripts/perf_doh.py`（性能）

---

## 1. 测试目标

1. **协议正确性**：DoH（RFC 8484）GET/POST 两条路径、Content-Type/Content-Length、Base64URL 编解码、错误码符合规范。
2. **多入口一致**：DoH、DoT、明文 UDP/TCP 对**同一域名 + 同一客户端线路**返回一致结果。
3. **客户端 IP 分流（核心新特性）**：按客户端真实 IP 命中 ISP 分组（telecom/cmcc），走该分组引用的域名分流列表；未命中分组走全局分流。
4. **云替换多线路（核心新特性）**：命中 CF 域名的查询，按当前客户端线路选用**不同的优选 IP 目标**：
   - 全局：`replace_cf_api`（`cf.niao.fun`）取前 `api_count` 条；
   - telecom：分组覆写 `cf_domain=cf.92555.xyz`；
   - cmcc：分组覆写 `cf_domain=chinwa.cf.090227.xyz`；
   - 覆写关闭（`override=false`）时必须回退全局目标。
5. **开关与旁路语义**：`定向域名` 列表 `enable_cloud_check=false` ⇒ 命中后**跳过**云检测/替换；`国外` 列表 `enable_cloud_check=true` ⇒ 执行替换；分组兜底路径强制云检测。
6. **缓存隔离**：缓存 key 含 scope，各线路互不污染。
7. **热更新**：在线改配置（`PUT /api/config`）后无需重启即可生效（`restart_required=false`，进程 PID 不变）。
8. **性能基线**：QPS、P50/P95/P99、错误率；热缓存 vs 冷缓存；UDP 与 DoH 对比。

---

## 2. 被测系统与拓扑

```
                 ┌───────────────────────────────┐
  测试机(Mac)    │  线上 dnsproxy @10.0.0.30      │
  10.0.0.29 ────►│  UDP/TCP 53   DoT 853          │──► 上游/替换域名 DNS
       │         │  DoH/DoH3 443 Web 80          │──► cf.niao.fun 优选接口
       └─ DoH/DoT └───────────────────────────────┘
```

- 服务端：2 核 / 512MB，`systemd` 服务 `dnsproxy`，部署路径 `/opt/dnsProxy`。
- Web API：`GET/PUT /api/config`、`GET /api/logs`、`POST /api/restart`。
- **`/api/logs` 是路由/线路断言的 ground truth**：字段 `action`（cache/cloud/split/filtered/override/error）、`list_name`、`dns_mode`、`ecs`、`answers`、`elapsed_ms`。

---

## 3. 线路区分机制（测试可观测性设计）

### 3.1 客户端 IP 来源
线上 `client_ip_sources=["static","header","socket"]`，`trusted_proxies=[]`（⇒ header 伪造被禁用）。
因此测试机（源 IP `10.0.0.29`）**只能通过临时配置 `client_ip_static={"10.0.0.29":"<测试IP>"}`** 来“扮演”不同 ISP 客户端。

| 线路 | scope | 临时 client_ip_static | 期望替换来源 |
|---|---|---|---|
| 全局 | `-` | 不设置（null） | `cf.niao.fun` 接口前 `api_count` 条 |
| 电信 | `telecom` | `{"10.0.0.29":"1.48.0.1"}` | `cf.92555.xyz` 解析结果 |
| 移动 | `cmcc` | `{"10.0.0.29":"27.0.160.1"}` | `chinwa.cf.090227.xyz` 解析结果 |

### 3.2 期望值是**动态**的（关键）
优选域名/接口返回会随时间变化（实测 `cf.92555.xyz` 在数小时内由 `104.17.11.11` 变为 `172.64.144.44`）。
**用例不得硬编码期望 IP**，而应在执行时动态计算：

```
期望_telecom = A(cf.92555.xyz @ 58.20.127.238)          # 服务端替换域名统一走全局 upstream
期望_cmcc    = A(chinwa.cf.090227.xyz @ 58.20.127.238)
期望_global  = parse(cf.niao.fun/api/results?select=cm)[:api_count]
```

断言口径统一为：**应答 A 记录的 IP 集合 ⊆ 对应线路的期望集合**（且非空），并额外断言三线路集合**两两不等**（隔离性）。

### 3.3 触发云替换的前置条件
云替换仅在「域名 CNAME 链的 IP 命中 Cloudflare 网段」时触发（`DetectCloudflareService`）。
⇒ 云替换用例必须选用 **CF 托管域名**（实测可用：`chatgpt.com`、`discord.com`、`medium.com`、`openai.com`、`www.speedtest.net`、`004430.xyz`、`x.com`）。
非 CF 域名（如 `claude.ai`=160.79.104.10、`reddit.com`=Fastly）只会 `action=split`，用于反向用例。

### 3.4 缓存注意
- 缓存 TTL 5m（内容）/10m（替换接口、替换域名）；key 含 scope。
- 同一 `(域名, 线路)` 二次查询会变 `action=cache`，此时**不能**再断言路由动作。
- 因此**每个需要观测路由动作的用例使用独立域名**（不同线路可复用同一域名，因 scope 不同）。

---

## 4. 用例设计方法说明

- **等价类**：CF 域名 / 非 CF 域名 / 定向域名 / 不存在域名 / 国内域名。
- **边界值**：`api_count` 前 N 条、`max_ip_records`、`cname_recursion_depth`、Base64URL 无填充、空/超长报文。
- **状态迁移**：覆写开启↔关闭、列表云检测开↔关、热更新前后、冷缓存→热缓存。
- **正交组合**：{线路×列表×域名类型} 三维正交，重点覆盖“线路 × 列表云检测开关”引发的跳过/替换分叉。
- **风险驱动**：多线路隔离（最容易串线/缓存污染）、覆写回退（最容易失效）、热更新（最容易丢配置）。

---

## 5. 用例矩阵

> 优先级：P0 阻塞级 / P1 核心 / P2 一般
> 断言真源：DoH 应答报文 + `/api/logs` 记录

### A. 协议与基础可用性

| ID | 优先级 | 场景 | 前置 | 步骤 | 预期 / 断言 |
|---|---|---|---|---|---|
| TC-A01 | P0 | DoH GET 基本解析 | 无 | `GET /dns-query?dns=base64url(example.com A)` | HTTP 200；`content-type: application/dns-message`；rcode=NOERROR；含 A 记录；ID 回显一致 |
| TC-A02 | P0 | DoH POST 与 GET 一致 | 无 | 同一域名分别 GET/POST | 两者 A 集合相同、rcode 相同 |
| TC-A03 | P0 | DoH 与 UDP 一致（同线路） | 无 | 同域名 DoH POST 与 `dig @10.0.0.30` | A 集合相同（缓存命中亦一致） |
| TC-A04 | P2 | DoH GET 非法 base64 | 无 | `?dns=@@@not-base64@@@` | HTTP 400（Bad Request），不 500 |
| TC-A05 | P2 | DoH POST 错误 Content-Type | 无 | `POST text/plain` | HTTP 415/400；不得按 DNS 解析 |
| TC-A06 | P2 | NXDOMAIN 透传 | 无 | 查询不存在域名 | rcode=NXDOMAIN；不返回 SERVFAIL |
| TC-A07 | P1 | 空报文 / 超短 body | 无 | POST 0 字节 / 2 字节 | HTTP 400；服务不崩溃 |
| TC-A08 | P2 | DoT 冒烟 | 无 | `dns.query.tls @10.0.0.30:853` | 成功返回 A 记录 |

### B. 客户端 IP 分流 + 云替换多线路（核心）

| ID | 优先级 | 场景 | 前置 | 步骤 | 预期 / 断言 |
|---|---|---|---|---|---|
| TC-B01 | P0 | 全局线路云替换 | 不设 static | DoH 查询 CF 域名 A | log `action=cloud`、`list_name=国外`；IP ⊆ 期望_global；IP 均为 CF 网段 |
| TC-B02 | P0 | 电信分组覆写生效 | static=1.48.0.1 | DoH 查询 CF 域名 A | log `action=cloud`；IP ⊆ 期望_telecom（`cf.92555.xyz`） |
| TC-B03 | P0 | 移动分组覆写生效 | static=27.0.160.1 | DoH 查询 CF 域名 A | log `action=cloud`；IP ⊆ 期望_cmcc（`chinwa.cf.090227.xyz`） |
| TC-B04 | P0 | 三线路隔离 | 承接 B01-B03 | 对比三条线路应答集合 | 三集合**两两不相等**；各自 ⊆ 各自期望 |
| TC-B05 | P0 | 覆写关闭回退全局 | 临时 `telecom.cloud_replace.override=false` | 同 B02 查询（新域名） | IP 不再是 telecom 目标；⊆ 期望_global（CF 网段、≠期望_telecom） |
| TC-B06 | P1 | 分组兜底路径强制云检测 | static=telecom | 查询**不在** `国外` 列表、也不在 `定向域名` 的 CF 域名 | log `list_name=telecom`（兜底）、`action=cloud`；IP ⊆ 期望_telecom |
| TC-B07 | P1 | 非 CF 域名不替换 | 不设 static | 查询 `claude.ai`/`reddit.com` | log `action=split`；IP = 真实 IP（非 CF 优选） |

### C. 云检测旁路与偏好

| ID | 优先级 | 场景 | 前置 | 步骤 | 预期 / 断言 |
|---|---|---|---|---|---|
| TC-C01 | P0 | `定向域名` 跳过云替换 | 不设 static | 查询命中 `定向域名` 的域名（如 `cloudflare-cn.com`/`cf.niao.fun`） | log `list_name=定向域名`、`action=split`；IP 为真实 IP，**未**被替换 |
| TC-C02 | P1 | `国外` 列表触发替换 | 不设 static | 查询 CF 域名（同 B01） | log `list_name=国外`、`action=cloud`（与 C01 形成正交对照） |
| TC-C03 | P2 | AAAA `prefer_a` 过滤 | 承接线路 | 对含 A 的域名查询 AAAA | rcode=NOERROR；AAAA 为空 / `action=filtered`（“优先 A”） |

### D. 缓存与热更新

| ID | 优先级 | 场景 | 前置 | 步骤 | 预期 / 断言 |
|---|---|---|---|---|---|
| TC-D01 | P1 | scope 缓存隔离 | 承接 B01-B03 | 重复查询三条线路同域名 | 均 `action=cache`；各自应答 = 各自线路集合（未串线） |
| TC-D02 | P0 | 热更新不重启 | 任意 | `PUT /api/config`（仅改 `client_ip_static`） | HTTP 200、`ok=true`、`restart_required=false`；服务 PID **不变** |
| TC-D03 | P1 | 配置持久化正确 | 承接 D02 | `GET /api/config` 回读 | 修改字段与下发一致；其余字段未被破坏 |

---

## 6. 执行与还原策略

1. **备份**：执行前 `GET /api/config` 落盘为 `backup`（脚本内自动）。
2. **变更最小化**：仅临时修改 `client_ip_static`、（B05 用例）`telecom.cloud_replace.override`；**其余字段原样回写**。
3. **还原**：`try/finally` 保证无论用例失败与否都回写原始配置，并回读校验 `client_ip_static=null`、`override=true`。
4. **流量保护**：生产环境，功能用例串行、间隔 ≥ 300ms；性能用例限制并发与总请求数（见 `perf_doh.py`），实时采样服务器 CPU/内存，避免打爆 2 核机器。
5. **域名轮换**：为规避缓存污染，每个“需观测路由动作”的用例分配独立 CF 域名并轮询重试。

---

## 7. 风险与不覆盖项

| 项 | 说明 |
|---|---|
| Header 伪造分流 | `trusted_proxies=[]`，`cf-connecting-ip` 等被忽略，无法测试 header 分流；依赖 static/socket 覆盖。 |
| DoH3(QUIC) | 需要 `aioquic`，本机未装；仅做可用性冒烟（可选），不计入阻断。 |
| 真实多 ISP 客户端 | 生产环境无 telecom/cmcc 真实终端，用 static 映射模拟，属**等价类近似**。 |
| 优选 IP 时效性 | 期望值动态，断言用“子集包含 + 互斥”，不做绝对值比对。 |
| 上游接口抖动 | `cf.niao.fun` 偶发超时（历史观测到 5s 超时→降级返回真实 IP），故 B01 在超时场景可能拿到真实 IP；脚本对 `elapsed_ms>4500` 的降级单独标记 WARN 而非 FAIL。 |