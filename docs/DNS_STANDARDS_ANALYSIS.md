# DNS 代理项目：工作流程与标准合规性分析

> 分析日期：2026-09-17
> 分析范围：`main.go`、`internal/dns/`（handler / server / query / cache_manager / optimized_cache / cname_processor / pool / recovery 等，约 1.2 万行）

---

## 一、项目当前工作流程

### 1.1 启动流程

```
main.go
 ├─ config.LoadAndValidateConfig()          # 加载并校验 config.yaml
 ├─ utils.InitResourceFiles(cfg)            # 初始化数据文件与目录
 ├─ utils.NewEnhancedLogger(...)            # 日志系统
 └─ recovery.NewRecoveryManager(cfg).Start()
      ├─ NewRefactoredHandler()             # 组装所有 DNS 组件
      │    ├─ CloudDetector                 # Cloudflare / AWS IP 检测
      │    ├─ CacheManager + OptimizedDNSCache  # 分片 LRU 缓存 + singleflight + 异步刷新
      │    ├─ SimpleModernOptimizer / FastQueryOptimizer  # 上游并发查询（fastest-wins）
      │    ├─ DoT / DoH / UDP / TCP 连接池
      │    ├─ MatcherHandler（YAML 定向域名 + ChinaMatcher 分流）
      │    ├─ CloudHandler / CloudProcessor # 云 IP 替换
      │    ├─ CNAMEProcessor               # CNAME 链递归解析
      │    ├─ RefreshHandler / TaskScheduler / FileLoader
      │    └─ StartBackgroundTasks()        # 后台定时任务
      ├─ NewUDPServer + NewTCPServer        # 监听同一端口
      └─ ActivateAndServe()（阻塞）
```

### 1.2 查询处理主流程（ServeDNS）

```
客户端请求 (UDP/TCP)
 │
 ▼
ServeDNS (handler.go:200)
 ├─ panic 恢复 + 计时
 ├─ 空请求 → SERVFAIL
 └─ for 每个 Question：
      ├─ domain = ToLower(TrimSuffix(q.Name, "."))   ← 大小写丢失
      ├─ 域名非法 → continue（可能不回任何响应）
      ├─ 非 A/AAAA → processNonIPQuery → 缓存命中？→ 上游查询 → 缓存 → 返回
      └─ A/AAAA → processQuery (handler.go:333)
           ├─ ① GetWithFlight：singleflight 查缓存
           │     ├─ 命中 + 云域名 → GetCloudResponse → 改 TTL → 返回
           │     └─ 命中 + 普通域名 → 改 TTL → 返回
           ├─ ② determineUpstreamsForDomain
           │     ├─ YAML 定向域名 → 指定 DNS
           │     ├─ 中国域名 → ChinaDNS
           │     └─ 默认 → config.Upstream 列表
           ├─ ③ proxyQueryWithCaching：并发查询所有上游，取最快成功结果
           │     └─ 失败时回退 BackupDNS
           ├─ ④ ProcessDNSResponseWithCNAME：递归追 CNAME 链
           │     └─ 每跳：查缓存或 proxyQuery 子查询
           ├─ ⑤ 云检测：DetectCloudflareService / DetectAWSService
           │     ├─ 云域名 → CloudHandler.HandleCloudReplacement（替换 IP）→ 返回
           │     └─ 非云 → ensureMinimumTTL → WriteMsg
           └─ ⑥ 缓存写入（含云标记、失败响应短 TTL）
```

### 1.3 缓存与后台刷新机制

- **缓存结构**：分片 map + LRU（按 LastAccess 淘汰），key = `domain|qtype`（无 qclass）
- **写入**：取 answer 最小 TTL 与配置 TTL 取大者作为过期时间；NXDOMAIN/SERVFAIL 固定缓存 5s
- **命中**：返回缓存对象本体（调用方自行 `Copy()`），**TTL 不递减**
- **过期策略**：
  - 失败响应过期 → 立即删除返回 miss
  - 成功响应过期 → 仍返回（TTL 改写为 5s）+ 触发后台刷新（serve-stale 变体）
- **异步刷新**：worker pool + 域名级锁，singleflight 防重复查询
- **云域名标记**：`MarkDomainAsCloud` 给 A/AAAA/CNAME/MX/TXT 五个 qtype 全部打标

### 1.4 上游协议支持

UDP / TCP / DoH（HTTP POST `application/dns-message`）/ DoT / DoH3，通过 URL scheme 区分；连接池按地址管理，DoT 连接带 `inUse` 独占标记。

---

## 二、问题清单

### P0 — 协议正确性问题（客户端可感知）

#### P0-1. CNAME 响应重写破坏 DNS 语义（最严重）

**位置**：`cname_processor.go:252-260`（链上每跳 CNAME owner 重写）、`cname_processor.go:326-328`（其他记录 owner 重写）、`cname_processor.go:366-374`（Aggressive 版本同样问题）

**现象**：客户端查询 `a.com`，上游返回 `a.com CNAME b.com`，代码再查 `b.com` 得到 A 记录后，把 owner name 全部重写为原始域名：

```
实际返回（错误）：            标准应为：
a.com CNAME b.com            a.com CNAME b.com
a.com A     1.2.3.4          b.com A     1.2.3.4   ← owner 应保留
```

**违规**：RFC 1034 §3.6.2 — CNAME 与其他记录类型在同一 owner 上互斥，`a.com` 同时存在 CNAME 和 A 是矛盾数据，严格客户端会解析失败或拒绝缓存。

**根源**：recursive resolver 不应自己追 CNAME 链——上游（同为递归服务器）已经追完并返回完整链。手动重追再重写 owner 属于画蛇添足。

#### P0-2. 缓存命中 TTL 不递减

**位置**：`optimized_cache.go:244-254`（命中直接返回原始对象）；`handler.go:381`、`handler.go:505`（`ensureMinimumTTL` 反而抬高 TTL）；`optimized_cache.go:364-381`（`adjustExpiredResponseTTL` 连 Ns/Extra 段一起改，未来放入 OPT 记录会被破坏）

**现象**：缓存 TTL 300s 的记录，第 299 秒命中仍返回 TTL=300，客户端会再缓存 300 秒；`ensureMinimumTTL` 还会把上游给的短 TTL（如 30s）抬高到配置下限，主动延长数据生存期。

**违规**：RFC 1035 §4.3.1 — TTL 表示剩余生存时间，缓存返回时必须按 `now - storedAt` 递减。

#### P0-3. 没有任何 TC 截断逻辑

**位置**：全项目无 `Truncate` 调用；所有 `WriteMsg` 直接写出（handler.go 有 6+ 处分散的 WriteMsg）

**现象**：UDP 下响应超过 512B（无 EDNS）或超过客户端通告 payload size 时，客户端收到分片报文或直接丢包，表现为随机超时（TXT 记录多的域名在 UDP 下时好时坏）。

**违规**：RFC 1035 §4.2.1、RFC 6891 §6.2.3 — 超限时应设置 TC=1 截断返回，让客户端转 TCP 重试。

#### P0-4. 完全没有 EDNS0/OPT 处理

**位置**：全项目无 OPT 解析/构造

**现象**：
- 不解析请求中的 OPT 记录（UDP payload size、DO bit、version）
- 响应不回带 OPT（带 EDNS 的现代客户端均期望响应带 OPT）
- 不知道客户端 buffer size → 堵死了 P0-3 的正确解法

**违规**：RFC 6891。

#### P0-5. 非法请求静默无响应

**位置**：`handler.go:229-233`

**现象**：域名非法时 `continue`；若所有问题均非法，循环结束不回任何报文，客户端干等到超时。应回 FORMERR。

#### P0-6. Server 启动/停止死锁

**位置**：`server.go:60-124`（`Start()` 持 `s.mu` 并阻塞在 `ActivateAndServe()`）；`server.go:127-131`（`Stop()` 首行抢同一把锁）；`recovery.go:239-241`（`stopDNSService` 因此永久阻塞）

**现象**：
- 服务器正常运行期间 `Stop()` 永远拿不到锁 → 优雅停机失效
- `s.running = true` 放在 `ActivateAndServe` 返回之后 — 即服务器**停止后**才标记运行中，逻辑颠倒

### P1 — 标准合规性问题

| # | 位置 | 问题 | 应有行为 |
|---|------|------|----------|
| P1-1 | `handler.go:200` | 不检查 QR bit | QR=1 的消息应忽略（防请求回环） |
| P1-2 | `handler.go:200` | 不检查 Opcode | 非 QUERY 回 NOTIMP（RFC 1035 §4.1.1） |
| P1-3 | `handler.go:244` | 多 question 请求只处理第一个 | QDCOUNT>1 应回 FORMERR |
| P1-4 | `handler.go:200` | 不区分 RD=0 | 非递归请求应 REFUSED 或仅用缓存回答 |
| P1-5 | `handler.go:226` | `strings.ToLower` 后重建 Question/RR name | 应保留客户端原始 QNAME（含大小写）；0x20 随机化客户端校验失败（`dig +dns0x20` 可复现） |
| P1-6 | `cname_processor.go:65-77` | 篡改 answer 后未清 AD bit | 数据被改写后 AD 断言不再成立，应清零 |
| P1-7 | `cache_manager.go:340-348` | NXDOMAIN 固定缓存 5s | RFC 2308：应遵循 SOA 的 negative TTL |
| P1-8 | `cname_processor.go:85-88` | A/AAAA 裁剪到 maxIPRecords=2 | RFC 2181 §5.2：RRset 应原子性返回；裁剪破坏客户端地址选择与负载均衡 |

### P2 — 结构与工程质量问题

| # | 位置 | 问题 |
|---|------|------|
| P2-1 | `query.go:135` → `handler.go:448` → `cache_manager.go:325` | 云检测重复执行：同一响应最多被扫描三遍（proxyQueryWithCaching 一次、processQuery 一次、CacheManager.Set 一次） |
| P2-2 | `handler.go:57-83` | 组件网状耦合：RefactoredHandler 持有 10+ 组件；cloudHandler / refreshHandler / cnameProcessor 反向持有 `handler.proxyQuery` 函数值 + `SetRefreshCallback` 回调，无清晰调用方向 |
| P2-3 | `query.go:26-34`、`query.go:88-96` | `queryOptimizer` 声明为 `interface{}`，每次使用都类型断言，应抽成接口 |
| P2-4 | `optimized_cache.go:251-254` | 缓存 Get 返回共享对象本体，依赖调用方自觉 `Copy()`，存在数据竞争隐患 |
| P2-5 | `server.go:224-257` | 两套启动路径（`StartUDPServer`/`StartTCPServer` 函数 vs recovery 管理器），死代码嫌疑 |
| P2-6 | `handler.go:236` | 查询路径中大量 `map[string]interface{}` 构造用于 Debug 日志，每个请求多次分配 |

---

## 三、改进设计思路

### 3.1 核心原则

**把「协议合规」与「业务策略」（云替换、中国分流）彻底分离成流水线。**

参考 CoreDNS 的 plugin chain 结构：

```
请求 → [1 守卫] → [2 缓存] → [3 上游解析] → [4 策略] → [5 响应出口] → 客户端
```

### 3.2 各层职责

**第 1 层 — 协议守卫（ServeDNS 入口）**

- 校验 QR / Opcode / QDCOUNT
- 解析 EDNS：记录客户端 payload size、DO bit
- 保留原始 QNAME（内部缓存 key 可小写化，但响应回写原串）
- 不合格输入一律回标准 rcode（FORMERR / NOTIMP / REFUSED），绝不让客户端空等

**第 2 层 — 缓存（唯一职责：存取 + TTL 递减）**

- 缓存条目存 `storedAt`；命中时 Copy 并按 `now - storedAt` 递减每条 RR 的 TTL（下限 0）
- serve-stale 做成显式开关，仅在上游查询失败时兜底（RFC 8767 语义），而非无条件返回过期数据
- NXDOMAIN 改用 SOA negative TTL
- 去掉 `ensureMinimumTTL` 抬高 TTL 的行为

**第 3 层 — 上游解析（只查不改）**

- 保留 fastest-wins 并发扇出，但返回的响应**原样透传**，不做任何 answer 改写
- DoT 连接池已有 `inUse` 独占标记，无并发问题，维持现状

**第 4 层 — 策略（云替换/分流只在这里发生）**

- `ProcessDNSResponseWithCNAME` 重新定位为**内部检测工具**：沿 CNAME 链收集 IP 用于判断是否云域名，不再重写返回给客户端的响应
- 客户端可见的 answer 保持上游原样；云替换只替换最终 A/AAAA 的 IP 值，不动 CNAME 结构和 owner
- 此改动同时消灭 P0-1 和 P2-1（重复检测）

**第 5 层 — 响应出口（唯一 WriteMsg 的地方）**

所有路径（缓存命中 / 上游 / 云替换 / 错误）收口到一个函数，统一做：

1. `Id = req.Id`、`Question = req.Question` 原样
2. 被篡改过则清 AD bit
3. `resp.Truncate(maxPayload)` 设置 TC 位
4. 按请求回带 OPT

### 3.3 落地顺序（每步独立可验证）

| 步骤 | 内容 | 验证方式 |
|------|------|----------|
| 1 | 修 `server.go` Start/Stop 死锁 | SIGTERM 能秒级退出 |
| 2 | 缓存 TTL 递减 | `dig` 同一域名第二次查询 TTL < 第一次 |
| 3 | 去掉 CNAME owner 重写 | `dig` 带 CNAME 链的域名，answer 各跳 owner 正确 |
| 4 | 非法请求回 FORMERR | 畸形包不超时 |
| 5 | EDNS 解析 + Truncate 出口 | 大 TXT 记录 UDP 查询返回 TC=1，TCP 正常 |
| 6 | pipeline 大重构 | 协议层已正确后，重构只是挪代码，行为不变 |

---

## 四、参考标准

| RFC | 主题 |
|-----|------|
| RFC 1034 / 1035 | DNS 基础协议、CNAME 语义、缓存 TTL 语义、截断 |
| RFC 2181 | RRset 原子性、TTL 规则澄清 |
| RFC 2308 | 负缓存（NXDOMAIN）语义 |
| RFC 6891 | EDNS0 / OPT 记录 |
| RFC 7766 | DNS over TCP 实现要求 |
| RFC 8767 | Serve-stale（过期待定返回）合法化与实施条件 |
