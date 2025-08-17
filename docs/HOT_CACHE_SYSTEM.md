# 热点域名缓存系统

## 设计理念

新的热点缓存系统采用**固定大小池子**的设计理念：

1. **固定内存大小** - 启动时根据配置分配固定大小的缓存池
2. **只保留热点域名** - 自动驱逐最冷门的域名，保留最热门的
3. **LRU + 热度排序** - 结合最后访问时间和命中次数进行智能驱逐
4. **无内存泄漏** - 缓存大小固定，不会无限增长

## 核心特性

### 1. 固定大小缓存池

```go
// 配置示例：100MB -> 100000个域名
cache:
  max_size: "100MB"  # 每MB对应1000个域名
```

- 启动时创建固定大小的缓存池
- 超出容量时自动驱逐最冷的数据
- 内存使用完全可控，不会溢出

### 2. 智能驱逐策略

```go
// 驱逐优先级：
// 1. 命中次数最少
// 2. 最后访问时间最早
// 3. TTL过期
```

- 使用最小堆（Min Heap）快速找到最冷的数据
- 优先保留高命中率的域名
- 自动清理过期的缓存项

### 3. 热点域名识别

```go
type HotDomain struct {
    Domain     string        // 域名
    HitCount   int64         // 命中次数
    LastAccess time.Time     // 最后访问时间
    TTL        time.Duration // 缓存TTL
    Data       interface{}   // 缓存的数据
}
```

- 记录每个域名的访问热度
- 实时更新命中统计
- 支持 TTL 过期检查

## 配置说明

### 缓存大小配置

```yaml
cache:
  max_size: "100MB"    # 100MB -> 100000个域名
  max_size: "50MB"     # 50MB -> 50000个域名
  max_size: "200MB"    # 200MB -> 200000个域名
```

**转换规则**：每 1MB 对应 1000 个域名

- 100MB = 100,000 个域名
- 50MB = 50,000 个域名
- 200MB = 200,000 个域名

### TTL 配置

```yaml
cache:
  dns_ttl_min: "5m" # 最小TTL：5分钟
  dns_ttl_max: "2h" # 最大TTL：2小时
  strict_ttl: true # 严格TTL模式
```

## 性能特点

### 1. 内存使用稳定

- 缓存大小固定，不会无限增长
- 内存使用量完全可预测
- 适合容器化部署

### 2. 热点数据优先

- 自动识别并保留热门域名
- 冷门域名自动被驱逐
- 提高整体缓存命中率

### 3. 高效的数据结构

- 使用最小堆进行快速驱逐
- O(log n)的插入和删除复杂度
- 支持并发访问

## 监控指标

### 缓存统计

```go
type CacheStats struct {
    Hits        int64 `json:"hits"`        // 命中次数
    Misses      int64 `json:"misses"`      // 未命中次数
    Evictions   int64 `json:"evictions"`   // 驱逐次数
    Size        int   `json:"size"`        // 当前大小
    MaxSize     int   `json:"max_size"`    // 最大大小
}
```

### 关键指标

- **命中率** = Hits / (Hits + Misses)
- **驱逐率** = Evictions / (Hits + Misses)
- **缓存利用率** = Size / MaxSize

## 使用示例

### 1. 基本使用

```go
// 创建热点缓存
cache := NewHotCache(10000) // 10000个域名

// 设置缓存
cache.Set("example.com", dnsResponse, 5*time.Minute)

// 获取缓存
if data, found := cache.Get("example.com"); found {
    // 使用缓存数据
}
```

### 2. 获取统计信息

```go
stats := cache.GetStats()
fmt.Printf("命中率: %.2f%%, 大小: %d/%d\n",
    float64(stats.Hits)/float64(stats.Hits+stats.Misses)*100,
    stats.Size, stats.MaxSize)
```

### 3. 获取热门域名

```go
topDomains := cache.GetTopDomains(10)
for _, domain := range topDomains {
    fmt.Printf("域名: %s, 命中次数: %d\n", domain.Domain, domain.HitCount)
}
```

## 与旧系统的对比

### 旧系统（ristretto）

- ❌ 内存使用不可控
- ❌ 可能无限增长
- ❌ 驱逐策略复杂
- ✅ 性能较高

### 新系统（HotCache）

- ✅ 内存使用完全可控
- ✅ 固定大小，不会溢出
- ✅ 智能驱逐策略
- ✅ 热点数据优先
- ✅ 监控指标清晰

## 最佳实践

### 1. 缓存大小配置

```yaml
# 小型部署
cache:
  max_size: "50MB"    # 50,000个域名

# 中型部署
cache:
  max_size: "100MB"   # 100,000个域名

# 大型部署
cache:
  max_size: "200MB"   # 200,000个域名
```

### 2. TTL 配置

```yaml
cache:
  dns_ttl_min: "5m" # 最小5分钟
  dns_ttl_max: "2h" # 最大2小时
  refresh_threshold: "10s" # 提前10秒刷新
```

### 3. 监控告警

- 命中率 < 70% 时告警
- 驱逐率 > 10% 时告警
- 缓存利用率 > 90% 时告警

## 故障排除

### 1. 命中率过低

- 检查缓存大小是否足够
- 调整 TTL 配置
- 检查域名访问模式

### 2. 驱逐率过高

- 增加缓存大小
- 检查是否有大量一次性访问
- 优化 TTL 策略

### 3. 内存使用过高

- 检查缓存大小配置
- 监控标签系统大小
- 检查连接池状态

## 总结

新的热点缓存系统通过**固定大小池子**的设计，完美解决了内存溢出的问题：

1. **内存可控** - 启动时分配固定大小，不会无限增长
2. **热点优先** - 自动保留最热门的域名，提高命中率
3. **智能驱逐** - 结合命中次数和访问时间的智能驱逐策略
4. **性能稳定** - 使用高效的数据结构，支持高并发访问

这种设计确保了系统在长期运行时的内存稳定性，同时保持了优秀的缓存性能。
