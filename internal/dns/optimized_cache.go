package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CacheEntry 优化的缓存条目
type CacheEntry struct {
	Domain        string        // 域名
	QType         uint16        // 查询类型
	Response      *dns.Msg      // DNS响应
	TTL           time.Duration // 缓存TTL
	LastUserQuery time.Time     // 用户最后查询时间
}

// OptimizedDNSCache 优化的DNS缓存系统
type OptimizedDNSCache struct {
	mu             sync.RWMutex
	entries        map[string]*CacheEntry // 缓存条目映射
	maxSize        int                    // 最大缓存条目数
	defaultTTL     time.Duration          // 默认TTL
	refreshTTL     time.Duration          // 刷新阈值
	stats          *CacheStats            // 缓存统计
	asyncRefreshFn func(domain string, qType uint16) (*dns.Msg, error) // 异步刷新函数
}

// CacheStats 缓存统计
type CacheStats struct {
	Hits      int64 `json:"hits"`      // 命中次数
	Misses    int64 `json:"misses"`    // 未命中次数
	Evictions int64 `json:"evictions"` // 驱逐次数
	Size      int   `json:"size"`      // 当前大小
	MaxSize   int   `json:"max_size"`  // 最大大小
}

// NewOptimizedDNSCache 创建优化的DNS缓存
func NewOptimizedDNSCache(maxSize int, defaultTTL, refreshTTL time.Duration, asyncRefreshFn func(domain string, qType uint16) (*dns.Msg, error)) *OptimizedDNSCache {
	if maxSize <= 0 {
		maxSize = 5000 // 默认5000个条目
	}
	
	cache := &OptimizedDNSCache{
		entries:        make(map[string]*CacheEntry),
		maxSize:        maxSize,
		defaultTTL:     defaultTTL,
		refreshTTL:     refreshTTL,
		stats:          &CacheStats{MaxSize: maxSize},
		asyncRefreshFn: asyncRefreshFn,
	}
	
	// 启动定时检查过期条目的goroutine
	if asyncRefreshFn != nil {
		go cache.periodicExpiryCheck()
	}
	
	return cache
}

// generateCacheKey 生成缓存键
func (c *OptimizedDNSCache) generateCacheKey(domain string, qType uint16) string {
	return fmt.Sprintf("%s:%d", domain, qType)
}

// calculateActualTTL 计算实际TTL：取域名TTL和配置最小TTL的较大值
func (c *OptimizedDNSCache) calculateActualTTL(response *dns.Msg) time.Duration {
	if response == nil || len(response.Answer) == 0 {
		return c.defaultTTL
	}
	
	// 从DNS响应中提取最小TTL
	var minResponseTTL uint32 = ^uint32(0) // 初始化为最大值
	for _, answer := range response.Answer {
		if answer.Header().Ttl < minResponseTTL {
			minResponseTTL = answer.Header().Ttl
		}
	}
	
	// 如果TTL为0或无效，使用默认值
	if minResponseTTL == 0 || minResponseTTL == ^uint32(0) {
		return c.defaultTTL
	}
	
	// 转换为time.Duration
	responseTTL := time.Duration(minResponseTTL) * time.Second
	
	// 取域名TTL和配置最小TTL的较大值
	if responseTTL > c.defaultTTL {
		log.Printf("【TTL计算】域名TTL(%v) > 配置最小TTL(%v)，使用域名TTL: %v", 
			responseTTL, c.defaultTTL, responseTTL)
		return responseTTL
	} else {
		log.Printf("【TTL计算】域名TTL(%v) < 配置最小TTL(%v)，使用配置最小TTL: %v", 
			responseTTL, c.defaultTTL, c.defaultTTL)
		return c.defaultTTL
	}
}

// Get 获取缓存（用户查询）
func (c *OptimizedDNSCache) Get(domain string, qType uint16, queryID uint16) (*dns.Msg, bool) {
	key := c.generateCacheKey(domain, qType)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	entry, exists := c.entries[key]
	if !exists {
		c.stats.Misses++
		return nil, false
	}
	
	// 检查是否过期
	now := time.Now()
	if now.After(entry.LastUserQuery.Add(entry.TTL)) {
		// 过期，从缓存中移除
		c.removeEntry(entry)
		c.stats.Misses++
		
		// 触发异步刷新
		if c.asyncRefreshFn != nil {
			go c.asyncRefresh(domain, qType)
		}
		
		return nil, false
	}
	
	// 检查是否需要异步刷新
	if c.asyncRefreshFn != nil && now.Add(c.refreshTTL).After(entry.LastUserQuery.Add(entry.TTL)) {
		// 在刷新阈值内，触发异步刷新
		log.Printf("【异步刷新】触发刷新: %s, TTL剩余: %v, 刷新阈值: %v", 
			domain, entry.LastUserQuery.Add(entry.TTL).Sub(now), c.refreshTTL)
		go c.asyncRefresh(domain, qType)
	}
	
	// 更新用户查询时间
	entry.LastUserQuery = now
	
	c.stats.Hits++
	
	// 返回响应副本，并确保ID与当前查询匹配
	response := entry.Response.Copy()
	// 重要：设置正确的查询ID，确保客户端能正确识别响应
	response.Id = queryID
	return response, true
}

// Set 设置缓存（用户查询或异步刷新）
func (c *OptimizedDNSCache) Set(domain string, qType uint16, response *dns.Msg, isAsyncRefresh bool) {
	if response == nil {
		return
	}
	
	key := c.generateCacheKey(domain, qType)
	now := time.Now()
	
	// 计算实际TTL：取域名TTL和配置最小TTL的较大值
	actualTTL := c.calculateActualTTL(response)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// 如果条目已存在，更新数据
	if existing, exists := c.entries[key]; exists {
		existing.Response = response.Copy()
		existing.TTL = actualTTL
		
		// 只有用户查询才更新LastUserQuery时间
		if !isAsyncRefresh {
			existing.LastUserQuery = now
		}
		// 更新Size统计（条目已存在，Size不变，但确保统计准确）
		c.stats.Size = len(c.entries)
		return
	}
	
	// 如果缓存已满，驱逐最旧的用户查询
	if len(c.entries) >= c.maxSize {
		c.evictOldestUserQuery()
	}
	
	// 创建新条目
	entry := &CacheEntry{
		Domain:        domain,
		QType:         qType,
		Response:      response.Copy(),
		TTL:           actualTTL,
		LastUserQuery: now, // 新条目总是设置当前时间
	}
	
	// 添加到缓存
	c.entries[key] = entry
	c.stats.Size = len(c.entries)
	
	// 调试日志：显示缓存条目添加
	log.Printf("【缓存调试】添加条目: %s, TTL: %v, 当前大小: %d/%d", key, actualTTL, c.stats.Size, c.maxSize)
}

// evictOldestUserQuery 驱逐最旧的用户查询
func (c *OptimizedDNSCache) evictOldestUserQuery() {
	if len(c.entries) == 0 {
		return
	}
	
	// 找到最旧的用户查询
	var oldestKey string
	var oldestTime = time.Now()
	
	for key, entry := range c.entries {
		if entry.LastUserQuery.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastUserQuery
		}
	}
	
	if oldestKey != "" {
		log.Printf("【缓存驱逐】驱逐最旧条目: %s, 最后查询时间: %v", oldestKey, oldestTime)
		delete(c.entries, oldestKey)
		c.stats.Evictions++
		c.stats.Size = len(c.entries)
		log.Printf("【缓存驱逐】驱逐完成，当前大小: %d/%d", c.stats.Size, c.maxSize)
	}
}

// removeEntry 移除缓存条目
func (c *OptimizedDNSCache) removeEntry(entry *CacheEntry) {
	key := c.generateCacheKey(entry.Domain, entry.QType)
	delete(c.entries, key)
	c.stats.Evictions++
	c.stats.Size = len(c.entries)
}

// Remove 根据域名和查询类型移除缓存条目
func (c *OptimizedDNSCache) Remove(domain string, qType uint16) {
	key := c.generateCacheKey(domain, qType)
	
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if _, exists := c.entries[key]; exists {
		delete(c.entries, key)
		c.stats.Evictions++
		c.stats.Size = len(c.entries)
		// 缓存条目已移除
		log.Printf("【缓存调试】移除条目: %s, 当前大小: %d/%d", key, c.stats.Size, c.maxSize)
	}
}

// SetAsyncRefreshFn 设置异步刷新函数
func (c *OptimizedDNSCache) SetAsyncRefreshFn(fn func(domain string, qType uint16) (*dns.Msg, error)) {
	c.asyncRefreshFn = fn
}

// GetStats 获取缓存统计信息
func (c *OptimizedDNSCache) GetStats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// 确保Size统计是最新的
	c.stats.Size = len(c.entries)
	
	// 调试日志：显示当前缓存状态
	log.Printf("【缓存统计调试】当前条目数: %d, 最大容量: %d", len(c.entries), c.maxSize)
	for key := range c.entries {
		log.Printf("【缓存条目】%s", key)
	}
	
	return c.stats
}

// DebugCache 调试缓存内容
func (c *OptimizedDNSCache) DebugCache() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	log.Printf("=== 缓存调试信息 ===")
	log.Printf("配置: 最大容量=%d, 当前大小=%d", c.maxSize, len(c.entries))
	log.Printf("统计: 命中=%d, 未命中=%d, 驱逐=%d", c.stats.Hits, c.stats.Misses, c.stats.Evictions)
	
	if len(c.entries) == 0 {
		log.Printf("缓存为空")
		return
	}
	
	log.Printf("缓存条目详情:")
	for key, entry := range c.entries {
		log.Printf("  - 键: %s", key)
		log.Printf("    域名: %s", entry.Domain)
		log.Printf("    类型: %d", entry.QType)
		log.Printf("    TTL: %v", entry.TTL)
		log.Printf("    最后查询: %v", entry.LastUserQuery)
		log.Printf("    是否过期: %v", time.Now().After(entry.LastUserQuery.Add(entry.TTL)))
	}
	log.Printf("=== 缓存调试信息结束 ===")
}

// asyncRefresh 异步刷新
func (c *OptimizedDNSCache) asyncRefresh(domain string, qType uint16) {
	log.Printf("【异步刷新】开始执行: %s, 类型: %d", domain, qType)
	
	if c.asyncRefreshFn == nil {
		log.Printf("【异步刷新】错误: 异步刷新函数未设置")
		return
	}
	
	// 执行异步刷新
	log.Printf("【异步刷新】调用异步刷新函数: %s", domain)
	if response, err := c.asyncRefreshFn(domain, qType); err == nil && response != nil {
		// 异步刷新成功，更新缓存（标记为异步刷新）
		log.Printf("【异步刷新】成功: %s, 更新缓存", domain)
		c.Set(domain, qType, response, true)
	} else {
		log.Printf("【异步刷新】失败: %s, 错误: %v", domain, err)
	}
}

// CleanupExpired 清理过期条目
func (c *OptimizedDNSCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	// 遍历所有条目，检查是否过期
	for _, entry := range c.entries {
		if now.After(entry.LastUserQuery.Add(entry.TTL)) {
			c.removeEntry(entry)
			expiredCount++
		}
	}
	
	return expiredCount
}



// periodicExpiryCheck 定时检查过期条目
func (c *OptimizedDNSCache) periodicExpiryCheck() {
	log.Printf("【定时检查】启动定时检查，每10秒检查一次")
	ticker := time.NewTicker(10 * time.Second) // 每10秒检查一次
	defer ticker.Stop()
	
	for range ticker.C {
		log.Printf("【定时检查】执行定时检查")
		c.checkAndRefreshExpired()
	}
}

// checkAndRefreshExpired 检查并刷新即将过期的条目
func (c *OptimizedDNSCache) checkAndRefreshExpired() {
	c.mu.RLock()
	entriesToRefresh := make([]string, 0)
	now := time.Now()
	
	log.Printf("【定时检查】开始检查缓存条目，当前时间: %v", now)
	
	for key, entry := range c.entries {
		// 计算TTL剩余时间
		expireTime := entry.LastUserQuery.Add(entry.TTL)
		remainingTTL := expireTime.Sub(now)
		
		log.Printf("【定时检查】条目: %s, TTL: %v, 剩余时间: %v, 刷新阈值: %v", 
			key, entry.TTL, remainingTTL, c.refreshTTL)
		
		// 检查是否在刷新阈值内：剩余时间小于刷新阈值时触发刷新
		if remainingTTL <= c.refreshTTL {
			log.Printf("【定时检查】条目 %s 需要刷新，剩余时间: %v <= 刷新阈值: %v", 
				key, remainingTTL, c.refreshTTL)
			entriesToRefresh = append(entriesToRefresh, key)
		}
	}
	c.mu.RUnlock()
	
	log.Printf("【定时检查】需要刷新的条目数: %d", len(entriesToRefresh))
	
	// 触发异步刷新
	for _, key := range entriesToRefresh {
		parts := strings.Split(key, ":")
		if len(parts) == 2 {
			domain := parts[0]
			if qType, err := strconv.ParseUint(parts[1], 10, 16); err == nil {
				log.Printf("【定时检查】触发异步刷新: %s, 类型: %d", domain, uint16(qType))
				go c.asyncRefresh(domain, uint16(qType))
			}
		}
	}
}

// Clear 清空缓存
func (c *OptimizedDNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.entries = make(map[string]*CacheEntry)
	c.stats.Size = 0
	c.stats.Evictions = 0
	c.stats.Hits = 0
	c.stats.Misses = 0
}

// GetOldestUserQueries 获取最旧的用户查询（按用户查询时间排序）
func (c *OptimizedDNSCache) GetOldestUserQueries(limit int) []*CacheEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if limit <= 0 || limit > len(c.entries) {
		limit = len(c.entries)
	}
	
	// 收集所有条目
	entries := make([]*CacheEntry, 0, len(c.entries))
	for _, entry := range c.entries {
		entries = append(entries, entry)
	}
	
	// 按用户查询时间排序（简单冒泡排序）
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].LastUserQuery.After(entries[j].LastUserQuery) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}
	
	return entries[:limit]
}