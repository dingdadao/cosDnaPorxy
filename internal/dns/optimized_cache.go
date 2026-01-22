package dns

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"
)

// CacheEntry 缓存条目
type CacheEntry struct {
	Response         *dns.Msg
	ExpireAt         time.Time
	IsCloud          bool          // 标记是否为云服务域名
	CloudType        int           // 云服务类型（0-无，1-Cloudflare，2-AWS）
	CloudResponse    *dns.Msg      // 云域名的替换响应缓存
	RefreshThreshold time.Duration // 异步刷新阈值
	LastAccess       time.Time
}

// OptimizedDNSCache 优化的DNS缓存系统
type OptimizedDNSCache struct {
	mu          sync.RWMutex
	store       map[string]*CacheEntry
	maxSize     int
	defaultTTL  time.Duration
	flightGroup singleflight.Group
}

// NewOptimizedDNSCache 创建一个新的优化DNS缓存系统
func NewOptimizedDNSCache(maxSize int, defaultTTL time.Duration) *OptimizedDNSCache {
	cache := &OptimizedDNSCache{
		store:       make(map[string]*CacheEntry),
		maxSize:     maxSize,
		defaultTTL:  defaultTTL,
		flightGroup: singleflight.Group{},
	}

	// 启动后台清理协程
	go cache.cleanupRoutine()

	return cache
}

// key 生成缓存键
func (c *OptimizedDNSCache) key(domain string, qType uint16) string {
	return domain + "|" + dns.TypeToString[qType]
}

// GetCloudResponse 获取云域名的替换响应缓存
func (c *OptimizedDNSCache) GetCloudResponse(domain string, qType uint16) (*dns.Msg, bool, int) {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists || !entry.IsCloud {
		return nil, false, 0
	}

	// 检查是否过期
	if time.Now().After(entry.ExpireAt) {
		// 异步删除过期条目
		go func() {
			c.mu.Lock()
			delete(c.store, key)
			c.mu.Unlock()
		}()
		return nil, false, 0
	}

	// 更新最后访问时间
	c.mu.Lock()
	entry.LastAccess = time.Now()
	c.mu.Unlock()

	// 返回云响应缓存
	if entry.CloudResponse != nil {
		return entry.CloudResponse.Copy(), true, entry.CloudType
	}
	return nil, false, entry.CloudType
}

// SetCloudResponse 设置云域名的替换响应缓存
func (c *OptimizedDNSCache) SetCloudResponse(domain string, qType uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	key := c.key(domain, qType)

	// 使用自定义TTL或默认TTL
	ttl := c.defaultTTL
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	}

	// 计算刷新阈值（TTL的30%）
	refreshThreshold := time.Duration(float64(ttl) * 0.3)

	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查是否需要清理缓存
	if len(c.store) >= c.maxSize {
		c.evictLeastRecentlyUsed()
	}

	// 存储云域名缓存
	c.store[key] = &CacheEntry{
		Response:         nil, // 不缓存原始响应
		CloudResponse:    response.Copy(),
		ExpireAt:         time.Now().Add(ttl),
		IsCloud:          true,
		CloudType:        cloudType,
		RefreshThreshold: refreshThreshold,
		LastAccess:       time.Now(),
	}
}

// Get 获取缓存响应
func (c *OptimizedDNSCache) Get(domain string, qType uint16) (*dns.Msg, bool, bool, int) {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false, false, 0
	}

	// 检查是否过期
	isExpired := time.Now().After(entry.ExpireAt)
	if isExpired {
		// 检查是否为失败响应（如NXDOMAIN）且已过期，如果是则立即删除并返回未命中
		if !entry.IsCloud && entry.Response != nil && entry.Response.Rcode != dns.RcodeSuccess {
			// 失败响应已过期，立即删除缓存项并返回未命中
			c.mu.Lock()
			delete(c.store, key)
			c.mu.Unlock()
			return nil, false, false, 0
		}

		// 对于成功的过期响应，先返回给客户端，但不立即删除缓存项
		// 为了避免并发请求导致的缓存雪崩问题，我们采用懒惰删除策略
		// 云服务域名特殊处理
		if entry.IsCloud && entry.CloudResponse != nil {
			// 创建响应副本并调整TTL
			resp := entry.CloudResponse.Copy()
			c.adjustExpiredResponseTTL(resp, 5*time.Second) // 设置较小的TTL给客户端
			// 不删除缓存项，而是更新访问时间
			c.mu.Lock()
			entry.LastAccess = time.Now()
			c.mu.Unlock()
			return resp, true, true, entry.CloudType
		} else if !entry.IsCloud && entry.Response != nil {
			// 普通域名响应
			resp := entry.Response.Copy()
			c.adjustExpiredResponseTTL(resp, 5*time.Second) // 设置较小的TTL给客户端
			// 不删除缓存项，而是更新访问时间
			c.mu.Lock()
			entry.LastAccess = time.Now()
			c.mu.Unlock()
			return resp, true, false, 0
		}
		return nil, true, entry.IsCloud, entry.CloudType
	}

	// 更新最后访问时间（用于LRU淘汰策略）
	c.mu.Lock()
	entry.LastAccess = time.Now()
	c.mu.Unlock()

	// 云服务域名特殊处理
	if entry.IsCloud {
		return entry.CloudResponse, true, true, entry.CloudType
	}

	return entry.Response, true, false, 0
}

// CacheStats 缓存统计信息
type CacheStats struct {
	Size           int                  `json:"size"`
	MaxSize        int                  `json:"max_size"`
	HitCount       int64                `json:"hit_count"`
	MissCount      int64                `json:"miss_count"`
	Entries        map[string]EntryInfo `json:"entries,omitempty"`
	HotEntries     []HotEntry           `json:"hot_entries,omitempty"`
	ExpiredEntries []string             `json:"expired_entries,omitempty"`
	ValidEntries   int                  `json:"valid_entries"`
	ExpiredCount   int                  `json:"expired_count"`
	IPCounts       map[string]int       `json:"ip_counts,omitempty"`
}

// EntryInfo 单个缓存条目信息
type EntryInfo struct {
	Domain      string    `json:"domain"`
	QType       string    `json:"qtype"`
	IsExpired   bool      `json:"is_expired"`
	IsCloud     bool      `json:"is_cloud"`
	ExpireAt    time.Time `json:"expire_at"`
	LastAccess  time.Time `json:"last_access"`
	AnswerCount int       `json:"answer_count"`
}

// HotEntry 热点条目
type HotEntry struct {
	Domain      string    `json:"domain"`
	QType       string    `json:"qtype"`
	LastAccess  time.Time `json:"last_access"`
	AccessCount int       `json:"access_count"`
}

// GetWithFlight 获取缓存响应，使用单飞行模式避免重复查询
func (c *OptimizedDNSCache) GetWithFlight(domain string, qType uint16) (*dns.Msg, bool, bool, int) {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return nil, false, false, 0
	}

	// 检查是否过期
	isExpired := time.Now().After(entry.ExpireAt)
	if isExpired {
		// 检查是否为失败响应（如NXDOMAIN）且已过期，如果是则立即删除并返回未命中
		if !entry.IsCloud && entry.Response != nil && entry.Response.Rcode != dns.RcodeSuccess {
			// 失败响应已过期，立即删除缓存项并返回未命中
			c.mu.Lock()
			delete(c.store, key)
			c.mu.Unlock()
			return nil, false, false, 0
		}

		// 对于成功的过期响应，我们使用单飞行模式来避免重复查询
		// 返回当前的过期响应，并在后台刷新
		var resp *dns.Msg
		var isCloudResult bool
		var cloudType int
		var hit bool

		// 云服务域名特殊处理
		if entry.IsCloud && entry.CloudResponse != nil {
			// 创建响应副本并调整TTL
			resp = entry.CloudResponse.Copy()
			c.adjustExpiredResponseTTL(resp, 5*time.Second) // 设置较小的TTL给客户端
			isCloudResult = true
			cloudType = entry.CloudType
			hit = true
		} else if !entry.IsCloud && entry.Response != nil {
			// 普通域名响应
			resp = entry.Response.Copy()
			c.adjustExpiredResponseTTL(resp, 5*time.Second) // 设置较小的TTL给客户端
			isCloudResult = false
			hit = true
		}

		// 更新访问时间
		c.mu.Lock()
		entry.LastAccess = time.Now()
		c.mu.Unlock()

		// 返回过期的响应，但通过单飞行模式触发后台刷新
		if hit {
			return resp, true, isCloudResult, cloudType
		}
		return nil, true, entry.IsCloud, entry.CloudType
	}

	// 更新最后访问时间（用于LRU淘汰策略）
	c.mu.Lock()
	entry.LastAccess = time.Now()
	c.mu.Unlock()

	// 云服务域名特殊处理
	if entry.IsCloud {
		return entry.CloudResponse, true, true, entry.CloudType
	}

	return entry.Response, true, false, 0
}

// adjustExpiredResponseTTL 调整过期响应的TTL值
func (c *OptimizedDNSCache) adjustExpiredResponseTTL(resp *dns.Msg, newTTL time.Duration) {
	if resp == nil {
		return
	}

	// 将新的TTL值应用到所有RR记录
	newTTLValue := uint32(newTTL.Seconds())

	for _, rr := range resp.Answer {
		rr.Header().Ttl = newTTLValue
	}
	for _, rr := range resp.Ns {
		rr.Header().Ttl = newTTLValue
	}
	for _, rr := range resp.Extra {
		rr.Header().Ttl = newTTLValue
	}
}

// GetExpireTime 获取缓存条目的过期时间
func (c *OptimizedDNSCache) GetExpireTime(domain string, qType uint16) time.Time {
	key := c.key(domain, qType)

	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.store[key]
	if !exists {
		return time.Time{} // 返回零时间
	}

	return entry.ExpireAt
}

// IsCloud 检查域名是否为云服务域名（即使缓存已过期）
func (c *OptimizedDNSCache) IsCloud(domain string, qType uint16) bool {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return false
	}

	return entry.IsCloud
}

// Set 设置缓存响应
// 注意：云服务的查询结果只缓存标记，不缓存响应内容
func (c *OptimizedDNSCache) Set(domain string, qType uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		key := c.key(domain, qType)
		c.mu.Lock()
		defer c.mu.Unlock()

		// 检查是否需要清理缓存
		if len(c.store) >= c.maxSize {
			c.evictLeastRecentlyUsed()
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := c.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 只存储云服务标记，不存储原始响应内容
		c.store[key] = &CacheEntry{
			Response:         nil,                            // 不缓存原始响应内容
			CloudResponse:    existingCloudResponse,          // 保留已有的云响应或为空
			ExpireAt:         time.Now().Add(24 * time.Hour), // 云服务标记缓存24小时
			IsCloud:          true,
			CloudType:        cType,
			RefreshThreshold: 6 * time.Hour, // 云标记外6小时后刷新
			LastAccess:       time.Now(),
		}
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 计算实际TTL（使用响应中的最小TTL，但不低于默认TTL）
	actualTTL := c.defaultTTL
	if responseCopy != nil && len(responseCopy.Answer) > 0 {
		// 从响应中获取最小的TTL
		var minTTL uint32 = 0
		for _, rr := range responseCopy.Answer {
			if rr.Header().Ttl > 0 {
				if minTTL == 0 || rr.Header().Ttl < minTTL {
					minTTL = rr.Header().Ttl
				}
			}
		}

		// 如果有有效的TTL，则使用它（但不低于默认TTL）
		if minTTL > 0 {
			upstreamTTL := time.Duration(minTTL) * time.Second
			if upstreamTTL > c.defaultTTL {
				actualTTL = upstreamTTL
			}
		}
	}

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 生成缓存键
	key := c.key(domain, qType)

	// 创建缓存条目
	entry := &CacheEntry{
		Response:         responseCopy,
		CloudResponse:    nil,
		ExpireAt:         expireAt,
		IsCloud:          isCloud,
		CloudType:        0,
		RefreshThreshold: refreshThreshold,
		LastAccess:       time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(c.store) >= c.maxSize && c.maxSize > 0 {
		c.evictLeastRecentlyUsed()
	}

	// 存储缓存条目
	c.store[key] = entry
}

// SetWithTTL 设置缓存响应（使用自定义TTL）
func (c *OptimizedDNSCache) SetWithTTL(domain string, qType uint16, response *dns.Msg, isCloud bool, customTTL time.Duration, cloudType ...int) {
	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		key := c.key(domain, qType)
		c.mu.Lock()
		defer c.mu.Unlock()

		// 检查是否需要清理缓存
		if len(c.store) >= c.maxSize {
			c.evictLeastRecentlyUsed()
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := c.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 只存储云服务标记，不存储原始响应内容
		c.store[key] = &CacheEntry{
			Response:         nil,                            // 不缓存原始响应内容
			CloudResponse:    existingCloudResponse,          // 保留已有的云响应或为空
			ExpireAt:         time.Now().Add(24 * time.Hour), // 云服务标记缓存24小时
			IsCloud:          true,
			CloudType:        cType,
			RefreshThreshold: 6 * time.Hour, // 云标记外6小时后刷新
			LastAccess:       time.Now(),
		}
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 使用自定义TTL，但确保不低于默认TTL
	actualTTL := customTTL
	if customTTL < c.defaultTTL {
		actualTTL = c.defaultTTL
	}

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 生成缓存键
	key := c.key(domain, qType)

	// 创建缓存条目
	entry := &CacheEntry{
		Response:         responseCopy,
		CloudResponse:    nil,
		ExpireAt:         expireAt,
		IsCloud:          isCloud,
		CloudType:        0,
		RefreshThreshold: refreshThreshold,
		LastAccess:       time.Now(),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(c.store) >= c.maxSize && c.maxSize > 0 {
		c.evictLeastRecentlyUsed()
	}

	// 存储缓存条目
	c.store[key] = entry
}

// ShouldRefreshWithThreshold 检查是否应该刷新缓存（使用指定的刷新阈值）
func (c *OptimizedDNSCache) ShouldRefreshWithThreshold(domain string, qType uint16, refreshThreshold time.Duration) bool {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return false
	}

	// 计算剩余TTL
	remainingTTL := time.Until(entry.ExpireAt)

	// 如果已经过期或即将过期，不需要刷新
	if remainingTTL <= 0 {
		return false
	}

	// 使用传入的刷新阈值
	shouldRefresh := remainingTTL <= refreshThreshold

	return shouldRefresh
}

// ShouldRefresh 检查是否应该刷新缓存（TTL剩余时间低于刷新阈值）
func (c *OptimizedDNSCache) ShouldRefresh(domain string, qType uint16) bool {
	key := c.key(domain, qType)

	c.mu.RLock()
	entry, exists := c.store[key]
	c.mu.RUnlock()

	if !exists {
		return false
	}

	// 计算剩余TTL
	remainingTTL := time.Until(entry.ExpireAt)

	// 如果已经过期或即将过期，不需要刷新
	if remainingTTL <= 0 {
		return false
	}

	// 使用自定义刷新阈值或动态计算
	var refreshThreshold time.Duration
	if entry.RefreshThreshold > 0 {
		// 使用设置的刷新阈值
		refreshThreshold = entry.RefreshThreshold
	} else {
		// 动态计算：使用条目总生存时间的30%作为刷新阈值
		totalTTL := time.Since(entry.LastAccess.Add(-c.defaultTTL)) // 计算条目的总生存时间
		if totalTTL > 0 {
			refreshThreshold = time.Duration(float64(totalTTL) * 0.3)
		} else {
			// 备用方案：使用默认TTL的30%
			refreshThreshold = time.Duration(float64(c.defaultTTL) * 0.3)
		}
	}

	// 设置最小刷新间隔，避免过于频繁的刷新
	minRefreshInterval := 30 * time.Second
	if refreshThreshold < minRefreshInterval {
		refreshThreshold = minRefreshInterval
	}

	// 如果剩余TTL小于刷新阈值，则需要刷新
	shouldRefresh := remainingTTL <= refreshThreshold

	return shouldRefresh
}

// asyncRefresh 异步刷新缓存（由外部调用）
func (c *OptimizedDNSCache) asyncRefresh(domain string, qType uint16, refreshFn func(string, uint16) (*dns.Msg, error)) {
	// 这个方法由外部的异步刷新机制调用，这里只提供一个接口
}

// evictLeastRecentlyUsed 淘汰最少使用的条目
func (c *OptimizedDNSCache) evictLeastRecentlyUsed() {
	if len(c.store) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// 找到最久未访问的条目
	for key, entry := range c.store {
		if oldestKey == "" || entry.LastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccess
		}
	}

	// 删除最久未访问的条目
	if oldestKey != "" {
		delete(c.store, oldestKey)
	}
}

// Lock 实现互斥锁接口
func (c *OptimizedDNSCache) Lock() {
	c.mu.Lock()
}

// Unlock 实现互斥锁接口
func (c *OptimizedDNSCache) Unlock() {
	c.mu.Unlock()
}

// CleanupExpired 清理过期条目
func (c *OptimizedDNSCache) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		for k, v := range c.store {
			if time.Now().After(v.ExpireAt) {
				delete(c.store, k)
			}
		}
		c.mu.Unlock()
	}
}

// Clear 清空缓存
func (c *OptimizedDNSCache) Clear() {
	c.mu.Lock()
	c.store = make(map[string]*CacheEntry)
	c.mu.Unlock()
}

// Delete 删除指定的缓存条目
func (c *OptimizedDNSCache) Delete(domain string, qType uint16) {
	key := c.key(domain, qType)

	c.mu.Lock()
	delete(c.store, key)
	c.mu.Unlock()
}

// GetExpiringSoonEntries 获取即将过期的缓存条目列表
func (c *OptimizedDNSCache) GetExpiringSoonEntries(refreshThreshold time.Duration) []CacheEntryInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var expiringSoon []CacheEntryInfo
	now := time.Now()

	for key, entry := range c.store {
		// 计算剩余TTL
		remainingTTL := entry.ExpireAt.Sub(now)

		// 如果剩余TTL小于或等于刷新阈值，则添加到列表
		if remainingTTL > 0 && remainingTTL <= refreshThreshold {
			// 解析缓存键获取domain和qtype
			parts := strings.Split(key, "|")
			if len(parts) == 2 {
				domain := parts[0]
				qtypeStr := parts[1]

				// 将qtype字符串转换为uint16
				for qtype, qtypeString := range dns.TypeToString {
					if qtypeString == qtypeStr {
						expiringSoon = append(expiringSoon, CacheEntryInfo{
							Domain:  domain,
							QType:   qtype,
							IsCloud: entry.IsCloud,
						})
						break
					}
				}
			}
		}
	}

	return expiringSoon
}

// ExtendTTL 延长缓存条目的过期时间
func (c *OptimizedDNSCache) ExtendTTL(domain string, qType uint16, duration time.Duration) {
	// 添加空指针检查
	if c == nil {
		return
	}

	key := c.key(domain, qType)

	c.mu.Lock()
	defer c.mu.Unlock()

	if entry, exists := c.store[key]; exists {
		// 检查当前剩余TTL
		remainingTTL := time.Until(entry.ExpireAt)

		// 如果当前剩余TTL已经大于要延长的时间，则不进行延长
		// 这样可以避免频繁刷新导致的过度延长
		if remainingTTL > duration {
			return
		}

		// 延长过期时间，但不超过配置的最大TTL
		newTTL := duration
		if newTTL > c.defaultTTL*2 { // 最多延长到默认TTL的2倍
			newTTL = c.defaultTTL * 2
		}

		entry.ExpireAt = time.Now().Add(newTTL)
		// 更新最后访问时间
		entry.LastAccess = time.Now()
	}
}

// DebugCache 输出缓存内容用于调试
func (c *OptimizedDNSCache) DebugCache() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, _ = range c.store {
		// 仅作为调试接口，实际应用中可能需要记录缓存内容
	}
}

// GetStats 获取缓存统计信息
func (c *OptimizedDNSCache) GetStats(includeEntries bool) *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := &CacheStats{
		Size:    len(c.store),
		MaxSize: c.maxSize,
		Entries: make(map[string]EntryInfo),
	}

	currentTime := time.Now()
	validEntries := 0
	expiredEntries := []string{}

	// 收集所有条目的详细信息
	for key, entry := range c.store {
		isExpired := currentTime.After(entry.ExpireAt)
		if isExpired {
			expiredEntries = append(expiredEntries, key)
		} else {
			validEntries++
		}

		// 解析域名和查询类型
		parts := strings.Split(key, "|")
		domain := "unknown"
		qtype := "unknown"
		if len(parts) >= 2 {
			domain = parts[0]
			qtype = parts[1]
		}

		answerCount := 0
		if entry.Response != nil {
			answerCount = len(entry.Response.Answer)
		} else if entry.CloudResponse != nil {
			answerCount = len(entry.CloudResponse.Answer)
		}

		stats.Entries[key] = EntryInfo{
			Domain:      domain,
			QType:       qtype,
			IsExpired:   isExpired,
			IsCloud:     entry.IsCloud,
			ExpireAt:    entry.ExpireAt,
			LastAccess:  entry.LastAccess,
			AnswerCount: answerCount,
		}
	}

	stats.ValidEntries = validEntries
	stats.ExpiredCount = len(expiredEntries)
	stats.ExpiredEntries = expiredEntries

	// 如果不需要详细条目信息，则清空Entries字段
	if !includeEntries {
		stats.Entries = nil
	}

	return stats
}

// GetHotEntries 获取热点条目（最近访问的条目）
func (c *OptimizedDNSCache) GetHotEntries(limit int) []HotEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 创建临时切片存储所有条目及其访问信息
	allEntries := make([]struct {
		Key        string
		Entry      *CacheEntry
		LastAccess time.Time
	}, 0, len(c.store))

	for key, entry := range c.store {
		allEntries = append(allEntries, struct {
			Key        string
			Entry      *CacheEntry
			LastAccess time.Time
		}{key, entry, entry.LastAccess})
	}

	// 按最后访问时间排序（最新的在前）
	sort.Slice(allEntries, func(i, j int) bool {
		return allEntries[i].LastAccess.After(allEntries[j].LastAccess)
	})

	// 获取前N个热点条目
	hotEntries := make([]HotEntry, 0, limit)
	count := 0
	for _, item := range allEntries {
		if count >= limit {
			break
		}

		parts := strings.Split(item.Key, "|")
		domain := "unknown"
		qtype := "unknown"
		if len(parts) >= 2 {
			domain = parts[0]
			qtype = parts[1]
		}

		hotEntries = append(hotEntries, HotEntry{
			Domain:     domain,
			QType:      qtype,
			LastAccess: item.LastAccess,
		})
		count++
	}

	return hotEntries
}

// CountCachedIPs 统计缓存中的IP数量
func (c *OptimizedDNSCache) CountCachedIPs() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ipCounts := make(map[string]int)
	currentTime := time.Now()

	for _, entry := range c.store {
		// 检查条目是否已过期
		if currentTime.After(entry.ExpireAt) {
			continue // 跳过已过期的条目
		}

		// 检查响应中的IP记录
		var response *dns.Msg
		if entry.IsCloud && entry.CloudResponse != nil {
			response = entry.CloudResponse
		} else if !entry.IsCloud && entry.Response != nil {
			response = entry.Response
		}

		if response != nil {
			for _, rr := range response.Answer {
				switch rr.(type) {
				case *dns.A:
					ipCounts["A"]++
				case *dns.AAAA:
					ipCounts["AAAA"]++
				}
			}
		}
	}

	return ipCounts
}
