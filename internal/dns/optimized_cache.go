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
	StoredAt         time.Time     // 写入缓存的时间，用于命中时递减TTL（RFC 1035 §4.3.1）
	IsCloud          bool          // 标记是否为云服务域名
	CloudType        int           // 云服务类型（0-无，1-Cloudflare，2-AWS）
	CloudResponse    *dns.Msg      // 云域名的替换响应缓存
	RefreshThreshold time.Duration // 异步刷新阈值
	LastAccess       time.Time
}

// CacheShard 缓存分片
type CacheShard struct {
	mu          sync.RWMutex
	store       map[string]*CacheEntry
	flightGroup singleflight.Group
}

// CacheEntryPool CacheEntry对象池
type CacheEntryPool struct {
	pool sync.Pool
}

// NewCacheEntryPool 创建CacheEntry对象池
func NewCacheEntryPool() *CacheEntryPool {
	return &CacheEntryPool{
		pool: sync.Pool{
			New: func() interface{} {
				return &CacheEntry{}
			},
		},
	}
}

// Get 从对象池获取CacheEntry
func (p *CacheEntryPool) Get() *CacheEntry {
	return p.pool.Get().(*CacheEntry)
}

// Put 将CacheEntry放回对象池
func (p *CacheEntryPool) Put(entry *CacheEntry) {
	// 重置字段
	entry.Response = nil
	entry.CloudResponse = nil
	entry.ExpireAt = time.Time{}
	entry.StoredAt = time.Time{}
	entry.IsCloud = false
	entry.CloudType = 0
	entry.RefreshThreshold = 0
	entry.LastAccess = time.Time{}
	p.pool.Put(entry)
}

// OptimizedDNSCache 优化的DNS缓存系统
type OptimizedDNSCache struct {
	shards     []*CacheShard
	shardCount int
	maxSize    int
	defaultTTL time.Duration
	entryPool  *CacheEntryPool
}

// NewOptimizedDNSCache 创建一个新的优化DNS缓存系统
func NewOptimizedDNSCache(maxSize int, defaultTTL time.Duration) *OptimizedDNSCache {
	// 确定分片数量，根据CPU核心数或固定值
	shardCount := 16
	if shardCount <= 0 {
		shardCount = 8 // 默认8个分片
	}

	shards := make([]*CacheShard, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = &CacheShard{
			store:       make(map[string]*CacheEntry),
			flightGroup: singleflight.Group{},
		}
	}

	cache := &OptimizedDNSCache{
		shards:     shards,
		shardCount: shardCount,
		maxSize:    maxSize,
		defaultTTL: defaultTTL,
		entryPool:  NewCacheEntryPool(),
	}

	// 启动后台清理协程
	go cache.cleanupRoutine()

	return cache
}

// key 生成缓存键
func (c *OptimizedDNSCache) key(domain string, qType uint16) string {
	return domain + "|" + dns.TypeToString[qType]
}

// getShard 根据键获取对应的缓存分片
func (c *OptimizedDNSCache) getShard(key string) *CacheShard {
	// 使用简单的哈希函数将键映射到分片
	hash := 0
	for i := 0; i < len(key); i++ {
		hash = (hash << 5) - hash + int(key[i])
	}
	if hash < 0 {
		hash = -hash
	}
	return c.shards[hash%c.shardCount]
}

// decrementTTLs 按缓存时长递减响应中所有RR的TTL（下限0），跳过OPT记录
// 符合 RFC 1035 §4.3.1：TTL表示剩余生存时间，缓存返回时必须按 now - storedAt 递减
func decrementTTLs(msg *dns.Msg, elapsed time.Duration) {
	if msg == nil || elapsed <= 0 {
		return
	}
	secs := uint32(elapsed.Seconds())
	if secs == 0 {
		return
	}
	dec := func(rrs []dns.RR) {
		for _, rr := range rrs {
			if _, isOPT := rr.(*dns.OPT); isOPT {
				continue // OPT的TTL字段是扩展rcode/flags，不能递减
			}
			h := rr.Header()
			if h.Ttl <= secs {
				h.Ttl = 0
			} else {
				h.Ttl -= secs
			}
		}
	}
	dec(msg.Answer)
	dec(msg.Ns)
	dec(msg.Extra)
}

// GetCloudResponse 获取云域名的替换响应缓存
func (c *OptimizedDNSCache) GetCloudResponse(domain string, qType uint16) (*dns.Msg, bool, int) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists || !entry.IsCloud {
		return nil, false, 0
	}

	// 检查是否过期
	if time.Now().After(entry.ExpireAt) {
		// 异步删除过期条目
		go func() {
			shard.mu.Lock()
			delete(shard.store, key)
			shard.mu.Unlock()
		}()
		return nil, false, 0
	}

	// 更新最后访问时间
	shard.mu.Lock()
	entry.LastAccess = time.Now()
	shard.mu.Unlock()

	// 返回云响应缓存（副本，递减TTL）
	if entry.CloudResponse != nil {
		resp := entry.CloudResponse.Copy()
		decrementTTLs(resp, time.Since(entry.StoredAt))
		return resp, true, entry.CloudType
	}
	return nil, false, entry.CloudType
}

// SetCloudResponse 设置云域名的替换响应缓存
func (c *OptimizedDNSCache) SetCloudResponse(domain string, qType uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	// 使用自定义TTL或默认TTL
	ttl := c.defaultTTL
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	}

	// 计算刷新阈值（TTL的30%）
	refreshThreshold := time.Duration(float64(ttl) * 0.3)

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.Response = nil // 不缓存原始响应
	entry.CloudResponse = response.Copy()
	entry.ExpireAt = time.Now().Add(ttl)
	entry.StoredAt = time.Now()
	entry.IsCloud = true
	entry.CloudType = cloudType
	entry.RefreshThreshold = refreshThreshold
	entry.LastAccess = time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查是否需要清理缓存
	if len(shard.store) >= c.maxSize/c.shardCount {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储云域名缓存
	shard.store[key] = entry
}

// Get 获取缓存响应
func (c *OptimizedDNSCache) Get(domain string, qType uint16) (*dns.Msg, bool, bool, int) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return nil, false, false, 0
	}

	// 检查是否过期
	isExpired := time.Now().After(entry.ExpireAt)
	if isExpired {
		// 检查是否为失败响应（如NXDOMAIN）且已过期，如果是则立即删除并返回未命中
		if !entry.IsCloud && entry.Response != nil && entry.Response.Rcode != dns.RcodeSuccess {
			// 失败响应已过期，立即删除缓存项并返回未命中
			shard.mu.Lock()
			delete(shard.store, key)
			shard.mu.Unlock()
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
			shard.mu.Lock()
			entry.LastAccess = time.Now()
			shard.mu.Unlock()
			return resp, true, true, entry.CloudType
		} else if !entry.IsCloud && entry.Response != nil {
			// 普通域名响应
			resp := entry.Response.Copy()
			c.adjustExpiredResponseTTL(resp, 5*time.Second) // 设置较小的TTL给客户端
			// 不删除缓存项，而是更新访问时间
			shard.mu.Lock()
			entry.LastAccess = time.Now()
			shard.mu.Unlock()
			return resp, true, false, 0
		}
		return nil, true, entry.IsCloud, entry.CloudType
	}

	// 更新最后访问时间（用于LRU淘汰策略）
	shard.mu.Lock()
	entry.LastAccess = time.Now()
	storedAt := entry.StoredAt
	shard.mu.Unlock()

	// 命中统一返回副本并按缓存时长递减TTL，避免共享对象竞争（调用方无需再Copy）
	if entry.IsCloud {
		if entry.CloudResponse != nil {
			resp := entry.CloudResponse.Copy()
			decrementTTLs(resp, time.Since(storedAt))
			return resp, true, true, entry.CloudType
		}
		return nil, true, true, entry.CloudType
	}

	resp := entry.Response.Copy()
	decrementTTLs(resp, time.Since(storedAt))
	return resp, true, false, 0
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
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return nil, false, false, 0
	}

	// 检查是否过期
	isExpired := time.Now().After(entry.ExpireAt)
	if isExpired {
		// 检查是否为失败响应（如NXDOMAIN）且已过期，如果是则立即删除并返回未命中
		if !entry.IsCloud && entry.Response != nil && entry.Response.Rcode != dns.RcodeSuccess {
			// 失败响应已过期，立即删除缓存项并返回未命中
			shard.mu.Lock()
			delete(shard.store, key)
			shard.mu.Unlock()
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
		shard.mu.Lock()
		entry.LastAccess = time.Now()
		shard.mu.Unlock()

		// 返回过期的响应，但通过单飞行模式触发后台刷新
		if hit {
			return resp, true, isCloudResult, cloudType
		}
		return nil, true, entry.IsCloud, entry.CloudType
	}

	// 更新最后访问时间（用于LRU淘汰策略）
	shard.mu.Lock()
	entry.LastAccess = time.Now()
	storedAt := entry.StoredAt
	shard.mu.Unlock()

	// 命中统一返回副本并按缓存时长递减TTL，避免共享对象竞争（调用方无需再Copy）
	if entry.IsCloud {
		if entry.CloudResponse != nil {
			resp := entry.CloudResponse.Copy()
			decrementTTLs(resp, time.Since(storedAt))
			return resp, true, true, entry.CloudType
		}
		return nil, true, true, entry.CloudType
	}

	resp := entry.Response.Copy()
	decrementTTLs(resp, time.Since(storedAt))
	return resp, true, false, 0
}

// adjustExpiredResponseTTL 调整过期响应的TTL值
// 仅调整Answer段：Ns/Extra段可能包含OPT等记录，其TTL字段并非生存时间
func (c *OptimizedDNSCache) adjustExpiredResponseTTL(resp *dns.Msg, newTTL time.Duration) {
	if resp == nil {
		return
	}

	newTTLValue := uint32(newTTL.Seconds())
	for _, rr := range resp.Answer {
		rr.Header().Ttl = newTTLValue
	}
}

// GetExpireTime 获取缓存条目的过期时间
func (c *OptimizedDNSCache) GetExpireTime(domain string, qType uint16) time.Time {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	defer shard.mu.RUnlock()

	entry, exists := shard.store[key]
	if !exists {
		return time.Time{} // 返回零时间
	}

	return entry.ExpireAt
}

// IsCloud 检查域名是否为云服务域名（即使缓存已过期）
func (c *OptimizedDNSCache) IsCloud(domain string, qType uint16) bool {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

	if !exists {
		return false
	}

	return entry.IsCloud
}

// Set 设置缓存响应
// 注意：云服务的查询结果只缓存标记，不缓存响应内容
func (c *OptimizedDNSCache) Set(domain string, qType uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		shard.mu.Lock()
		defer shard.mu.Unlock()

		// 检查是否需要清理缓存
		if len(shard.store) >= c.maxSize/c.shardCount {
			c.evictLeastRecentlyUsed(shard)
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := shard.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 从对象池获取CacheEntry
		entry := c.entryPool.Get()
		// 只存储云服务标记，不存储原始响应内容
		entry.Response = nil                            // 不缓存原始响应内容
		entry.CloudResponse = existingCloudResponse     // 保留已有的云响应或为空
		entry.ExpireAt = time.Now().Add(24 * time.Hour) // 云服务标记缓存24小时
		entry.StoredAt = time.Now()
		entry.IsCloud = true
		entry.CloudType = cType
		entry.RefreshThreshold = 6 * time.Hour // 云标记外6小时后刷新
		entry.LastAccess = time.Now()

		// 存储缓存条目
		shard.store[key] = entry
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 计算实际TTL：遵循上游响应中的最小TTL，绝不抬高；无有效TTL时用默认TTL兜底
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

		// 如果有有效的TTL，直接使用上游TTL
		if minTTL > 0 {
			actualTTL = time.Duration(minTTL) * time.Second
		}
	}

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.Response = responseCopy
	entry.CloudResponse = nil
	entry.ExpireAt = expireAt
	entry.StoredAt = time.Now()
	entry.IsCloud = isCloud
	entry.CloudType = 0
	entry.RefreshThreshold = refreshThreshold
	entry.LastAccess = time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(shard.store) >= c.maxSize/c.shardCount && c.maxSize > 0 {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储缓存条目
	shard.store[key] = entry
}

// SetWithTTL 设置缓存响应（使用自定义TTL）
func (c *OptimizedDNSCache) SetWithTTL(domain string, qType uint16, response *dns.Msg, isCloud bool, customTTL time.Duration, cloudType ...int) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	// 如果是云服务域名，只缓存标记，不缓存响应内容
	if isCloud {
		shard.mu.Lock()
		defer shard.mu.Unlock()

		// 检查是否需要清理缓存
		if len(shard.store) >= c.maxSize/c.shardCount {
			c.evictLeastRecentlyUsed(shard)
		}

		// 获取云服务类型
		var cType int
		if len(cloudType) > 0 {
			cType = cloudType[0]
		}

		// 检查是否已经存在云标记，如果存在则保留CloudResponse
		var existingCloudResponse *dns.Msg
		if existingEntry, exists := shard.store[key]; exists && existingEntry.IsCloud {
			existingCloudResponse = existingEntry.CloudResponse
		}

		// 从对象池获取CacheEntry
		entry := c.entryPool.Get()
		// 只存储云服务标记，不存储原始响应内容
		entry.Response = nil                            // 不缓存原始响应内容
		entry.CloudResponse = existingCloudResponse     // 保留已有的云响应或为空
		entry.ExpireAt = time.Now().Add(24 * time.Hour) // 云服务标记缓存24小时
		entry.StoredAt = time.Now()
		entry.IsCloud = true
		entry.CloudType = cType
		entry.RefreshThreshold = 6 * time.Hour // 云标记外6小时后刷新
		entry.LastAccess = time.Now()

		// 存储缓存条目
		shard.store[key] = entry
		return
	}

	// 普通域名缓存处理
	if response == nil {
		return
	}

	// 深拷贝响应对象
	responseCopy := response.Copy()

	// 使用调用方给定的TTL（如负缓存TTL），绝不抬高
	actualTTL := customTTL

	// 计算过期时间和刷新阈值
	expireAt := time.Now().Add(actualTTL)
	refreshThreshold := time.Duration(float64(actualTTL) * 0.3) // 30%作为刷新阈值

	// 从对象池获取CacheEntry
	entry := c.entryPool.Get()
	entry.Response = responseCopy
	entry.CloudResponse = nil
	entry.ExpireAt = expireAt
	entry.StoredAt = time.Now()
	entry.IsCloud = isCloud
	entry.CloudType = 0
	entry.RefreshThreshold = refreshThreshold
	entry.LastAccess = time.Now()

	shard.mu.Lock()
	defer shard.mu.Unlock()

	// 检查容量，如果达到上限，删除最少访问的条目
	if len(shard.store) >= c.maxSize/c.shardCount && c.maxSize > 0 {
		c.evictLeastRecentlyUsed(shard)
	}

	// 存储缓存条目
	shard.store[key] = entry
}

// ShouldRefreshWithThreshold 检查是否应该刷新缓存（使用指定的刷新阈值）
func (c *OptimizedDNSCache) ShouldRefreshWithThreshold(domain string, qType uint16, refreshThreshold time.Duration) bool {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

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
	shard := c.getShard(key)

	shard.mu.RLock()
	entry, exists := shard.store[key]
	shard.mu.RUnlock()

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
func (c *OptimizedDNSCache) evictLeastRecentlyUsed(shard *CacheShard) {
	if len(shard.store) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// 找到最久未访问的条目
	for key, entry := range shard.store {
		if oldestKey == "" || entry.LastAccess.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.LastAccess
		}
	}

	// 删除最久未访问的条目
	if oldestKey != "" {
		// 先获取条目，然后删除，最后放回对象池
		entry := shard.store[oldestKey]
		delete(shard.store, oldestKey)
		// 将条目放回对象池
		c.entryPool.Put(entry)
	}
}

// Lock 实现互斥锁接口（空实现，因为我们使用分片锁）
func (c *OptimizedDNSCache) Lock() {
	// 由于使用了分片锁，这里不需要全局锁
}

// Unlock 实现互斥锁接口（空实现，因为我们使用分片锁）
func (c *OptimizedDNSCache) Unlock() {
	// 由于使用了分片锁，这里不需要全局锁
}

// CleanupExpired 清理过期条目
func (c *OptimizedDNSCache) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		// 遍历所有分片
		for _, shard := range c.shards {
			shard.mu.Lock()
			for k, v := range shard.store {
				if time.Now().After(v.ExpireAt) {
					// 删除过期条目并放回对象池
					delete(shard.store, k)
					c.entryPool.Put(v)
				}
			}
			shard.mu.Unlock()
		}
	}
}

// Clear 清空缓存
func (c *OptimizedDNSCache) Clear() {
	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.Lock()
		// 清空缓存并将所有条目放回对象池
		for _, entry := range shard.store {
			c.entryPool.Put(entry)
		}
		shard.store = make(map[string]*CacheEntry)
		shard.mu.Unlock()
	}
}

// Delete 删除指定的缓存条目
func (c *OptimizedDNSCache) Delete(domain string, qType uint16) {
	key := c.key(domain, qType)
	shard := c.getShard(key)

	shard.mu.Lock()
	if entry, exists := shard.store[key]; exists {
		delete(shard.store, key)
		// 将删除的条目放回对象池
		c.entryPool.Put(entry)
	}
	shard.mu.Unlock()
}

// GetExpiringSoonEntries 获取即将过期的缓存条目列表
func (c *OptimizedDNSCache) GetExpiringSoonEntries(refreshThreshold time.Duration) []CacheEntryInfo {
	var expiringSoon []CacheEntryInfo
	now := time.Now()

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
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
		shard.mu.RUnlock()
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
	shard := c.getShard(key)

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if entry, exists := shard.store[key]; exists {
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
	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for _, _ = range shard.store {
			// 仅作为调试接口，实际应用中可能需要记录缓存内容
		}
		shard.mu.RUnlock()
	}
}

// GetStats 获取缓存统计信息
func (c *OptimizedDNSCache) GetStats(includeEntries bool) *CacheStats {
	stats := &CacheStats{
		Size:    0,
		MaxSize: c.maxSize,
		Entries: make(map[string]EntryInfo),
	}

	currentTime := time.Now()
	validEntries := 0
	expiredEntries := []string{}

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
			stats.Size++
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

			if includeEntries {
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
		}
		shard.mu.RUnlock()
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
	// 创建临时切片存储所有条目及其访问信息
	allEntries := make([]struct {
		Key        string
		Entry      *CacheEntry
		LastAccess time.Time
	}, 0, c.maxSize)

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for key, entry := range shard.store {
			allEntries = append(allEntries, struct {
				Key        string
				Entry      *CacheEntry
				LastAccess time.Time
			}{key, entry, entry.LastAccess})
		}
		shard.mu.RUnlock()
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
	ipCounts := make(map[string]int)
	currentTime := time.Now()

	// 遍历所有分片
	for _, shard := range c.shards {
		shard.mu.RLock()
		for _, entry := range shard.store {
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
		shard.mu.RUnlock()
	}

	return ipCounts
}
