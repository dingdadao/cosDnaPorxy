package dns

import (
	"container/heap"
	"sync"
	"time"
)

// HotDomain 热点域名结构
type HotDomain struct {
	Domain     string        // 域名
	HitCount   int64         // 命中次数
	LastAccess time.Time     // 最后访问时间
	TTL        time.Duration // 缓存TTL
	Data       interface{}   // 缓存的数据
	index      int           // 堆中的索引位置
}

// HotCache 热点域名缓存池
type HotCache struct {
	mu          sync.RWMutex
	maxSize     int                    // 最大缓存项数
	domains     map[string]*HotDomain  // 域名到热点数据的映射
	hotHeap     *HotDomainHeap         // 最小堆，用于快速找到最冷的数据
	stats       *CacheStats            // 缓存统计
}

// CacheStats 缓存统计
type CacheStats struct {
	Hits        int64 `json:"hits"`        // 命中次数
	Misses      int64 `json:"misses"`      // 未命中次数
	Evictions   int64 `json:"evictions"`   // 驱逐次数
	Size        int   `json:"size"`        // 当前大小
	MaxSize     int   `json:"max_size"`    // 最大大小
}

// NewHotCache 创建新的热点缓存
func NewHotCache(maxSize int) *HotCache {
	if maxSize <= 0 {
		maxSize = 10000 // 默认1万个域名
	}
	
	cache := &HotCache{
		maxSize: maxSize,
		domains: make(map[string]*HotDomain),
		hotHeap: &HotDomainHeap{},
		stats:   &CacheStats{MaxSize: maxSize},
	}
	
	heap.Init(cache.hotHeap)
	return cache
}

// Get 获取缓存数据
func (c *HotCache) Get(domain string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if domain == "" {
		return nil, false
	}
	
	// 查找域名
	hotDomain, exists := c.domains[domain]
	if !exists {
		c.stats.Misses++
		return nil, false
	}
	
	// 检查是否过期
	if time.Now().After(hotDomain.LastAccess.Add(hotDomain.TTL)) {
		// 过期，从缓存中移除
		delete(c.domains, domain)
		c.stats.Misses++
		return nil, false
	}
	
	// 更新访问信息
	hotDomain.HitCount++
	hotDomain.LastAccess = time.Now()
	
	// 更新堆中的位置
	heap.Fix(c.hotHeap, hotDomain.index)
	
	c.stats.Hits++
	return hotDomain.Data, true
}

// Set 设置缓存数据
func (c *HotCache) Set(domain string, data interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if domain == "" || data == nil {
		return
	}
	
	// 如果域名已存在，更新数据
	if existing, exists := c.domains[domain]; exists {
		existing.Data = data
		existing.TTL = ttl
		existing.LastAccess = time.Now()
		existing.HitCount++
		heap.Fix(c.hotHeap, existing.index)
		return
	}
	
	// 如果缓存已满，驱逐最冷的数据
	if len(c.domains) >= c.maxSize {
		c.evictColdest()
	}
	
	// 创建新的热点域名
	hotDomain := &HotDomain{
		Domain:     domain,
		HitCount:   1,
		LastAccess: time.Now(),
		TTL:        ttl,
		Data:       data,
	}
	
	// 添加到缓存和堆
	c.domains[domain] = hotDomain
	heap.Push(c.hotHeap, hotDomain)
	
	c.stats.Size = len(c.domains)
}

// evictColdest 驱逐最冷的数据
func (c *HotCache) evictColdest() {
	if c.hotHeap.Len() == 0 {
		return
	}
	
	// 从堆顶取出最冷的数据
	coldest := heap.Pop(c.hotHeap).(*HotDomain)
	delete(c.domains, coldest.Domain)
	c.stats.Evictions++
	c.stats.Size = len(c.domains)
}

// Remove 移除指定域名
func (c *HotCache) Remove(domain string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if hotDomain, exists := c.domains[domain]; exists {
		heap.Remove(c.hotHeap, hotDomain.index)
		delete(c.domains, domain)
		c.stats.Size = len(c.domains)
	}
}

// Clear 清空缓存
func (c *HotCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.domains = make(map[string]*HotDomain)
	c.hotHeap = &HotDomainHeap{}
	heap.Init(c.hotHeap)
	c.stats.Size = 0
}

// GetStats 获取缓存统计
func (c *HotCache) GetStats() *CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	stats := *c.stats
	return &stats
}

// GetTopDomains 获取最热门的域名列表
func (c *HotCache) GetTopDomains(limit int) []*HotDomain {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	if limit <= 0 || limit > len(c.domains) {
		limit = len(c.domains)
	}
	
	// 按命中次数排序
	domains := make([]*HotDomain, 0, len(c.domains))
	for _, domain := range c.domains {
		domains = append(domains, domain)
	}
	
	// 简单的排序（实际项目中可以用更高效的排序）
	for i := 0; i < len(domains)-1; i++ {
		for j := i + 1; j < len(domains); j++ {
			if domains[i].HitCount < domains[j].HitCount {
				domains[i], domains[j] = domains[j], domains[i]
			}
		}
	}
	
	return domains[:limit]
}

// CleanupExpired 清理过期数据
func (c *HotCache) CleanupExpired() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for domain, hotDomain := range c.domains {
		if now.After(hotDomain.LastAccess.Add(hotDomain.TTL)) {
			heap.Remove(c.hotHeap, hotDomain.index)
			delete(c.domains, domain)
			expiredCount++
		}
	}
	
	c.stats.Size = len(c.domains)
	return expiredCount
}

// ===== 最小堆实现 =====

// HotDomainHeap 最小堆，用于快速找到最冷的数据
type HotDomainHeap []*HotDomain

func (h HotDomainHeap) Len() int { return len(h) }

func (h HotDomainHeap) Less(i, j int) bool {
	// 优先按命中次数排序，其次按最后访问时间
	if h[i].HitCount != h[j].HitCount {
		return h[i].HitCount < h[j].HitCount
	}
	return h[i].LastAccess.Before(h[j].LastAccess)
}

func (h HotDomainHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}

func (h *HotDomainHeap) Push(x interface{}) {
	n := len(*h)
	item := x.(*HotDomain)
	item.index = n
	*h = append(*h, item)
}

func (h *HotDomainHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // 避免内存泄漏
	item.index = -1 // 标记为已移除
	*h = old[0 : n-1]
	return item
} 