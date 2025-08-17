package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// generateCacheKey 生成缓存键 - 只使用域名和查询类型
func (h *Handler) generateCacheKey(req *dns.Msg) string {
	var key strings.Builder
	for _, q := range req.Question {
		key.WriteString(q.Name)
		key.WriteString(fmt.Sprintf(":%d", q.Qtype))
	}
	return key.String()
}

// getCachedResponse 获取缓存的DNS响应
func (h *Handler) getCachedResponse(req *dns.Msg) (*dns.Msg, bool) {
	cacheKey := h.generateCacheKey(req)

	if cached, found := h.hotCache.Get(cacheKey); found {
		if cachedResp, ok := cached.(*dns.Msg); ok {
			h.logger.Debug("缓存命中: %s, Rcode=%d, Answer数=%d", cacheKey, cachedResp.Rcode, len(cachedResp.Answer))
			if cachedResp != nil && len(cachedResp.Answer) > 0 {
				h.metrics.GetCacheHits().WithLabelValues("dns_query").Inc()
				// 创建响应副本以避免并发问题
				resp := cachedResp.Copy()
				resp.Id = req.Id // 保持请求ID一致
				return resp, true
			} else {
				h.logger.Warn("缓存命中但内容无效: %s", cacheKey)
			}
		}
	}

	h.logger.Debug("缓存未命中: %s", cacheKey)
	return nil, false
}

// setCachedResponse 设置DNS响应到缓存
func (h *Handler) setCachedResponse(req *dns.Msg, resp *dns.Msg) {
	if resp == nil {
		return
	}

	cacheKey := h.generateCacheKey(req)
	cacheTTL := h.calculateCacheTTL(resp)

	// 记录缓存详情
	domain := strings.TrimSuffix(req.Question[0].Name, ".")
	qtype := dns.TypeToString[req.Question[0].Qtype]
	
	h.logger.Debug("【缓存设置】域名: %s, 类型: %s, 缓存键: %s", domain, qtype, cacheKey)
	h.logger.Debug("【缓存设置】TTL: %v", cacheTTL)
	
	// 记录响应详情
	if len(resp.Answer) > 0 {
		for i, rr := range resp.Answer {
			h.logger.Debug("【缓存设置】响应记录 %d: %s, TTL: %ds", i+1, rr.String(), rr.Header().Ttl)
		}
	}

	// 使用热点缓存，只保留最热门的域名
	h.hotCache.Set(cacheKey, resp, cacheTTL)
	h.logger.Debug("【缓存设置】缓存已设置: %s, TTL=%v", cacheKey, cacheTTL)

	// 如果启用异步刷新，检查是否需要安排刷新任务
	if h.config.Cache.EnableAsyncRefresh && h.config.Cache.RefreshThreshold > 0 {
		h.logger.Debug("【缓存设置】检查异步刷新: TTL=%v, 刷新阈值=%v", cacheTTL, h.config.Cache.RefreshThreshold)
		h.scheduleAsyncRefresh(req, cacheTTL)
	} else {
		h.logger.Debug("【缓存设置】异步刷新未启用或阈值配置无效")
	}
}

// scheduleAsyncRefresh 安排异步刷新任务
func (h *Handler) scheduleAsyncRefresh(req *dns.Msg, cacheTTL time.Duration) {
	// 计算刷新时间点（TTL剩余时间达到阈值时）
	refreshTime := time.Now().Add(cacheTTL - h.config.Cache.RefreshThreshold)
	
	// 如果刷新时间已经过了，不安排任务
	if refreshTime.Before(time.Now()) {
		return
	}

	// 创建刷新任务
	task := &AsyncRefreshTask{
		Domain:      strings.TrimSuffix(req.Question[0].Name, "."),
		QType:       req.Question[0].Qtype,
		OriginalTTL: cacheTTL,
		ExpireTime:  time.Now().Add(cacheTTL),
		Handler:     h,
	}

	// 增加工作线程计数
	atomic.AddInt32(&h.asyncWorkers, 1)

	// 安排延迟执行
	go func() {
		time.Sleep(time.Until(refreshTime))
		
		// 检查任务是否仍然有效
		select {
		case h.asyncRefreshChan <- task:
			h.logger.Debug("安排异步刷新任务: %s, 刷新时间: %v", task.Domain, refreshTime)
		default:
			// 通道已满，减少计数
			atomic.AddInt32(&h.asyncWorkers, -1)
			h.logger.Warn("异步刷新通道已满，丢弃任务: %s", task.Domain)
		}
	}()
}

// calculateCacheCost 计算缓存成本
func (h *Handler) calculateCacheCost(resp *dns.Msg) int64 {
	if resp == nil {
		return 1
	}
	packed, err := resp.Pack()
	if err != nil {
		return 1
	}
	return int64(len(packed))
}

// calculateCacheTTL 计算缓存TTL
func (h *Handler) calculateCacheTTL(resp *dns.Msg) time.Duration {
	if resp == nil || len(resp.Answer) == 0 {
		// 没有响应或答案，使用配置的最小TTL
		if h.config.Cache.DNSTTLMin > 0 {
			h.logger.Debug("无DNS响应，使用配置的最小TTL: %v", h.config.Cache.DNSTTLMin)
			return h.config.Cache.DNSTTLMin
		}
		return 30 * time.Second // 默认30秒
	}

	// 从DNS响应中提取最小TTL
	var minTTL uint32 = 600 // 默认10分钟
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// 获取配置的TTL范围限制
	var minLimit, maxLimit uint32
	if h.config.Cache.DNSTTLMin > 0 {
		minLimit = uint32(h.config.Cache.DNSTTLMin.Seconds())
	} else {
		minLimit = 30 // 默认30秒
	}
	
	if h.config.Cache.DNSTTLMax > 0 {
		maxLimit = uint32(h.config.Cache.DNSTTLMax.Seconds())
	} else {
		maxLimit = 3600 // 默认1小时
	}

	// 应用TTL范围限制：取DNS TTL与配置范围的交集
	originalTTL := minTTL
	if minTTL < minLimit {
		minTTL = minLimit
		h.logger.Debug("DNS TTL %ds 小于最小限制 %ds，使用最小限制", originalTTL, minLimit)
	} else if minTTL > maxLimit {
		minTTL = maxLimit
		h.logger.Debug("DNS TTL %ds 大于最大限制 %ds，使用最大限制", originalTTL, maxLimit)
	} else {
		h.logger.Debug("DNS TTL %ds 在配置范围内 [%ds, %ds]，使用DNS TTL", originalTTL, minLimit, maxLimit)
	}

	finalTTL := time.Duration(minTTL) * time.Second
	h.logger.Debug("最终缓存TTL: %v (原始DNS TTL: %ds, 配置范围: [%ds, %ds])", 
		finalTTL, originalTTL, minLimit, maxLimit)

	return finalTTL
}

// shouldLogCacheStats 判断是否应该输出缓存统计
func (h *Handler) shouldLogCacheStats() bool {
	// 每1000询输出一次统计
	h.Lock()
	defer h.Unlock()

	// 使用简单的计数器
	if h.cacheStatsCounter == 0 {
		h.cacheStatsCounter = 1000
	}
	h.cacheStatsCounter--

	return h.cacheStatsCounter == 0
}

// logCacheStats 输出缓存统计信息
func (h *Handler) logCacheStats() {
	if h.hotCache == nil {
		return
	}
	
	// 获取热点缓存统计
	stats := h.hotCache.GetStats()
	
	h.logger.Info("【缓存统计】命中率: %0.2f%%, 驱逐: %d, 大小: %d/%d",
		float64(stats.Hits)/float64(stats.Hits+stats.Misses)*100,
		stats.Evictions,
		stats.Size,
		stats.MaxSize)
}

// 添加内存监控和清理机制
func (h *Handler) monitorMemoryUsage() {
	ticker := time.NewTicker(30 * time.Second) // 每30秒检查一次
	defer ticker.Stop()
	
	for range ticker.C {
		// 获取热点缓存统计
		if h.hotCache != nil {
			stats := h.hotCache.GetStats()
			hits := stats.Hits
			misses := stats.Misses
			evicted := stats.Evictions
			
			// 如果驱逐率过高，记录警告
			if hits+misses > 1000 && float64(evicted)/float64(hits+misses) > 0.1 {
				h.logger.Warn("【内存监控】驱逐率过高 (%.2f%%), 缓存可能配置过小", 
					float64(evicted)/float64(hits+misses)*100)
			}
			
			// 记录内存使用情况
			h.logger.Debug("【内存监控】缓存状态: 命中=%d, 未命中=%d, 驱逐=%d, 大小=%d/%d", 
				hits, misses, evicted, stats.Size, stats.MaxSize)
		}
		
		// 检查标签系统内存使用
		TagMapMu.RLock()
		tagMapSize := len(TagMapSimple)
		TagMapMu.RUnlock()
		
		if tagMapSize > 50000 { // 如果标签超过5万个，记录警告
			h.logger.Warn("【内存监控】标签系统内存使用过高: %d 个域名", tagMapSize)
		}
		
		// 检查真实内存使用情况
		h.checkRealMemoryUsage()
	}
}

// 检查真实内存使用情况
func (h *Handler) checkRealMemoryUsage() {
	// 获取当前进程的内存使用
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	// 计算内存使用率
	memoryUsageMB := m.Alloc / 1024 / 1024
	memoryLimitMB := int64(0)
	
	// 从配置文件获取内存限制
	if h.config.Cache.MaxSize != "" {
		if size, err := parseCacheSize(h.config.Cache.MaxSize); err == nil {
			memoryLimitMB = size / 1024 / 1024
		}
	}
	
	// 如果内存使用超过限制的80%，强制清理
	if memoryLimitMB > 0 && memoryUsageMB > memoryLimitMB*80/100 {
		h.logger.Warn("【内存监控】内存使用过高: %d MB (限制: %d MB), 执行强制清理", 
			memoryUsageMB, memoryLimitMB)
		
		// 强制清理缓存
		if h.hotCache != nil {
			h.hotCache.Clear()
		}
		
		// 清理标签系统
		h.cleanupExpiredTags()
		
		// 强制GC
		runtime.GC()
		
		h.logger.Info("【内存监控】强制清理完成")
	}
	
	// 记录内存使用情况
	h.logger.Debug("【内存监控】当前内存使用: %d MB, 堆内存: %d MB, GC次数: %d", 
		memoryUsageMB, m.HeapAlloc/1024/1024, m.NumGC)
}

// parseCacheSize 解析缓存大小配置，如 "50MB" -> 50*1024*1024
func parseCacheSize(sizeStr string) (int64, error) {
	// 这里简化处理，实际可以根据需要支持更多单位
	if len(sizeStr) < 2 {
		return 0, fmt.Errorf("invalid cache size format")
	}
	
	unit := sizeStr[len(sizeStr)-2:]
	valueStr := sizeStr[:len(sizeStr)-2]
	
	var multiplier int64
	switch unit {
	case "MB":
		multiplier = 1024 * 1024
	case "KB":
		multiplier = 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unsupported unit: %s", unit)
	}
	
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, err
	}
	
	return value * multiplier, nil
}

// 添加主动缓存清理机制
func (h *Handler) aggressiveCacheCleanup() {
	ticker := time.NewTicker(1 * time.Minute) // 每1分钟清理一次，更频繁
	defer ticker.Stop()
	
	for range ticker.C {
		if h.hotCache != nil {
			// 清理过期数据
			expiredCount := h.hotCache.CleanupExpired()
			if expiredCount > 0 {
				h.logger.Info("【主动清理】清理了 %d 个过期缓存项", expiredCount)
			}
			
			// 获取当前缓存统计
			stats := h.hotCache.GetStats()
			
			// 如果命中率过低，清理缓存
			total := stats.Hits + stats.Misses
			if total > 1000 && float64(stats.Hits)/float64(total) < 0.3 {
				h.logger.Info("【主动清理】缓存命中率过低 (%.2f%%), 执行清理", 
					float64(stats.Hits)/float64(total)*100)
				h.hotCache.Clear()
			}
			
			// 如果缓存大小超过限制的80%，强制清理
			if stats.Size > int(float64(stats.MaxSize)*0.8) {
				h.logger.Warn("【主动清理】缓存大小超过限制的80%% (%d/%d), 执行清理", 
					stats.Size, stats.MaxSize)
				h.hotCache.Clear()
			}
		}
		
		// 清理过期的标签数据
		h.cleanupExpiredTags()
		
		// 强制GC，释放内存
		runtime.GC()
	}
}

// 清理过期的标签数据
func (h *Handler) cleanupExpiredTags() {
	TagMapMu.Lock()
	defer TagMapMu.Unlock()
	
	now := time.Now().Unix()
	expiredCount := 0
	maxAge := int64(24 * 3600) // 24小时
	
	for domain, tag := range TagMapSimple {
		if now-tag.Updated > maxAge {
			delete(TagMapSimple, domain)
			delete(TagDirtySimple, domain)
			expiredCount++
		}
	}
	
	if expiredCount > 0 {
		h.logger.Info("【标签清理】清理了 %d 个过期标签", expiredCount)
	}
}

// 手动清理缓存 - 供外部调用
func (h *Handler) ClearCache() {
	if h.hotCache != nil {
		h.logger.Info("【手动清理】执行手动缓存清理")
		h.hotCache.Clear()
		h.logger.Info("【手动清理】缓存清理完成")
	}
}

// 获取缓存统计信息
func (h *Handler) GetCacheStats() map[string]interface{} {
	if h.hotCache == nil {
		return map[string]interface{}{
			"error": "缓存未初始化",
		}
	}
	
	stats := h.hotCache.GetStats()
	total := stats.Hits + stats.Misses
	hitRate := 0.0
	if total > 0 {
		hitRate = float64(stats.Hits) / float64(total) * 100
	}
	
	return map[string]interface{}{
		"hits":           stats.Hits,
		"misses":         stats.Misses,
		"evicted":        stats.Evictions,
		"size":           stats.Size,
		"max_size":       stats.MaxSize,
		"hit_rate":       hitRate,
		"total_queries":  total,
	}
} 