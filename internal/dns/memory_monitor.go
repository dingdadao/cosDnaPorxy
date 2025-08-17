package dns

import (
	"runtime"
	"runtime/debug"
	"time"
)

// MemoryStats 内存统计信息
type MemoryStats struct {
	Alloc      uint64  `json:"alloc"`       // 当前分配的内存
	TotalAlloc uint64  `json:"total_alloc"` // 累计分配的内存
	Sys        uint64  `json:"sys"`         // 系统分配的内存
	NumGC      uint32  `json:"num_gc"`      // GC次数
	HeapObjects uint64 `json:"heap_objects"` // 堆对象数量
	TagMapSize int     `json:"tag_map_size"` // 标签map大小
	CacheSize  int64   `json:"cache_size"`   // 缓存大小
}

// GetMemoryStats 获取当前内存统计信息
func (h *Handler) GetMemoryStats() *MemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	TagMapMu.RLock()
	tagMapSize := len(TagMapSimple)
	TagMapMu.RUnlock()
	
	var cacheSize int64
	if h.hotCache != nil {
		stats := h.hotCache.GetStats()
		// 估算缓存大小：每个域名平均1KB
		cacheSize = int64(stats.Size) * 1024
	}
	
	return &MemoryStats{
		Alloc:       m.Alloc,
		TotalAlloc:  m.TotalAlloc,
		Sys:         m.Sys,
		NumGC:       m.NumGC,
		HeapObjects: m.HeapObjects,
		TagMapSize:  tagMapSize,
		CacheSize:   cacheSize,
	}
}

// ForceGC 强制垃圾回收
func (h *Handler) ForceGC() {
	before := h.GetMemoryStats()
	
	// 强制GC
	runtime.GC()
	debug.FreeOSMemory()
	
	after := h.GetMemoryStats()
	
	h.logger.Info("【强制GC】完成 - 释放内存: %d bytes -> %d bytes (减少: %d bytes)",
		before.Alloc, after.Alloc, before.Alloc-after.Alloc)
}

// StartMemoryMonitor 启动内存监控
func (h *Handler) StartMemoryMonitor() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute) // 每分钟检查一次
		defer ticker.Stop()
		
		for range ticker.C {
			stats := h.GetMemoryStats()
			
			// 记录内存使用情况
			h.logger.Info("【内存监控】当前内存使用: %d MB, 标签数量: %d, 缓存大小: %d KB",
				stats.Alloc/(1024*1024), stats.TagMapSize, stats.CacheSize/1024)
			
			// 如果内存使用过高，触发清理
			if stats.Alloc > 500*1024*1024 { // 超过500MB
				h.logger.Warn("【内存监控】内存使用过高，触发清理")
				h.triggerMemoryCleanup()
			}
			
			// 如果标签数量过多，触发标签清理
			if stats.TagMapSize > 100000 { // 超过10万个标签
				h.logger.Warn("【内存监控】标签数量过多，触发标签清理")
				h.cleanupExpiredTags()
			}
		}
	}()
}

// triggerMemoryCleanup 触发内存清理
func (h *Handler) triggerMemoryCleanup() {
	// 清理缓存
	if h.hotCache != nil {
		h.logger.Info("【内存清理】清理热点缓存")
		h.hotCache.Clear()
	}
	
	// 强制GC
	h.ForceGC()
	
	// 清理连接池
	if h.dotPool != nil {
		h.dotPool.Close()
		h.dotPool = NewDoTConnPool()
	}
	
	if h.dohPool != nil {
		h.dohPool.Close()
		h.dohPool = NewDoHConnPool()
	}
} 