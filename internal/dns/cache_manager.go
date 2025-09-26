package dns

import (
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// CacheManager 缓存管理器
type CacheManager struct {
	cache  *OptimizedDNSCache
	config *config.Config
	logger *utils.EnhancedLogger

	// 异步刷新相关
	asyncChan  chan *AsyncRefreshTask
	asyncSet   map[string]struct{}
	asyncMu    sync.RWMutex
	workerPool *AsyncWorkerPool

	// 刷新回调
	refreshCallback RefreshCallback
}

// AsyncRefreshTask 异步刷新任务
type AsyncRefreshTask struct {
	Domain     string
	QType      uint16
	ExpireTime time.Time
	Priority   int // 优先级：0-正常，1-高优先级
}

// AsyncWorkerPool 异步工作池
type AsyncWorkerPool struct {
	workers int
	stopCh  chan struct{}
	stopped bool
	mu      sync.Mutex
}

// NewCacheManager 创建缓存管理器
func NewCacheManager(cfg *config.Config, logger *utils.EnhancedLogger, metrics interface{}) *CacheManager {
	cm := &CacheManager{
		cache:     NewOptimizedDNSCache(cfg.Cache.MaxItems, cfg.Cache.TTL),
		config:    cfg,
		logger:    logger,
		asyncChan: make(chan *AsyncRefreshTask, 1000),
		asyncSet:  make(map[string]struct{}),
		workerPool: &AsyncWorkerPool{
			workers: cfg.Cache.MaxAsyncWorkers,
			stopCh:  make(chan struct{}),
		},
	}

	// 启动异步工作池
	cm.startAsyncWorkers()

	// 启动定期缓存扫描任务
	if cfg.Cache.EnableAsyncRefresh {
		go cm.startCacheScanTask()
	}

	logger.Info("🗄️ 缓存管理器初始化完成", map[string]interface{}{
		"max_items":     cfg.Cache.MaxItems,
		"ttl":           cfg.Cache.TTL.String(),
		"async_workers": cfg.Cache.MaxAsyncWorkers,
		"async_refresh": cfg.Cache.EnableAsyncRefresh,
	})

	return cm
}

// Get 获取缓存
func (cm *CacheManager) Get(domain string, qtype uint16) (*dns.Msg, bool, bool, int) {
	timer := cm.logger.StartTimer("cache_get", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})
	defer timer.End()

	resp, hit, isCloud, cloudType := cm.cache.Get(domain, qtype)

	if hit {
		cm.logger.Debug("💾 缓存命中详细信息", map[string]interface{}{
			"domain":   domain,
			"qtype":    dns.TypeToString[qtype],
			"is_cloud": isCloud,
			"hit_type": "normal_cache",
		})

		// 移除此处的异步刷新检查，由定时扫描任务处理
		// if cm.config.Cache.EnableAsyncRefresh && cm.shouldRefresh(domain, qtype) {
		//     cm.submitAsyncRefresh(domain, qtype, time.Now().Add(cm.config.Cache.TTL), 0)
		// }
	} else {
		cm.logger.Debug("🔍 缓存未命中详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": "cache_miss",
		})
	}

	return resp, hit, isCloud, cloudType
}

// GetCloudResponse 获取云域名的替换响应缓存
func (cm *CacheManager) GetCloudResponse(domain string, qtype uint16) (*dns.Msg, bool, int) {
	timer := cm.logger.StartTimer("cache_get_cloud", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})
	defer timer.End()

	resp, hit, cloudType := cm.cache.GetCloudResponse(domain, qtype)

	if hit {
		cm.logger.Debug("☁️ 云响应缓存命中详细信息", map[string]interface{}{
			"domain":     domain,
			"qtype":      dns.TypeToString[qtype],
			"cloud_type": cloudType,
			"hit_type":   "cloud_response_cache",
		})

		// 移除此处的异步刷新检查，由定时扫描任务处理
		// if cm.config.Cache.EnableAsyncRefresh && cm.shouldRefresh(domain, qtype) {
		//     cm.submitAsyncRefresh(domain, qtype, time.Now().Add(cm.config.Cache.TTL), 1)
		// }
	} else {
		cm.logger.Debug("☁️ 云响应缓存未命中详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": "cloud_response_cache_miss",
		})
	}

	return resp, hit, cloudType
}

// SetCloudResponse 设置云域名的替换响应缓存
func (cm *CacheManager) SetCloudResponse(domain string, qtype uint16, response *dns.Msg, cloudType int, customTTL ...time.Duration) {
	timer := cm.logger.StartTimer("cache_set_cloud", map[string]interface{}{
		"domain":     domain,
		"qtype":      dns.TypeToString[qtype],
		"cloud_type": cloudType,
	})
	defer timer.End()

	if response == nil {
		cm.logger.Warn("尝试缓存空的云响应", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	// 使用自定义TTL或默认TTL
	var ttl time.Duration
	if len(customTTL) > 0 {
		ttl = customTTL[0]
	} else {
		ttl = cm.calculateTTL(response)
	}

	cm.cache.SetCloudResponse(domain, qtype, response, cloudType, ttl)

	cm.logger.Info("📋 [缓存设置-云响应] ", map[string]interface{}{
		"domain":     domain,
		"rule":       "CACHE_SET_CLOUD",
		"cloud_type": cloudType,
	})

	cm.logger.Debug("☁️ 云响应缓存详细信息", map[string]interface{}{
		"domain":     domain,
		"qtype":      dns.TypeToString[qtype],
		"cloud_type": cloudType,
		"ttl":        ttl.String(),
		"answers":    len(response.Answer),
		"operation":  "cloud_response_cached",
	})

	// 如果TTL较短，提交异步刷新任务（不再在这里检查，移到Get时检查）
	// if cm.config.Cache.EnableAsyncRefresh && ttl <= cm.config.Cache.RefreshThreshold {
	//     cm.submitAsyncRefresh(domain, qtype, time.Now().Add(ttl), 1) // 高优先级
	// }
}

// Set 设置缓存（只缓存成功的响应）
func (cm *CacheManager) Set(domain string, qtype uint16, response *dns.Msg, isCloud bool, cloudType ...int) {
	timer := cm.logger.StartTimer("cache_set", map[string]interface{}{
		"domain":   domain,
		"qtype":    dns.TypeToString[qtype],
		"is_cloud": isCloud,
	})
	defer timer.End()

	// 云服务域名特殊处理
	if isCloud {
		cm.cache.Set(domain, qtype, nil, true, cloudType...)
		cm.logger.Info("📋 [缓存设置-云标记] ", map[string]interface{}{
			"domain": domain,
			"rule":   "CACHE_SET_CLOUD_MARK",
		})
		cm.logger.Debug("☁️ 云服务域名标记缓存详细信息", map[string]interface{}{
			"domain":    domain,
			"qtype":     dns.TypeToString[qtype],
			"operation": "cloud_domain_marked",
		})
		return
	}

	// 检查响应是否为空或失败
	if response == nil {
		cm.logger.Debug("⚠️ 空响应，不缓存", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return
	}

	// 只缓存成功的响应（NOERROR）
	if response.Rcode != dns.RcodeSuccess {
		cm.logger.Debug("❌ 失败响应，不缓存详细信息", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"rcode":  dns.RcodeToString[response.Rcode],
			"reason": "failed_response_not_cached",
		})
		return
	}

	// 验证响应内容是否有效
	if !cm.isValidDNSResponse(domain, qtype, response) {
		cm.logger.Warn("⚠️ 无效响应内容，不缓存", map[string]interface{}{
			"domain":  domain,
			"qtype":   dns.TypeToString[qtype],
			"rcode":   dns.RcodeToString[response.Rcode],
			"answers": len(response.Answer),
			"reason":  "invalid_response_content",
		})
		return
	}

	// 计算实际TTL
	actualTTL := cm.calculateTTL(response)

	cm.cache.Set(domain, qtype, response, false)

	cm.logger.Info("📋 [缓存设置-成功响应] ", map[string]interface{}{
		"domain": domain,
		"rule":   "CACHE_SET_SUCCESS",
	})

	cm.logger.Debug("💾 成功响应缓存详细信息", map[string]interface{}{
		"domain":    domain,
		"qtype":     dns.TypeToString[qtype],
		"ttl":       actualTTL.String(),
		"answers":   len(response.Answer),
		"rcode":     dns.RcodeToString[response.Rcode],
		"operation": "success_response_cached",
	})
}

// calculateTTL 计算响应的实际TTL（使用配置的TTL作为最小值）
func (cm *CacheManager) calculateTTL(response *dns.Msg) time.Duration {
	if response == nil || len(response.Answer) == 0 {
		return cm.config.Cache.TTL
	}

	// 从响应中获取最小的TTL
	var minTTL uint32 = 0
	for _, rr := range response.Answer {
		if rr.Header().Ttl > 0 {
			if minTTL == 0 || rr.Header().Ttl < minTTL {
				minTTL = rr.Header().Ttl
			}
		}
	}

	// 如果没有有效的TTL，使用配置的TTL
	if minTTL == 0 {
		return cm.config.Cache.TTL
	}

	upstreamTTL := time.Duration(minTTL) * time.Second
	configTTL := cm.config.Cache.TTL

	// 返回两者中的较大值（使用配置的TTL作为最小值）
	if upstreamTTL > configTTL {
		return upstreamTTL
	}
	return configTTL
}

// isValidDNSResponse 验证DNS响应是否值得缓存
// 只缓存 NOERROR 且有答案记录的响应
func (cm *CacheManager) isValidDNSResponse(domain string, qtype uint16, response *dns.Msg) bool {
	if response == nil {
		return false
	}

	// 只缓存成功的响应（NOERROR）
	if response.Rcode != dns.RcodeSuccess {
		// 记录非成功响应，但不缓存
		cm.logger.Debug("🔍 DNS响应非成功，不缓存", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"rcode":  dns.RcodeToString[response.Rcode],
		})
		return false
	}

	// 检查是否有答案记录 - NOERROR但无答案的不缓存
	if len(response.Answer) == 0 {
		cm.logger.Debug("🔍 NOERROR但无答案记录，不缓存", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		return false
	}

	// NOERROR且有答案记录，可以缓存
	return true
}

// isInvalidIP 检查IP地址是否为无效/不应该缓存的IP
func (cm *CacheManager) isInvalidIP(ip string) bool {
	// 空字符串
	if ip == "" {
		return true
	}

	// 常见的无效IP地址
	invalidIPs := []string{
		"0.0.0.0",         // 未指定地址
		"127.0.0.1",       // 本地地址
		"255.255.255.255", // 广播地址
		"::1",             // IPv6本地地址
		"::",              // IPv6未指定地址
	}

	for _, invalidIP := range invalidIPs {
		if ip == invalidIP {
			return true
		}
	}

	// 检查可疑的IP模式（如停放页面常用的IP）
	suspiciousPatterns := []string{
		"127.",     // 本地回环
		"169.254.", // 自动配置地址
		"224.",     // 多播地址
		"239.",     // 多播地址
	}

	for _, pattern := range suspiciousPatterns {
		if len(ip) > len(pattern) && ip[:len(pattern)] == pattern {
			cm.logger.Debug("⚠️ 检测到可疑IP模式", map[string]interface{}{
				"ip":      ip,
				"pattern": pattern,
			})
			return true
		}
	}

	return false
}

// shouldRefresh 检查是否应该刷新缓存
func (cm *CacheManager) shouldRefresh(domain string, qtype uint16) bool {
	// 使用配置中的刷新阈值检查是否需要刷新
	shouldRefresh := cm.cache.ShouldRefreshWithThreshold(domain, qtype, cm.config.Cache.RefreshThreshold)

	// 添加调试日志
	cm.logger.Debug("🔍 shouldRefresh检查", map[string]interface{}{
		"domain":            domain,
		"qtype":             dns.TypeToString[qtype],
		"should_refresh":    shouldRefresh,
		"async_enabled":     cm.config.Cache.EnableAsyncRefresh,
		"refresh_threshold": cm.config.Cache.RefreshThreshold.String(),
	})

	return shouldRefresh
}

// submitAsyncRefresh 提交异步刷新任务
func (cm *CacheManager) submitAsyncRefresh(domain string, qtype uint16, expireTime time.Time, priority int) {
	key := fmt.Sprintf("%s:%d", domain, qtype)

	cm.asyncMu.Lock()
	if _, exists := cm.asyncSet[key]; exists {
		cm.asyncMu.Unlock()
		return
	}
	cm.asyncSet[key] = struct{}{}
	cm.asyncMu.Unlock()

	task := &AsyncRefreshTask{
		Domain:     domain,
		QType:      qtype,
		ExpireTime: expireTime,
		Priority:   priority,
	}

	select {
	case cm.asyncChan <- task:
		cm.logger.Debug("📋 异步刷新任务已提交", map[string]interface{}{
			"domain":   domain,
			"qtype":    dns.TypeToString[qtype],
			"priority": priority,
		})
	default:
		cm.logger.Warn("⚠️ 异步刷新队列已满", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		cm.asyncMu.Lock()
		delete(cm.asyncSet, key)
		cm.asyncMu.Unlock()
	}
}

// startCacheScanTask 启动定期缓存扫描任务（带panic恢复）
func (cm *CacheManager) startCacheScanTask() {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			cm.logger.Error("💥 [缓存扫描任务panic] ", map[string]interface{}{
				"rule":        "CACHE_SCAN_PANIC",
				"panic_msg":   fmt.Sprintf("%v", r),
				"stack_trace": string(debug.Stack()),
			})
			// 重新启动扫描任务
			time.Sleep(10 * time.Second) // 等待一段时间再重启
			go cm.startCacheScanTask()
		}
	}()

	// 每30秒扫描一次缓存（降低扫描频率）
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	cm.logger.Info("🔍 定期缓存扫描任务已启动", map[string]interface{}{
		"scan_interval":     "30s",
		"refresh_threshold": cm.config.Cache.RefreshThreshold.String(),
	})

	for {
		select {
		case <-ticker.C:
			cm.scanCacheForRefresh()
		case <-cm.workerPool.stopCh:
			cm.logger.Info("🔍 定期缓存扫描任务已停止")
			return
		}
	}
}

// scanCacheForRefresh 扫描缓存并提交需要刷新的条目
func (cm *CacheManager) scanCacheForRefresh() {
	stats := cm.cache.GetStats()
	if stats.Size == 0 {
		cm.logger.Debug("🔍 缓存为空，跳过扫描")
		return
	}

	cm.logger.Debug("🔍 开始扫描缓存条目", map[string]interface{}{
		"cache_size": stats.Size,
	})

	// 获取需要刷新的条目
	entriesToRefresh := cm.cache.GetExpiringSoonEntries(cm.config.Cache.RefreshThreshold)

	if len(entriesToRefresh) > 0 {
		cm.logger.Info("🔄 发现需要刷新的缓存条目", map[string]interface{}{
			"count":             len(entriesToRefresh),
			"refresh_threshold": cm.config.Cache.RefreshThreshold.String(),
		})

		for _, entry := range entriesToRefresh {
			// 计算过期时间（当前时间 + TTL）
			expireTime := time.Now().Add(cm.config.Cache.TTL)
			priority := 0
			if entry.IsCloud {
				priority = 1 // 云域名高优先级
			}
			cm.logger.Debug("📋 提交异步刷新任务", map[string]interface{}{
				"domain":   entry.Domain,
				"qtype":    dns.TypeToString[entry.QType],
				"is_cloud": entry.IsCloud,
				"priority": priority,
			})
			cm.submitAsyncRefresh(entry.Domain, entry.QType, expireTime, priority)
		}
	} else {
		cm.logger.Debug("🔍 未发现需要刷新的缓存条目", map[string]interface{}{
			"cache_size": stats.Size,
		})
	}
}

// CacheEntryInfo 缓存条目信息
type CacheEntryInfo struct {
	Domain  string
	QType   uint16
	IsCloud bool
}

// startAsyncWorkers 启动异步工作器
func (cm *CacheManager) startAsyncWorkers() {
	workers := cm.config.Cache.MaxAsyncWorkers
	if workers <= 0 {
		workers = 5
	}

	for i := 0; i < workers; i++ {
		go cm.asyncWorker(i)
	}

	cm.logger.Info("🔄 异步刷新工作器启动完成", map[string]interface{}{
		"workers": workers,
	})
}

// asyncWorker 异步工作器（带panic恢复）
func (cm *CacheManager) asyncWorker(workerID int) {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			cm.logger.Error("💥 [异步工作器panic] ", map[string]interface{}{
				"rule":        "ASYNC_WORKER_PANIC",
				"worker_id":   workerID,
				"panic_msg":   fmt.Sprintf("%v", r),
				"stack_trace": string(debug.Stack()),
			})
			// 重新启动工作器
			go cm.asyncWorker(workerID)
		}
	}()

	cm.logger.Debug("🔄 异步工作器启动", map[string]interface{}{
		"worker_id": workerID,
	})

	for {
		select {
		case task := <-cm.asyncChan:
			cm.processAsyncTask(task, workerID)
		case <-cm.workerPool.stopCh:
			cm.logger.Debug("🔄 异步工作器停止", map[string]interface{}{
				"worker_id": workerID,
			})
			return
		}
	}
}

// processAsyncTask 处理异步任务
func (cm *CacheManager) processAsyncTask(task *AsyncRefreshTask, workerID int) {
	key := fmt.Sprintf("%s:%d", task.Domain, task.QType)

	defer func() {
		cm.asyncMu.Lock()
		delete(cm.asyncSet, key)
		cm.asyncMu.Unlock()
	}()

	// 检查任务是否过期
	if time.Now().After(task.ExpireTime) {
		cm.logger.Debug("⏰ 异步任务已过期", map[string]interface{}{
			"domain":    task.Domain,
			"qtype":     dns.TypeToString[task.QType],
			"worker_id": workerID,
		})
		return
	}

	timer := cm.logger.StartTimer("async_refresh", map[string]interface{}{
		"domain":    task.Domain,
		"qtype":     dns.TypeToString[task.QType],
		"worker_id": workerID,
		"priority":  task.Priority,
	})

	cm.logger.Debug("🔄 开始异步刷新", map[string]interface{}{
		"domain":    task.Domain,
		"qtype":     dns.TypeToString[task.QType],
		"worker_id": workerID,
	})

	// 这里需要从handler获取刷新函数
	// 由于循环依赖，我们通过回调方式处理
	if cm.refreshCallback != nil {
		if err := cm.refreshCallback(task.Domain, task.QType); err != nil {
			timer.EndWithError(err)
			cm.logger.Error("🔄 异步刷新失败", map[string]interface{}{
				"domain":    task.Domain,
				"qtype":     dns.TypeToString[task.QType],
				"worker_id": workerID,
				"error":     err.Error(),
			})
		} else {
			timer.End()
			cm.logger.Debug("✅ 异步刷新完成", map[string]interface{}{
				"domain":    task.Domain,
				"qtype":     dns.TypeToString[task.QType],
				"worker_id": workerID,
			})
		}
	}
}

// RefreshCallback 刷新回调函数类型
type RefreshCallback func(domain string, qtype uint16) error

// SetRefreshCallback 设置刷新回调
func (cm *CacheManager) SetRefreshCallback(callback RefreshCallback) {
	cm.refreshCallback = callback
}

// GetStats 获取缓存统计
func (cm *CacheManager) GetStats() map[string]interface{} {
	stats := cm.cache.GetStats()

	cm.asyncMu.RLock()
	pendingTasks := len(cm.asyncSet)
	cm.asyncMu.RUnlock()

	return map[string]interface{}{
		"cache_size":     stats.Size,
		"pending_tasks":  pendingTasks,
		"queue_capacity": cap(cm.asyncChan),
		"queue_length":   len(cm.asyncChan),
	}
}

// Clear 清空缓存
func (cm *CacheManager) Clear() {
	cm.cache.Clear()

	// 清空异步任务
	cm.asyncMu.Lock()
	cm.asyncSet = make(map[string]struct{})
	cm.asyncMu.Unlock()

	// 清空队列
	for len(cm.asyncChan) > 0 {
		<-cm.asyncChan
	}

	cm.logger.Info("🗑️ 缓存已清空")
}

// Close 关闭缓存管理器
func (cm *CacheManager) Close() {
	cm.workerPool.mu.Lock()
	if !cm.workerPool.stopped {
		close(cm.workerPool.stopCh)
		cm.workerPool.stopped = true
	}
	cm.workerPool.mu.Unlock()

	cm.Clear()
	close(cm.asyncChan)

	cm.logger.Info("📪 缓存管理器已关闭")
}
