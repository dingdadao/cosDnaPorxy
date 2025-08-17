package dns

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"strings"
	"time"
)

// runAsyncHealthCheck 异步健康检查，不影响查询性能
func (h *Handler) runAsyncHealthCheck() {
	ticker := time.NewTicker(5 * time.Minute) // 每5分钟检查一次
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.performAsyncHealthCheck()
		}
	}
}

// performAsyncHealthCheck 执行异步健康检查
func (h *Handler) performAsyncHealthCheck() {
	// 合并所有上游服务器
	allServers := append(h.config.CNUpstream, h.config.NotCNUpstream...)

	for _, server := range allServers {
		go func(srv string) {
			// 异步检查每个服务器，不阻塞主流程
			isHealthy := h.performHealthCheck(srv)

			// 简单记录健康状态
			h.Lock()
			if health, exists := h.serverHealth[srv]; exists {
				health.Lock()
				health.LastCheck = time.Now()
				health.IsHealthy = isHealthy
				if isHealthy {
					health.SuccessCount++
				} else {
					health.FailureCount++
				}
				health.Unlock()
			} else {
				// 创建新的健康记录
				h.serverHealth[srv] = &ServerHealth{
					LastCheck:    time.Now(),
					IsHealthy:    isHealthy,
					SuccessCount: 1,
					FailureCount: 0,
				}
			}
			h.Unlock()

			if isHealthy {
				h.logger.Debug("异步健康检查成功: %s", srv)
			} else {
				h.logger.Debug("异步健康检查失败: %s", srv)
			}
		}(server)
	}
}

// checkServerHealth 检查服务器健康状态
func (h *Handler) checkServerHealth(server string) bool {
	// 生成缓存键
	cacheKey := fmt.Sprintf("health:%s", server)

	// 尝试从缓存获取健康状态
	if cached, found := h.hotCache.Get(cacheKey); found {
		if health, ok := cached.(bool); ok {
			h.logger.Debug("健康状态缓存命中: %s -> %v", server, health)
			return health
		}
	}

	// 缓存未命中，执行健康检查
	h.logger.Debug("健康状态缓存未命中，执行检查: %s", server)

	h.Lock()
	health, exists := h.serverHealth[server]
	if !exists {
		health = &ServerHealth{}
		h.serverHealth[server] = health
	}
	h.Unlock()

	health.Lock()
	defer health.Unlock()

	// 对TLS服务器减少健康检查频率，避免频繁握手
	checkInterval := 5 * time.Second
	if strings.HasPrefix(server, "tls://") || strings.HasPrefix(server, "https://") {
		checkInterval = 30 * time.Second // TLS服务器30秒检查一次
	}

	// 如果距离上次检查时间太短，直接返回上次结果
	if time.Since(health.LastCheck) < checkInterval {
		return health.IsHealthy
	}

	// 执行健康检查
	isHealthy := h.performHealthCheck(server)

	// 更新健康状态
	health.LastCheck = time.Now()
	health.IsHealthy = isHealthy

	if isHealthy {
		health.SuccessCount++
		health.FailureCount = 0
		h.logger.Debug("服务器健康检查成功: %s", server)
	} else {
		health.FailureCount++
		health.SuccessCount = 0
		h.logger.Debug("服务器健康检查失败: %s", server)
	}

	// 缓存健康状态 - 使用配置的TTL值
	cacheTTL := h.config.Cache.HealthCheckTTL
	if strings.HasPrefix(server, "tls://") || strings.HasPrefix(server, "https://") {
		// TLS服务器缓存更长时间，避免频繁握手
		cacheTTL = h.config.Cache.HealthCheckTTL * 4 // TLS服务器缓存4倍时间
	}
	h.hotCache.Set(cacheKey, isHealthy, cacheTTL)

	return isHealthy
}

// performHealthCheck 执行实际的健康检查
func (h *Handler) performHealthCheck(server string) bool {
	// 创建测试查询
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

	// 设置超时 - 对TLS服务器给予更长的超时时间
	timeout := 2 * time.Second
	if strings.HasPrefix(server, "tls://") || strings.HasPrefix(server, "https://") {
		timeout = 5 * time.Second // TLS连接需要更长时间
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// 根据服务器类型选择查询方法
	if strings.HasPrefix(server, "https://") {
		// DoH查询
		resp, err := h.queryDoHWithContext(ctx, req, server, false)
		return err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess
	} else if strings.HasPrefix(server, "tls://") {
		// DoT查询 - 使用标准库
		network, timeout := h.getNetworkAndTimeout(server)
		c := &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		serverAddr := h.getServerAddress(server)
		resp, _, err := c.ExchangeContext(ctx, req, serverAddr)
		return err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess
	} else {
		// UDP/TCP查询
		resp, err := h.querySingleServerWithContext(ctx, req, server)
		return err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess
	}
}

// getHealthyServers 获取健康的DNS服务器列表
func (h *Handler) getHealthyServers(servers []string) []string {
	var healthy []string
	for _, server := range servers {
		if h.checkServerHealth(server) {
			healthy = append(healthy, server)
		}
	}

	// 如果没有健康的服务器，返回原始列表
	if len(healthy) == 0 {
		h.logger.Warn("没有健康的DNS服务器，使用原始列表")
		return servers
	}

	return healthy
} 