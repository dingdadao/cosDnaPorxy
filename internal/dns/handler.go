package dns

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// hasModernProtocols 检查是否包含现代协议或新格式（统一URL scheme）
func hasModernProtocols(upstreams []string) bool {
	for _, upstream := range upstreams {
		if strings.HasPrefix(upstream, "udp://") ||
			strings.HasPrefix(upstream, "tcp://") ||
			strings.HasPrefix(upstream, "https://") ||
			strings.HasPrefix(upstream, "tls://") ||
			strings.HasPrefix(upstream, "h3://") {
			return true
		}
	}
	return false
}

// getProtocolTypes 获取协议类型列表
func getProtocolTypes(upstreams []string) []string {
	protocolSet := make(map[string]bool)
	for _, upstream := range upstreams {
		if strings.HasPrefix(upstream, "udp://") {
			protocolSet["UDP"] = true
		} else if strings.HasPrefix(upstream, "tcp://") {
			protocolSet["TCP"] = true
		} else if strings.HasPrefix(upstream, "https://") {
			protocolSet["DoH"] = true
		} else if strings.HasPrefix(upstream, "tls://") {
			protocolSet["DoT"] = true
		} else if strings.HasPrefix(upstream, "h3://") {
			protocolSet["DoH3"] = true
		} else {
			protocolSet["UDP/TCP"] = true
		}
	}

	var protocols []string
	for protocol := range protocolSet {
		protocols = append(protocols, protocol)
	}
	return protocols
}

// RefactoredHandler 重构后的DNS处理器
type RefactoredHandler struct {
	config *config.Config
	Logger *utils.EnhancedLogger // 改为公共字段

	// 核心组件
	cacheManager      *CacheManager
	cloudDetector     *CloudDetector
	queryOptimizer    interface{} // 可以是 *FastQueryOptimizer 或 *SimpleModernOptimizer
	whitelistMatcher  *WhitelistMatcher
	designatedMatcher *DesignatedMatcher

	ctx    context.Context
	cancel context.CancelFunc
}

// NewRefactoredHandler 创建新的重构后处理器
func NewRefactoredHandler(cfg *config.Config, logger *utils.EnhancedLogger) (*RefactoredHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建核心组件（移除指标系统）
	cacheManager := NewCacheManager(cfg, logger, nil)
	cloudDetector := NewCloudDetector(logger, nil)

	// 根据上游配置选择查询优化器
	var queryOptimizer interface{}
	if hasModernProtocols(cfg.Upstream) {
		// 使用简化的现代查询优化器，传入现代协议超时
		queryOptimizer = NewSimpleModernOptimizer(logger, cfg.Timeout, cfg.ModernTimeout)
		logger.Info("🚀 [使用现代DNS查询优化器] ", map[string]interface{}{
			"rule":           "MODERN_OPTIMIZER_SELECTED",
			"protocols":      getProtocolTypes(cfg.Upstream),
			"timeout":        cfg.Timeout.String(),
			"modern_timeout": cfg.ModernTimeout.String(),
		})
	} else {
		// 使用传统查询优化器
		queryOptimizer = NewFastQueryOptimizer(logger, nil, cfg.Timeout)
		logger.Info("🚀 [使用传统 DNS查询优化器] ", map[string]interface{}{
			"rule": "TRADITIONAL_OPTIMIZER_SELECTED",
		})
	}

	whitelistMatcher := &WhitelistMatcher{logger: logger}
	designatedMatcher := &DesignatedMatcher{logger: logger}

	handler := &RefactoredHandler{
		config:            cfg,
		Logger:            logger, // 使用公共字段
		cacheManager:      cacheManager,
		cloudDetector:     cloudDetector,
		queryOptimizer:    queryOptimizer,
		whitelistMatcher:  whitelistMatcher,
		designatedMatcher: designatedMatcher,
		ctx:               ctx,
		cancel:            cancel,
	}

	// 设置缓存回调
	cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 加载所有数据
	if err := handler.loadAllData(); err != nil {
		logger.Error("加载数据失败", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// 启动后台任务
	handler.startBackgroundTasks()

	logger.Info("🚀 重构后DNS处理器初始化完成")

	return handler, nil
}

// ServeDNS 实现dns.Handler接口（带panic恢复）
func (h *RefactoredHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			h.Logger.Error("💥 [DNS处理panic] ", map[string]interface{}{
				"rule":        "DNS_HANDLER_PANIC",
				"panic_msg":   fmt.Sprintf("%v", r),
				"client_addr": w.RemoteAddr().String(),
				"stack_trace": string(debug.Stack()),
			})
			// 发送错误响应
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		}
	}()

	timer := h.Logger.StartTimer("dns_request")
	defer timer.End()

	if req == nil || len(req.Question) == 0 {
		h.Logger.Warn("⚠️ 收到空DNS请求")
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 处理每个问题（通常只有一个）
	for _, q := range req.Question {
		domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		// 检查域名是否合法
		if _, ok := dns.IsDomainName(domain); !ok {
			h.Logger.Warn("⚠️ 非法域名请求", map[string]interface{}{
				"domain": domain,
			})
			continue
		}

		// 只处理A和AAAA记录
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			continue
		}

		h.processQuery(w, req, domain, q.Qtype)
		return // 只处理第一个有效问题
	}
}

// processQuery 处理单个DNS查询
func (h *RefactoredHandler) processQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16) {
	h.Logger.Debug("🔍 开始处理DNS查询", map[string]interface{}{
		"domain":      domain,
		"qtype":       dns.TypeToString[qtype],
		"client_addr": w.RemoteAddr().String(),
		"request_id":  req.Id,
	})

	// 1. 缓存检查
	if resp, hit, isCloud, cloudType := h.cacheManager.Get(domain, qtype); hit {
		if isCloud {
			// 云域名缓存命中
			h.Logger.Info("📋 [缓存命中-云域名] ", map[string]interface{}{
				"domain":     domain,
				"rule":       "CACHE_CLOUD",
				"cloud_type": cloudType,
			})

			// 云域名需要特殊处理
			if cloudResp, cloudHit, cType := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				h.Logger.Debug("📋 返回云IP替换缓存", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"cloud_type":   cType,
					"answer_count": len(cloudResp.Answer),
				})
				respCopy := cloudResp.Copy()
				respCopy.Id = req.Id
				w.WriteMsg(respCopy)
				return
			}

			// 没有云响应缓存，执行云IP替换
			h.handleCloudReplacement(w, req, domain, qtype, cloudType)
			return
		} else {
			// 普通域名缓存命中
			h.Logger.Info("📋 [缓存命中-普通域名] ", map[string]interface{}{
				"domain": domain,
				"rule":   "CACHE_NORMAL",
			})

			h.Logger.Debug("返回普通缓存响应", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"answer_count": len(resp.Answer),
				"rcode":        dns.RcodeToString[resp.Rcode],
			})

			respCopy := resp.Copy()
			respCopy.Id = req.Id
			w.WriteMsg(respCopy)
			return
		}
	}

	// 2. 白名单检查
	if h.whitelistMatcher.IsWhitelisted(domain) {
		h.Logger.Info("✅ [白名单命中] ", map[string]interface{}{
			"domain": domain,
			"rule":   "WHITELIST",
		})

		h.Logger.Debug("白名单域名查询上游", map[string]interface{}{
			"domain":    domain,
			"upstreams": h.config.Upstream,
		})

		resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
		if err != nil || resp == nil {
			h.Logger.Error("❌ 白名单域名查询失败", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		respCopy := resp.Copy()
		respCopy.Id = req.Id
		w.WriteMsg(respCopy)
		return
	}

	// 3. 定向域名检查
	if designated := h.designatedMatcher.GetDesignatedDomain(domain); designated != nil {
		h.Logger.Info("🎯 [定向域名命中] ", map[string]interface{}{
			"domain": domain,
			"rule":   "DESIGNATED",
			"dns":    designated.DNS,
		})

		h.Logger.Debug("定向域名查询指定DNS", map[string]interface{}{
			"domain":         domain,
			"designated_dns": designated.DNS,
			"pattern":        designated.Pattern,
		})

		resp, err := h.proxyQueryWithCaching(req, []string{designated.DNS}, domain, qtype)
		if err != nil || resp == nil {
			h.Logger.Error("❌ 定向域名查询失败", map[string]interface{}{
				"domain": domain,
				"dns":    designated.DNS,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		respCopy := resp.Copy()
		respCopy.Id = req.Id
		w.WriteMsg(respCopy)
		return
	}

	// 4. 云域名检查和普通域名处理
	timer := h.Logger.StartTimer("upstream_query", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})

	resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
	timer.End()

	if err != nil || resp == nil {
		h.Logger.Error("❌ 上游查询失败", map[string]interface{}{
			"domain": domain,
			"error":  err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 检测云服务
	detection := h.cloudDetector.DetectCloudService(resp)
	if detection.Type != CloudTypeNone {
		h.Logger.Info("☁️ [云域名检测] ", map[string]interface{}{
			"domain":     domain,
			"rule":       "CLOUD_DETECTED",
			"cloud_type": detection.Type,
		})

		h.Logger.Debug("云服务检测结果", map[string]interface{}{
			"domain":         domain,
			"cloud_type":     detection.Type,
			"detected_ips":   detection.DetectedIPs,
			"replace_domain": detection.ReplaceDomain,
		})

		// 标记为云域名
		h.cacheManager.Set(domain, qtype, nil, true, int(detection.Type))

		// 执行云IP替换
		h.handleCloudReplacement(w, req, domain, qtype, int(detection.Type))
		return
	}

	// 5. 普通域名响应
	h.Logger.Info("🌐 [普通域名] ", map[string]interface{}{
		"domain": domain,
		"rule":   "NORMAL",
	})

	h.Logger.Debug("返回普通域名响应", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"answer_count": len(resp.Answer),
		"rcode":        dns.RcodeToString[resp.Rcode],
	})

	respCopy := resp.Copy()
	respCopy.Id = req.Id
	w.WriteMsg(respCopy)
}

// handleCloudReplacement 处理云IP替换
func (h *RefactoredHandler) handleCloudReplacement(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, cloudType int) {
	var replaceDomain string
	var cloudTypeName string
	switch CloudType(cloudType) {
	case CloudTypeCloudflare:
		replaceDomain = h.config.ReplaceCFDomain
		cloudTypeName = "Cloudflare"
	case CloudTypeAWS:
		replaceDomain = h.config.ReplaceAWSDomain
		cloudTypeName = "AWS"
	default:
		h.Logger.Warn("⚠️ 未知云服务类型", map[string]interface{}{
			"cloud_type": cloudType,
			"domain":     domain,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	if replaceDomain == "" {
		h.Logger.Warn("⚠️ 未配置云服务替换域名", map[string]interface{}{
			"cloud_type": cloudTypeName,
			"domain":     domain,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	h.Logger.Debug("开始云IP替换查询", map[string]interface{}{
		"original_domain": domain,
		"replace_domain":  replaceDomain,
		"cloud_type":      cloudTypeName,
	})

	// 查询替换域名
	replaceReq := &dns.Msg{}
	replaceReq.SetQuestion(dns.Fqdn(replaceDomain), qtype)

	replaceResp, err := h.proxyQuery(replaceReq, h.config.Upstream)
	if err != nil || replaceResp == nil {
		h.Logger.Error("❌ 替换域名查询失败", map[string]interface{}{
			"replace_domain":  replaceDomain,
			"original_domain": domain,
			"error":           err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 构建响应，将替换域名的IP地址作为原始域名的响应
	finalResp := &dns.Msg{}
	finalResp.SetReply(req)
	finalResp.Authoritative = true
	finalResp.RecursionAvailable = true

	// 复制Answer记录，但修改域名
	for _, rr := range replaceResp.Answer {
		newRR := dns.Copy(rr)
		newRR.Header().Name = dns.Fqdn(domain)
		finalResp.Answer = append(finalResp.Answer, newRR)
	}

	// 缓存替换后的响应
	h.cacheManager.SetCloudResponse(domain, qtype, finalResp, cloudType)

	h.Logger.Info("✅ [云IP替换成功] ", map[string]interface{}{
		"domain":         domain,
		"rule":           "CLOUD_REPLACED",
		"replace_domain": replaceDomain,
		"cloud_type":     cloudTypeName,
		"answer_count":   len(finalResp.Answer),
	})

	h.Logger.Debug("云IP替换详细信息", map[string]interface{}{
		"original_domain":  domain,
		"replace_domain":   replaceDomain,
		"cloud_type":       cloudTypeName,
		"original_answers": len(replaceResp.Answer),
		"final_answers":    len(finalResp.Answer),
		"cached_as_cloud":  true,
	})

	finalResp.Id = req.Id
	w.WriteMsg(finalResp)
}

// sendErrorResponse 发送错误响应
func (h *RefactoredHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	w.WriteMsg(resp)
}

// GetStats 获取统计信息
func (h *RefactoredHandler) GetStats() map[string]interface{} {
	cacheStats := h.cacheManager.GetStats()

	return map[string]interface{}{
		"cache": cacheStats,
	}
}

// Close 关闭处理器
func (h *RefactoredHandler) Close() {
	h.cancel()

	if h.cacheManager != nil {
		h.cacheManager.Close()
	}

	if h.queryOptimizer != nil {
		// 使用类型断言关闭不同类型的查询优化器
		if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
			modernOptimizer.Close()
		} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
			traditionalOptimizer.Close()
		}
	}

	h.Logger.Info("📪 重构后DNS处理器已关闭")
}
