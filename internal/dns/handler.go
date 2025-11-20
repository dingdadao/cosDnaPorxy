package dns

import (
	"context"
	"fmt"
	"runtime/debug"
	"strings"
	"time"

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

	// 设置替换域名配置
	cloudDetector.SetReplaceDomains(cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)

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

	designatedMatcher := NewDesignatedMatcher(logger)
	// 设置默认DNS
	if cfg.DefaultDNS != "" {
		designatedMatcher.SetDefaultDNS(cfg.DefaultDNS)
	}

	handler := &RefactoredHandler{
		config:            cfg,
		Logger:            logger, // 使用公共字段
		cacheManager:      cacheManager,
		cloudDetector:     cloudDetector,
		queryOptimizer:    queryOptimizer,
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
	h.Logger.Info("🔍 [DNS查询开始] ", map[string]interface{}{
		"domain":      domain,
		"qtype":       dns.TypeToString[qtype],
		"client_addr": w.RemoteAddr().String(),
		"request_id":  req.Id,
		"rule":        "DNS_QUERY_START",
	})

	// 1. 缓存检查
	if resp, hit, isCloud, cloudType := h.cacheManager.Get(domain, qtype); hit {
		h.Logger.Info("✅ [DNS查询结果-缓存命中] ", map[string]interface{}{
			"domain":     domain,
			"type":       "cache_hit",
			"is_cloud":   isCloud,
			"cloud_type": cloudType,
		})

		if isCloud {
			// 云域名缓存命中
			// 云域名需要特殊处理
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				respCopy := cloudResp.Copy()
				respCopy.Id = req.Id
				// 确保响应中的 TTL 不小于配置的最小 TTL
				h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
				w.WriteMsg(respCopy)

				h.Logger.Info("✅ [DNS查询完成] ", map[string]interface{}{
					"domain":       domain,
					"result":       "success",
					"source":       "cloud_cache",
					"answer_count": len(cloudResp.Answer),
				})
				return
			}

			// 没有云响应缓存，执行云IP替换
			h.handleCloudReplacement(w, req, domain, qtype, cloudType)
			return
		} else {
			// 普通域名缓存命中
			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)

			h.Logger.Info("✅ [DNS查询完成] ", map[string]interface{}{
				"domain":       domain,
				"result":       "success",
				"source":       "normal_cache",
				"answer_count": len(resp.Answer),
			})
			return
		}
	} else {
		h.Logger.Info("❌ [缓存未命中] ", map[string]interface{}{
			"domain": domain,
			"type":   "cache_miss",
		})
	}

	// 2. 缓存未命中，检查是否为替换域名
	// 如果是替换域名，直接查询并返回结果，避免套娃
	if h.cloudDetector.IsReplaceDomain(domain) {
		h.Logger.Debug("⏭️ 跳过云服务检测（替换域名）", map[string]interface{}{
			"domain": domain,
		})

		resp, err := h.proxyQuery(req, h.config.Upstream)
		if err != nil || resp == nil {
			h.Logger.Error("❌ [替换域名查询失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		respCopy := resp.Copy()
		respCopy.Id = req.Id
		// 确保响应中的 TTL 不小于配置的最小 TTL
		h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)

		// 缓存替换域名的响应结果
		h.cacheManager.Set(domain, qtype, respCopy, false)

		w.WriteMsg(respCopy)

		h.Logger.Info("✅ [替换域名查询完成] ", map[string]interface{}{
			"domain":       domain,
			"result":       "success",
			"answer_count": len(resp.Answer),
		})
		return
	}

	// 3. 非替换域名处理逻辑
	h.Logger.Debug("🎯 开始定向域名检查", map[string]interface{}{
		"domain": domain,
		"step":   "DESIGNATED_CHECK",
	})

	// 使用新的统一匹配方法
	if dnsServer, hasDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain); hasDesignated {
		// 检查是否使用默认DNS配置
		if dnsServer == h.designatedMatcher.GetDefaultDNS() {
			h.Logger.Info("🔄 [使用默认DNS] ", map[string]interface{}{
				"domain": domain,
				"dns":    dnsServer,
			})
			// 当使用默认DNS时，使用上游配置进行查询
			h.Logger.Info("🌐 [上游DNS查询] ", map[string]interface{}{
				"domain":    domain,
				"upstreams": h.config.Upstream,
			})

			resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype, true)
			if err != nil || resp == nil {
				h.Logger.Error("❌ [DNS查询失败] ", map[string]interface{}{
					"domain":    domain,
					"source":    "upstream",
					"upstreams": h.config.Upstream,
					"error":     err,
				})
				h.sendErrorResponse(w, req, dns.RcodeServerFailure)
				return
			}

			// 对于定向域名，即使它是云服务域名，也优先使用定向域名指定的DNS服务器

			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)

			h.Logger.Info("✅ [DNS查询完成] ", map[string]interface{}{
				"domain":       domain,
				"result":       "success",
				"source":       "upstream",
				"answer_count": len(resp.Answer),
			})
			return
		} else {
			// 如果匹配到定向域名且不是使用默认DNS，则使用指定的DNS服务器并跳过云服务检测
			h.Logger.Info("🎯 [定向域名匹配] ", map[string]interface{}{
				"domain":  domain,
				"matched": true,
				"dns":     dnsServer,
			})

			resp, err := h.proxyQueryWithCaching(req, []string{dnsServer}, domain, qtype, true) // 跳过云服务检测
			if err != nil || resp == nil {
				h.Logger.Error("❌ [DNS查询失败] ", map[string]interface{}{
					"domain": domain,
					"source": "designated",
					"error":  err,
				})
				h.sendErrorResponse(w, req, dns.RcodeServerFailure)
				return
			}
			// 对于定向域名，即使它是云服务域名，也优先使用定向域名指定的DNS服务器
			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)

			h.Logger.Info("✅ [DNS查询完成] ", map[string]interface{}{
				"domain":       domain,
				"result":       "success",
				"source":       "designated",
				"answer_count": len(resp.Answer),
			})
			return
		}
	} else {
		h.Logger.Info("❌ [定向域名未匹配] ", map[string]interface{}{
			"domain":  domain,
			"matched": false,
		})
	}

	// 如果没有匹配到定向域名，则使用上游配置进行并发查询
	h.Logger.Info("🌐 [上游DNS查询] ", map[string]interface{}{
		"domain":    domain,
		"upstreams": h.config.Upstream,
	})

	resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [DNS查询失败] ", map[string]interface{}{
			"domain":    domain,
			"source":    "upstream",
			"upstreams": h.config.Upstream,
			"error":     err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 检查是否为云服务（仅在没有定向域名匹配时）
	// 注意：这里会自动跳过替换域名的云服务检测
	detection := h.cloudDetector.DetectCloudService(resp, domain)
	if detection.Type != CloudTypeNone {
		h.Logger.Info("☁️ [云服务检测] ", map[string]interface{}{
			"domain":     domain,
			"cloud_type": detection.Type,
			"detected":   true,
		})

		// 执行云IP替换
		h.handleCloudReplacement(w, req, domain, qtype, int(detection.Type))
		return
	}

	respCopy := resp.Copy()
	respCopy.Id = req.Id
	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
	w.WriteMsg(respCopy)

	h.Logger.Info("✅ [DNS查询完成] ", map[string]interface{}{
		"domain":       domain,
		"result":       "success",
		"source":       "upstream",
		"answer_count": len(resp.Answer),
	})
}

// ensureMinimumTTL 确保响应中的 TTL 不小于指定的最小值
func (h *RefactoredHandler) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
	if resp == nil {
		return
	}

	minTTLSeconds := uint32(minTTL.Seconds())

	// 更新 Answer 部分的 TTL
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Authority 部分的 TTL
	for _, rr := range resp.Ns {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Additional 部分的 TTL
	for _, rr := range resp.Extra {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}
}

// processCloudResponse 处理云域名响应，确保符合DNS协议标准
func (h *RefactoredHandler) processCloudResponse(resp *dns.Msg, domain string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 创建新的响应，不复制原始响应的问题部分以避免Question section mismatch
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}

	// 设置正确的问题部分
	processedResp.Question = []dns.Question{
		{
			Name:   dns.Fqdn(domain),
			Qtype:  resp.Question[0].Qtype,
			Qclass: resp.Question[0].Qclass,
		},
	}

	processedResp.Id = resp.Id // 保持ID一致

	// 获取最大IP记录数配置，默认为4
	maxIPRecords := h.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 4 // 默认值
	}

	// 收集所有IP记录（最多maxIPRecords条）
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 如果已经收集了足够数量的记录，停止收集
		if len(ipRecords) >= maxIPRecords {
			break
		}

		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	// 如果没有足够的IP记录，尝试递归解析CNAME记录
	if len(ipRecords) < maxIPRecords {
		// 查找CNAME记录并递归解析
		for _, rr := range resp.Answer {
			// 如果已经收集了足够数量的记录，停止收集
			if len(ipRecords) >= maxIPRecords {
				break
			}

			if cname, ok := rr.(*dns.CNAME); ok {
				// 递归解析CNAME目标
				cnameTargetReq := &dns.Msg{}
				cnameTargetReq.SetQuestion(cname.Target, dns.TypeA) // 假设是A记录查询

				cnameTargetResp, err := h.proxyQuery(cnameTargetReq, h.config.Upstream)
				if err == nil && cnameTargetResp != nil {
					// 处理CNAME目标的响应
					for _, targetRR := range cnameTargetResp.Answer {
						// 如果已经收集了足够数量的记录，停止收集
						if len(ipRecords) >= maxIPRecords {
							break
						}

						// 只处理IP记录
						switch targetRR.(type) {
						case *dns.A, *dns.AAAA:
							ipRecords = append(ipRecords, targetRR)
						}
					}
				}
			}
		}
	}

	// 复制IP记录到处理后的响应，修改域名
	for _, rr := range ipRecords {
		newRR := dns.Copy(rr)
		newRR.Header().Name = dns.Fqdn(domain)
		processedResp.Answer = append(processedResp.Answer, newRR)
	}

	return processedResp
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
	// 保持请求ID一致，避免响应匹配问题
	replaceReq.Id = req.Id

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

	// 使用统一的云域名响应处理方法
	finalResp := h.processCloudResponse(replaceResp, domain)

	// 如果处理后的响应没有答案记录，返回错误
	if len(finalResp.Answer) == 0 {
		h.Logger.Error("❌ 云IP替换失败：没有解析到有效的IP记录", map[string]interface{}{
			"replace_domain":  replaceDomain,
			"original_domain": domain,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 解析替换缓存时间配置
	replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
	if h.config.ReplaceCacheTime != "" {
		if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
			replaceCacheTime = parsedTime
		} else {
			h.Logger.Warn("⚠️ 解析替换缓存时间失败，使用默认值", map[string]interface{}{
				"replace_cache_time": h.config.ReplaceCacheTime,
				"error":              err.Error(),
				"default_value":      h.config.Cache.TTL.String(),
			})
		}
	}

	// 确保云域名替换响应的TTL不小于配置的替换缓存时间
	h.ensureMinimumTTL(finalResp, replaceCacheTime)

	// 缓存替换后的响应，使用配置的替换缓存时间
	h.cacheManager.SetCloudResponse(domain, qtype, finalResp, cloudType, replaceCacheTime)

	h.Logger.Info("✅ [云IP替换成功] ", map[string]interface{}{
		"domain":         domain,
		"rule":           "CLOUD_REPLACED",
		"replace_domain": replaceDomain,
		"cloud_type":     cloudTypeName,
		"answer_count":   len(finalResp.Answer),
		"cache_ttl":      replaceCacheTime.String(),
	})

	h.Logger.Debug("云IP替换详细信息", map[string]interface{}{
		"original_domain":  domain,
		"replace_domain":   replaceDomain,
		"cloud_type":       cloudTypeName,
		"original_answers": len(replaceResp.Answer),
		"final_answers":    len(finalResp.Answer),
		"cached_as_cloud":  true,
		"cache_ttl":        replaceCacheTime.String(),
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

// loadAllData 加载所有配置数据
func (h *RefactoredHandler) loadAllData() error {
	var lastErr error

	// 加载云服务网段
	if err := h.cloudDetector.LoadNetworkRanges(
		h.config.CloudflareNetFile,
		h.config.CloudflareNetFile6,
		h.config.AWSNetFile,
	); err != nil {
		h.Logger.Error("加载云服务网段失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	// 加载定向域名（包含原白名单内容）
	if err := h.designatedMatcher.LoadDesignatedDomains(h.config.DesignatedDomain); err != nil {
		h.Logger.Error("加载定向域名失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	return lastErr
}

// refreshDNSRecord 刷新DNS记录（缓存回调）
func (h *RefactoredHandler) refreshDNSRecord(domain string, qtype uint16) error {
	// 添加顶层panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			// 记录panic信息
			if h != nil && h.Logger != nil {
				h.Logger.Error("💥 [异步刷新panic] ", map[string]interface{}{
					"rule":        "REFRESH_RECORD_PANIC",
					"domain":      domain,
					"qtype":       dns.TypeToString[qtype],
					"panic_msg":   fmt.Sprintf("%v", r),
					"stack_trace": string(debug.Stack()),
				})
			}

			// 即使发生panic，也要尝试延长缓存TTL以防止频繁刷新
			if h != nil && h.cacheManager != nil {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL/2)
			}
		}
	}()

	// 添加空指针检查
	if h == nil {
		return fmt.Errorf("handler is nil")
	}

	if h.Logger == nil {
		return fmt.Errorf("logger is nil")
	}

	// 检查是否为替换域名，如果是则直接返回，避免套娃
	if h.cloudDetector.IsReplaceDomain(domain) {
		h.Logger.Debug("⏭️ 跳过异步刷新（替换域名）", map[string]interface{}{
			"domain": domain,
		})
		return nil
	}

	h.Logger.Info("🔄 [异步刷新开始] ", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})

	// 确定应该使用的上游DNS服务器（遵循相同的优先级规则）
	upstreams := h.determineUpstreamsForDomain(domain)

	// 添加上游服务器检查
	if len(upstreams) == 0 {
		h.Logger.Warn("⚠️ [异步刷新警告] 未找到有效的上游服务器", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf("no valid upstream servers found")
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 添加请求检查
	if req == nil {
		h.Logger.Error("❌ [异步刷新失败] 请求对象为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf("request object is nil")
	}

	// 使用类型断言调用不同类型的查询优化器
	var result *ConcurrentQueryResult
	if h.queryOptimizer == nil {
		h.Logger.Error("❌ [异步刷新失败] 查询优化器未初始化", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf("query optimizer is nil")
	}

	if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(req, upstreams)
	} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(req, upstreams)
	} else {
		h.Logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  "unknown query optimizer type",
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf("unknown query optimizer type")
	}

	if result == nil {
		h.Logger.Error("❌ [异步刷新失败] 查询结果为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf("query result is nil")
	}

	if result.FastestResult == nil || result.FastestResult.Error != nil {
		errorMsg := "all upstream queries failed"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			errorMsg = result.FastestResult.Error.Error()
		}
		h.Logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  errorMsg,
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if h.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			_, _, isCloud, _ := h.cacheManager.Get(domain, qtype)
			if isCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
			}
		}
		return fmt.Errorf(errorMsg)
	}

	// 验证查询结果：必须有成功响应且包含实际答案记录
	if result.HasSuccess && result.SuccessResult != nil &&
		result.SuccessResult.Response != nil &&
		result.SuccessResult.Response.Rcode == dns.RcodeSuccess &&
		len(result.SuccessResult.Response.Answer) > 0 {

		// 添加缓存管理器检查
		if h.cacheManager == nil {
			h.Logger.Error("❌ [异步刷新失败] 缓存管理器未初始化", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
			})
			return fmt.Errorf("cache manager is nil")
		}

		// 直接从缓存中获取云域名信息，避免重复检测
		_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)

		// 检查是否匹配定向域名且不是使用默认DNS
		dnsServer, hasDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain)
		useDesignatedDNS := hasDesignated && dnsServer != h.designatedMatcher.GetDefaultDNS()

		if useDesignatedDNS {
			// 对于定向域名，即使它是云服务域名，也优先使用定向域名指定的DNS服务器
			// 不进行云服务检测，直接缓存结果
			h.ensureMinimumTTL(result.SuccessResult.Response, h.config.Cache.TTL)
			h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, false, 0)

			h.Logger.Info("✅ [异步刷新成功] ", map[string]interface{}{
				"domain":         domain,
				"qtype":          dns.TypeToString[qtype],
				"is_cloud":       false,
				"use_designated": true,
				"answer_count":   len(result.SuccessResult.Response.Answer),
				"upstreams":      upstreams,
			})
		} else if isCloud {
			// 对于云域名，使用配置的替换缓存时间
			replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
			if h.config.ReplaceCacheTime != "" {
				if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
					replaceCacheTime = parsedTime
				}
			}

			// 使用统一的云域名响应处理方法
			processedResponse := h.processCloudResponse(result.SuccessResult.Response, domain)

			// 确保云域名响应的TTL不小于配置的替换缓存时间
			h.ensureMinimumTTL(processedResponse, replaceCacheTime)
			h.cacheManager.Set(domain, qtype, processedResponse, isCloud, cloudType)
			// 同时更新云响应缓存
			h.cacheManager.SetCloudResponse(domain, qtype, processedResponse, cloudType, replaceCacheTime)
		} else {
			// 确保普通域名响应的TTL不小于配置的最小TTL
			h.ensureMinimumTTL(result.SuccessResult.Response, h.config.Cache.TTL)

			// 添加云检测器检查
			if h.cloudDetector == nil {
				h.Logger.Error("❌ [异步刷新失败] 云检测器未初始化", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[qtype],
				})
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL/2)
				return fmt.Errorf("cloud detector is nil")
			}

			// 对于非云域名且非定向域名，检测是否为云服务
			detection := h.cloudDetector.DetectCloudService(result.SuccessResult.Response, domain)
			isCloud = detection.Type != CloudTypeNone
			cloudType = int(detection.Type)

			// 如果检测到是云服务，使用统一的云域名响应处理方法
			if isCloud {
				processedResponse := h.processCloudResponse(result.SuccessResult.Response, domain)
				h.cacheManager.Set(domain, qtype, processedResponse, isCloud, cloudType)
			} else {
				h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, isCloud, cloudType)
			}
		}

		h.Logger.Info("✅ [异步刷新成功] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"is_cloud":     isCloud,
			"cloud_type":   cloudType,
			"answer_count": len(result.SuccessResult.Response.Answer),
			"upstreams":    upstreams,
		})
	} else {
		// 记录详细的失败原因
		failureReason := "unknown_error"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			failureReason = result.FastestResult.Error.Error()
		} else if !result.HasSuccess {
			failureReason = "no_successful_response"
		} else if result.SuccessResult == nil {
			failureReason = "success_result_is_nil"
		} else if result.SuccessResult.Response == nil {
			failureReason = "response_is_nil"
		} else if result.SuccessResult.Response.Rcode != dns.RcodeSuccess {
			failureReason = fmt.Sprintf("non_success_rcode: %s", dns.RcodeToString[result.SuccessResult.Response.Rcode])
		} else if len(result.SuccessResult.Response.Answer) == 0 {
			failureReason = "no_answer_records"
		}

		h.Logger.Warn("⚠️ [异步刷新跳过] ", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": failureReason,
		})

		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 这样可以避免缓存立即过期导致的查询失败
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if h.cacheManager != nil {
			h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL/2)
		}
	}

	return nil
}

// determineUpstreamsForDomain 确定域名应该使用的上游DNS服务器（使用统一的定向域名匹配）
func (h *RefactoredHandler) determineUpstreamsForDomain(domain string) []string {
	// 使用统一的定向域名匹配逻辑
	if dnsServer, hasDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain); hasDesignated {
		h.Logger.Debug("异步刷新：定向域名或默认DNS", map[string]interface{}{
			"domain":     domain,
			"dns_server": dnsServer,
		})
		return []string{dnsServer}
	}

	// 如果没有匹配到任何配置，使用上游DNS作为备用
	h.Logger.Debug("异步刷新：使用上游DNS作为备用", map[string]interface{}{
		"domain":    domain,
		"upstreams": h.config.Upstream,
	})
	return h.config.Upstream
}

// startBackgroundTasks 启动后台任务
func (h *RefactoredHandler) startBackgroundTasks() {
	// 定向域名刷新任务
	if h.config.DesignatedDomain != "" && h.config.DesignatedRefreshInterval > 0 {
		go h.designatedRefreshTask()
	}

	// 网络段刷新任务
	if h.config.NetworkRefreshInterval > 0 {
		go h.networkRefreshTask()
	}
}

// designatedRefreshTask 定向域名刷新任务
func (h *RefactoredHandler) designatedRefreshTask() {
	ticker := time.NewTicker(h.config.DesignatedRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [定向域名定时刷新启动] ", map[string]interface{}{
		"rule":     "DESIGNATED_REFRESH_TASK",
		"interval": h.config.DesignatedRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时定向域名刷新", map[string]interface{}{
				"file": h.config.DesignatedDomain,
			})
			if err := h.designatedMatcher.LoadDesignatedDomains(h.config.DesignatedDomain); err != nil {
				h.Logger.Error("❌ [定向域名刷新失败] ", map[string]interface{}{
					"rule":  "DESIGNATED_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [定向域名刷新成功] ", map[string]interface{}{
					"rule": "DESIGNATED_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [定向域名刷新任务停止] ", map[string]interface{}{
				"rule": "DESIGNATED_REFRESH_STOPPED",
			})
			return
		}
	}
}

// networkRefreshTask 网络段刷新任务
func (h *RefactoredHandler) networkRefreshTask() {
	ticker := time.NewTicker(h.config.NetworkRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
		"rule":     "NETWORK_REFRESH_TASK",
		"interval": h.config.NetworkRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时网络段刷新", map[string]interface{}{
				"cloudflare_v4": h.config.CloudflareNetFile,
				"cloudflare_v6": h.config.CloudflareNetFile6,
				"aws_file":      h.config.AWSNetFile,
			})
			if err := h.cloudDetector.LoadNetworkRanges(
				h.config.CloudflareNetFile,
				h.config.CloudflareNetFile6,
				h.config.AWSNetFile,
			); err != nil {
				h.Logger.Error("❌ [网络段刷新失败] ", map[string]interface{}{
					"rule":  "NETWORK_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [网络段刷新成功] ", map[string]interface{}{
					"rule": "NETWORK_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [网络段刷新任务停止] ", map[string]interface{}{
				"rule": "NETWORK_REFRESH_STOPPED",
			})
			return
		}
	}
}
