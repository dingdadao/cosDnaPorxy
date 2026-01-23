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
	cacheManager   *CacheManager
	cloudDetector  *CloudDetector
	queryOptimizer interface{} // 可以是 *FastQueryOptimizer 或 *SimpleModernOptimizer
	matcherHandler *MatcherHandler
	cloudHandler   *CloudHandler
	refreshHandler *RefreshHandler
	fileLoader     *FileLoader
	taskScheduler  *TaskScheduler

	// 新增处理器
	cnameProcessor *CNAMEProcessor
	cloudProcessor *CloudProcessor

	ctx    context.Context
	cancel context.CancelFunc
}

// NewRefactoredHandler 创建新的重构后处理器
func NewRefactoredHandler(cfg *config.Config, logger *utils.EnhancedLogger) (*RefactoredHandler, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// 创建核心组件（移除指标系统）
	cloudDetector := NewCloudDetector(logger, nil)

	// 设置替换域名配置
	cloudDetector.SetReplaceDomains(cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)

	// 创建缓存管理器，传入云检测器
	cacheManager := NewCacheManager(cfg, logger, cloudDetector, nil)

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

	// 初始化处理器结构体
	handler := &RefactoredHandler{
		config:         cfg,
		Logger:         logger, // 使用公共字段
		cacheManager:   cacheManager,
		cloudDetector:  cloudDetector,
		queryOptimizer: queryOptimizer,
		ctx:            ctx,
		cancel:         cancel,
	}

	// 初始化匹配处理器 - 传递完整的handler实例
	matcherHandler := NewMatcherHandler(cfg, logger, handler)
	handler.matcherHandler = matcherHandler
	if cfg.DefaultDNS != "" {
		matcherHandler.GetYAMLMatcher().SetDefaultDNS(cfg.DefaultDNS)
	}

	// 初始化云服务处理器
	cloudHandler := NewCloudHandler(cfg, logger, cacheManager, cloudDetector, handler.proxyQuery)
	handler.cloudHandler = cloudHandler

	// 初始化文件加载处理器
	fileLoader := NewFileLoader(cfg, logger, cloudDetector, matcherHandler)
	handler.fileLoader = fileLoader

	// 初始化任务调度器
	taskScheduler := NewTaskScheduler(cfg, logger, fileLoader, cloudDetector)
	handler.taskScheduler = taskScheduler

	// 初始化刷新处理器
	refreshHandler := NewRefreshHandler(cfg, logger, cacheManager, cloudDetector, queryOptimizer, matcherHandler, handler.proxyQuery)
	handler.refreshHandler = refreshHandler

	// 初始化CNAME处理器
	cnameProcessor := NewCNAMEProcessor(cfg, logger, handler.proxyQuery, cacheManager)
	handler.cnameProcessor = cnameProcessor

	// 初始化云服务处理器
	cloudProcessor := NewCloudProcessor(cfg, logger, handler.proxyQuery)
	handler.cloudProcessor = cloudProcessor

	// 设置缓存回调
	handler.cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 根据开关决定是否加载数据
	if err := handler.fileLoader.LoadSelectiveData(
		cfg.EnableChinaDomainCheck,
		cfg.EnableCloudflareCheck || cfg.EnableAWSCheck,
	); err != nil {
		logger.Error("选择性加载数据失败，但继续启动", map[string]interface{}{
			"error": err.Error(),
		})
		// 即使加载失败也继续启动，确保服务可用
	}

	// 启动后台任务
	handler.taskScheduler.StartBackgroundTasks()

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

		// 目前重点处理A和AAAA记录（IP地址记录）
		// 其他记录类型（如NS、MX等）也会被处理，但不经过云服务检测优化
		if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
			// 对于非A/AAAA记录，仍然进行查询，但跳过云服务检测和替换逻辑
			h.processNonIPQuery(w, req, domain, q.Qtype)
			return // 处理完后返回
		}

		h.processQuery(w, req, domain, q.Qtype)
		return // 只处理第一个有效问题
	}
}

// processNonIPQuery 处理非IP记录类型的DNS查询（如NS、MX、TXT等）
func (h *RefactoredHandler) processNonIPQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16) {
	// 非IP记录类型直接查询上游DNS服务器，不经过云服务检测和替换逻辑
	// 但仍经过缓存处理

	// 1. 检查缓存
	resp, hit, _, _ := h.cacheManager.Get(domain, qtype)
	if hit {
		respCopy := resp.Copy()
		h.cnameProcessor.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
		respCopy.Id = req.Id
		w.WriteMsg(respCopy)

		h.Logger.Info("✅ [DNS查询完成-非IP记录-缓存命中] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "cache_non_ip",
			"answer_count": len(respCopy.Answer),
			"result":       "success",
		})
		return
	}

	// 2. 确定上游服务器
	upstreams := h.determineUpstreamsForDomain(domain)

	// 3. 执行查询（不经过云服务检测和替换逻辑）
	resp, err := h.proxyQuery(req, upstreams)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [非IP记录查询失败] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"error":       err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 4. 处理响应 - 特别处理CNAME记录
	respCopy := resp.Copy()
	processedResp := h.cnameProcessor.ProcessNonIPResponseWithCNAME(respCopy, domain, qtype, upstreams)

	// 5. 验证响应是否有效
	mockResult := &ConcurrentQueryResult{
		FastestResult: &QueryResult{
			Response: processedResp,
			Error:    nil,
		},
	}

	if h.IsValidNonIPDNSResult(mockResult) {
		h.cnameProcessor.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
		// 6. 缓存结果
		h.cacheManager.Set(domain, qtype, processedResp, false)

		// 7. 返回响应
		processedResp.Id = req.Id
		w.WriteMsg(processedResp)

		h.Logger.Info("✅ [DNS查询完成-非IP记录] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "non_ip",
			"answer_count": len(processedResp.Answer),
			"auth_count":   len(processedResp.Ns),
			"extra_count":  len(processedResp.Extra),
			"rcode":        dns.RcodeToString[processedResp.Rcode],
			"result":       "success",
		})
	} else {
		h.Logger.Error("❌ [非IP记录响应无效] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"rcode":       dns.RcodeToString[processedResp.Rcode],
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}
}

// processQuery 处理单个DNS查询
func (h *RefactoredHandler) processQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16) {
	// 开始计时整个处理过程
	totalTimer := h.Logger.StartTimer("total_dns_request")
	defer totalTimer.End()

	// 1. 缓存检查（使用单飞行模式避免重复查询）
	resp, hit, _, _ := h.cacheManager.GetWithFlight(domain, qtype)
	if hit {
		// 检查域名级别的云服务状态，确保A/AAAA记录处理一致性
		isDomainCloud := h.cacheManager.IsDomainCloud(domain)

		// 云域名缓存命中
		if isDomainCloud {
			// 检查是否有云响应缓存
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				// 有云响应缓存，直接返回
				respCopy := cloudResp.Copy()
				// 确保响应中的 TTL 不小于配置的最小 TTL
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
				h.cnameProcessor.ensureMinimumTTL(respCopy, replaceCacheTime)
				respCopy.Id = req.Id
				w.WriteMsg(respCopy)
				totalTime := totalTimer.End()
				h.Logger.Info("✅ [DNS查询完成-缓存命中-云域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"client_addr":  w.RemoteAddr().String(),
					"source":       "cache_cloud",
					"answer_count": len(respCopy.Answer),
					"result":       "success",
					"total_time":   totalTime,
				})
				return
			}
		} else {
			// 普通域名缓存命中
			respCopy := resp.Copy()
			h.cnameProcessor.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			respCopy.Id = req.Id
			w.WriteMsg(respCopy)
			totalTime := totalTimer.End()
			h.Logger.Info("✅ [DNS查询完成-缓存命中] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"client_addr":  w.RemoteAddr().String(),
				"source":       "cache_normal",
				"answer_count": len(respCopy.Answer),
				"result":       "success",
				"total_time":   totalTime,
			})
			return
		}
	}

	// 确定上游服务器
	upstreams := h.determineUpstreamsForDomain(domain)

	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query")

	// 2. 代理查询上游DNS服务器
	resp, err := h.proxyQueryWithCaching(req, upstreams, domain, qtype)
	upstreamTime := upstreamTimer.End()

	if err != nil || resp == nil {
		upstreamTimer.End() // 确保计时器关闭
		totalTime := totalTimer.End()
		h.Logger.Error("❌ [上游域名查询失败，请检查上游] ", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"client_addr":   w.RemoteAddr().String(),
			"error":         err,
			"total_time":    totalTime,
			"upstream_time": upstreamTime,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 计时CNAME处理
	cnameTimer := h.Logger.StartTimer("cname_processing")

	// 先对响应进行CNAME递归解析，获取最终的响应
	resolvedResp := h.cnameProcessor.ProcessDNSResponseWithCNAME(resp, domain, h.config.Upstream)
	cnameProcessingTime := cnameTimer.End()

	// 检查解析后的响应是否包含IP记录，如果有IP则进行云服务检测
	// 但首先要检查域名是否是替换域名，如果是替换域名则跳过云服务检测
	var hasResolvedIP bool
	for _, rr := range resolvedResp.Answer {
		if _, ok := rr.(*dns.A); ok || isAAAARecord(rr) {
			hasResolvedIP = true
			break
		}
	}

	// 计时云服务检测
	cloudDetectionTimer := h.Logger.StartTimer("cloud_detection")

	if hasResolvedIP && !h.cloudDetector.IsReplaceDomain(domain) {
		// 解析后的响应包含IP，且不是替换域名，进行云服务检测
		// 根据配置开关分别检测Cloudflare和AWS
		var detection *CloudDetectionResult
		isCloud := false

		if h.config.EnableCloudflareCheck {
			// 检查Cloudflare
			cfDetection := h.cloudDetector.DetectCloudflareService(resolvedResp)
			if cfDetection.Type != CloudTypeNone {
				detection = cfDetection
				isCloud = true
			}
		}

		if !isCloud && h.config.EnableAWSCheck {
			// 如果不是Cloudflare，检查AWS
			awsDetection := h.cloudDetector.DetectAWSService(resolvedResp)
			if awsDetection.Type != CloudTypeNone {
				detection = awsDetection
				isCloud = true
			}
		}

		if isCloud && detection != nil {
			// 这是一个云域名，需要进行IP替换
			h.Logger.Info("☁️ [云域名检测到，开始替换处理] ", map[string]interface{}{
				"domain":         domain,
				"cloud_type":     detection.Type,
				"replace_domain": detection.ReplaceDomain,
			})

			// 使用云处理器进行替换处理
			_ = h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, int(detection.Type))
			cloudDetectionTime := cloudDetectionTimer.End()
			totalTime := totalTimer.End()
			h.Logger.Info("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
				"domain":                domain,
				"qtype":                 dns.TypeToString[qtype],
				"client_addr":           w.RemoteAddr().String(),
				"source":                "cloud_replacement",
				"answer_count":          len(resolvedResp.Answer),
				"result":                "success",
				"total_time":            totalTime,
				"upstream_time":         upstreamTime,
				"cname_processing_time": cnameProcessingTime,
				"cloud_detection_time":  cloudDetectionTime,
			})
			return
		}
	}
	cloudDetectionTime := cloudDetectionTimer.End()

	// 如果不是云服务域名，返回CNAME解析后的最终结果
	processedResp := resolvedResp
	processedResp.Id = req.Id
	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.cnameProcessor.ensureMinimumTTL(processedResp, h.config.Cache.TTL)

	// 记录实际返回给客户端的响应详情
	answerDetails := make([]map[string]interface{}, 0)
	for _, ans := range processedResp.Answer {
		answerDetail := map[string]interface{}{
			"type": dns.TypeToString[ans.Header().Rrtype],
			"name": ans.Header().Name,
		}
		switch rr := ans.(type) {
		case *dns.A:
			answerDetail["ip"] = rr.A.String()
		case *dns.AAAA:
			answerDetail["ip"] = rr.AAAA.String()
		case *dns.CNAME:
			answerDetail["target"] = rr.Target
		}
		answerDetails = append(answerDetails, answerDetail)
	}

	h.Logger.Debug("📤 实际返回给客户端的响应", map[string]interface{}{
		"domain":       req.Question[0].String(),
		"answer_count": len(processedResp.Answer),
		"answers":      answerDetails,
		"rcode":        dns.RcodeToString[processedResp.Rcode],
	})

	w.WriteMsg(processedResp)

	// 检查域名级别的云服务状态来判断是否为云服务域名（确保A/AAAA记录处理一致性）
	isDomainCloud := h.cacheManager.IsDomainCloud(domain)
	if isDomainCloud {
		totalTime := totalTimer.End()
		h.Logger.Info("✅ [DNS查询完成-云服务域名] ", map[string]interface{}{
			"domain":                domain,
			"qtype":                 dns.TypeToString[qtype],
			"client_addr":           w.RemoteAddr().String(),
			"source":                "cloud",
			"answer_count":          len(processedResp.Answer),
			"result":                "success",
			"total_time":            totalTime,
			"upstream_time":         upstreamTime,
			"cname_processing_time": cnameProcessingTime,
			"cloud_detection_time":  cloudDetectionTime,
		})
	} else {
		totalTime := totalTimer.End()
		h.Logger.Info("✅ [DNS查询完成-普通域名] ", map[string]interface{}{
			"domain":                domain,
			"qtype":                 dns.TypeToString[qtype],
			"client_addr":           w.RemoteAddr().String(),
			"source":                "normal",
			"answer_count":          len(processedResp.Answer),
			"result":                "success",
			"total_time":            totalTime,
			"upstream_time":         upstreamTime,
			"cname_processing_time": cnameProcessingTime,
			"cloud_detection_time":  cloudDetectionTime,
		})
	}
}

// sendErrorResponse 发送错误响应
func (h *RefactoredHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	w.WriteMsg(resp)
}

// GetStats 获取统计信息
func (h *RefactoredHandler) GetStats() map[string]interface{} {
	cacheStats := h.cacheManager.GetStats(false)

	return map[string]interface{}{
		"cache": cacheStats,
	}
}

// GetCacheManager 获取缓存管理器
func (h *RefactoredHandler) GetCacheManager() *CacheManager {
	return h.cacheManager
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

// refreshDNSRecord 刷新DNS记录（缓存回调）
func (h *RefactoredHandler) refreshDNSRecord(domain string, qtype uint16) error {
	return h.refreshHandler.RefreshDNSRecord(domain, qtype)
}

// determineUpstreamsForDomain 确定域名应该使用的上游DNS服务器（使用统一的定向域名匹配）
func (h *RefactoredHandler) determineUpstreamsForDomain(domain string) []string {
	// 使用统一的定向域名匹配逻辑
	if dnsServer, hasDesignated := h.matcherHandler.GetYAMLMatcher().GetDesignatedDomainOrDefault(domain); hasDesignated {
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

// isAAAARecord 检查记录是否为AAAA记录
func isAAAARecord(rr dns.RR) bool {
	_, ok := rr.(*dns.AAAA)
	return ok
}

// formatAnswerRecords 格式化回答记录用于日志
func formatAnswerRecords(records []dns.RR) []map[string]interface{} {
	formatted := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		recordInfo := map[string]interface{}{
			"type": dns.TypeToString[record.Header().Rrtype],
			"name": record.Header().Name,
		}
		switch rr := record.(type) {
		case *dns.A:
			recordInfo["ip"] = rr.A.String()
		case *dns.AAAA:
			recordInfo["ip"] = rr.AAAA.String()
		case *dns.CNAME:
			recordInfo["target"] = rr.Target
		}
		formatted = append(formatted, recordInfo)
	}
	return formatted
}

// processDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录
func (h *RefactoredHandler) processDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	return h.cnameProcessor.ProcessDNSResponseWithCNAME(resp, domain, upstreams)
}

// processCloudResponse 处理云域名响应，确保符合DNS协议标准
func (h *RefactoredHandler) processCloudResponse(resp *dns.Msg, domain string) *dns.Msg {
	return h.cnameProcessor.ProcessDNSResponseWithCNAME(resp, domain, h.config.Upstream)
}

// processDNSResponseWithCNAMEAggressive 更积极地解析CNAME记录以收集更多IP
func (h *RefactoredHandler) processDNSResponseWithCNAMEAggressive(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	return h.cnameProcessor.ProcessDNSResponseWithCNAMEAggressive(resp, domain, upstreams)
}

// ensureMinimumTTL 确保响应中的 TTL 不小于指定的最小值
func (h *RefactoredHandler) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
	h.cnameProcessor.ensureMinimumTTL(resp, minTTL)
}

// replaceCloudIPs 用替换域名的IP替换原始响应中的云服务IP
func (h *RefactoredHandler) replaceCloudIPs(originalResp *dns.Msg, originalDetection *CloudDetectionResult) *dns.Msg {
	return h.cloudProcessor.ReplaceCloudIPs(originalResp, originalDetection)
}
