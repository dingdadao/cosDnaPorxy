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

	// 设置云检测器
	cacheManager.SetCloudDetector(cloudDetector)

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

	// 1. 检查有无缓存，有缓存直接返回
	// 增加判断缓存是否过期，如果过期异步刷新并且删除过期缓存
	// 异步刷新查看缓存里面标记是什么云服务，如果是Cloudflare 就走Cloudflare替换后返回结果给用户重新写入缓存
	if resp, hit, isCloud, cloudType := h.cacheManager.Get(domain, qtype); hit {
		h.Logger.Info("✅ [DNS查询结果-缓存命中] ", map[string]interface{}{
			"domain":     domain,
			"type":       "cache_hit",
			"is_cloud":   isCloud,
			"cloud_type": cloudType,
		})

		// 检查是否为替换域名缓存
		isReplaceDomain := cloudType == int(CloudTypeCloudflare) || cloudType == int(CloudTypeAWS)

		if isReplaceDomain && !isCloud {
			// 替换域名缓存命中
			h.Logger.Debug("🔍 替换域名缓存命中", map[string]interface{}{
				"domain":     domain,
				"cloud_type": cloudType,
			})

			// 确定TTL：如果是替换域名，使用replace_cache_time配置
			cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
			if h.config.ReplaceCacheTime != "" {
				if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
					cacheTTL = parsedTime
				}
			}

			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, cacheTTL)
			w.WriteMsg(respCopy)

			h.Logger.Info("✅ [DNS查询完成-来自缓存] ", map[string]interface{}{
				"domain":       domain,
				"result":       "success",
				"source":       "replace_cache",
				"answer_count": len(resp.Answer),
				"cache_ttl":    cacheTTL.String(),
			})
			return
		}

		// 直接使用缓存结果，不再执行云域名类型检查
		if isCloud && cloudType != int(CloudTypeNone) {
			// 云域名缓存命中，直接使用缓存中标记的云服务类型
			h.Logger.Info("🔍 [云域名缓存命中] ", map[string]interface{}{
				"domain":     domain,
				"cloud_type": cloudType,
				"type":       "cloud_domain_cache_hit",
			})

			// 检查是否有云响应缓存
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				h.Logger.Debug("🔍 云响应缓存命中", map[string]interface{}{
					"domain": domain,
				})
				respCopy := cloudResp.Copy()
				respCopy.Id = req.Id
				// 确保响应中的 TTL 不小于配置的最小 TTL
				h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
				w.WriteMsg(respCopy)

				h.Logger.Info("✅ [DNS查询完成-来自缓存] ", map[string]interface{}{
					"domain":       domain,
					"result":       "success",
					"source":       "cloud_cache",
					"answer_count": len(cloudResp.Answer),
				})
				return
			}

			// 没有云响应缓存，但有云域名标记，检查是否需要异步刷新
			// 如果缓存已过期，先返回现有结果并异步刷新
			h.Logger.Info("🔍 [无云响应缓存，检查是否需要异步刷新] ", map[string]interface{}{
				"domain":     domain,
				"cloud_type": cloudType,
				"type":       "check_async_refresh",
			})
			
			// 检查是否需要按需刷新
			if h.cacheManager.shouldRefreshOnDemand(domain, qtype) {
				h.Logger.Info("🔄 [提交按需刷新任务] ", map[string]interface{}{
					"domain":     domain,
					"cloud_type": cloudType,
					"type":       "submit_on_demand_refresh",
				})
				h.cacheManager.submitOnDemandRefresh(domain, qtype)
			}

			// 执行云IP替换
			h.Logger.Info("🔍 [执行云IP替换] ", map[string]interface{}{
				"domain":     domain,
				"cloud_type": cloudType,
				"type":       "execute_cloud_replacement",
			})
			h.handleCloudReplacement(w, req, domain, qtype, cloudType)
			return
		} else {
			// 普通域名缓存命中
			h.Logger.Debug("🔍 普通域名缓存命中", map[string]interface{}{
				"domain": domain,
			})
			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)

			h.Logger.Info("✅ [DNS查询完成-来自缓存] ", map[string]interface{}{
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

	// 2. 检查是不是替换域名，如果是替换域名就直接查询并缓存结果
	// 注意：这个逻辑现在通过缓存标签处理，这里保留是为了处理缓存未命中的情况
	if h.cloudDetector.IsReplaceDomain(domain) {
		h.Logger.Info("⏭️ [替换域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"type":   "replace_domain_processing",
		})

		// 直接查询替换域名
		resp, err := h.proxyQuery(req, h.config.Upstream)
		if err != nil || resp == nil {
			h.Logger.Error("❌ [替换域名查询失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		// 确定替换域名的具体云服务类型
		var replaceCloudType int = -1 // 默认值
		if domain == h.config.ReplaceCFDomain {
			replaceCloudType = int(CloudTypeCloudflare)
		} else if domain == h.config.ReplaceAWSDomain {
			replaceCloudType = int(CloudTypeAWS)
		}

		// 确定TTL：如果是替换域名，使用replace_cache_time配置
		cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
		if h.config.ReplaceCacheTime != "" {
			if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
				cacheTTL = parsedTime
			}
		}

		// 确保响应中的 TTL 不小于配置的最小 TTL
		h.ensureMinimumTTL(resp, cacheTTL)

		// 缓存替换域名的响应结果，使用具体的云服务类型作为标签
		h.cacheManager.Set(domain, qtype, resp.Copy(), false, replaceCloudType)

		resp.Id = req.Id
		w.WriteMsg(resp)

		h.Logger.Info("✅ [替换域名处理完成-来自查询] ", map[string]interface{}{
			"domain":       domain,
			"type":         "replace_domain_query",
			"answer_count": len(resp.Answer),
			"cache_ttl":    cacheTTL.String(),
			"source":       "query",
		})
		return
	}

	// 3. 检查是不是定向，如果是定向域名就走对应的域名配置的dns服务解析
	if dnsServer, isDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain); isDesignated {
		// 匹配到定向域名规则
		h.Logger.Info("🎯 [定向域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"dns":    dnsServer,
		})

		resp, err := h.proxyQueryWithCaching(req, []string{dnsServer}, domain, qtype, true) // 跳过云服务检测
		if err != nil || resp == nil {
			h.Logger.Error("❌ [定向域名处理失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		// 处理CNAME记录
		processedResp := h.processDNSResponseWithCNAME(resp, domain, []string{dnsServer})
		processedResp.Id = req.Id
		// 确保响应中的 TTL 不小于配置的最小 TTL
		h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
		w.WriteMsg(processedResp)

		h.Logger.Info("✅ [定向域名处理完成] ", map[string]interface{}{
			"domain":       domain,
			"answer_count": len(processedResp.Answer),
		})
		return
	} else {
		h.Logger.Info("❌ [定向域名未匹配] ", map[string]interface{}{
			"domain": domain,
		})
	}

	// 4. 普通查询
	h.Logger.Info("🔍 [普通查询开始] ", map[string]interface{}{
		"domain": domain,
	})

	resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [普通查询失败] ", map[string]interface{}{
			"domain":    domain,
			"upstreams": h.config.Upstream,
			"error":     err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 5. 检查是否为云服务（在返回结果给用户之前进行云检测）
	h.Logger.Info("🔍 [云服务检测开始] ", map[string]interface{}{
		"domain": domain,
		"type":   "cloud_detection",
	})
	detection := h.cloudDetector.DetectCloudService(resp, domain)
	isCloud := detection.Type != CloudTypeNone
	cloudType := int(detection.Type)

	if isCloud {
		h.Logger.Info("☁️ [云服务检测结果] ", map[string]interface{}{
			"domain":     domain,
			"type":       "cloud_detected",
			"cloud_type": detection.Type,
		})

		// 缓存云服务标记和原始查询结果
		h.cacheManager.Set(domain, qtype, resp, true, cloudType)

		// 是云服务，执行云IP替换并返回结果给用户
		h.handleCloudReplacement(w, req, domain, qtype, cloudType)
		return
	}

	// 6. 普通域名处理，如果有CNAME全部递归解析到配置的IP条数返回给用户
	h.Logger.Info("🌐 [普通域名处理开始] ", map[string]interface{}{
		"domain":    domain,
		"upstreams": h.config.Upstream,
	})

	// 处理CNAME记录
	processedResp := h.processDNSResponseWithCNAME(resp, domain, h.config.Upstream)
	processedResp.Id = req.Id
	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)

	// 缓存处理后的结果
	h.cacheManager.Set(domain, qtype, processedResp, false)

	w.WriteMsg(processedResp)

	h.Logger.Info("✅ [普通域名处理完成] ", map[string]interface{}{
		"domain":       domain,
		"answer_count": len(processedResp.Answer),
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

	// 使用通用的CNAME处理方法，传入上游DNS服务器为默认上游
	return h.processDNSResponseWithCNAME(resp, domain, h.config.Upstream)
}

// processDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录
// 优化版本：收集到足够IP记录就返回，递归CNAME使用相同DNS服务器
func (h *RefactoredHandler) processDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
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

	// 获取最大IP记录数配置，默认为2
	maxIPRecords := h.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	h.Logger.Debug("🔍 CNAME处理开始", map[string]interface{}{
		"domain":         domain,
		"max_ip_records": maxIPRecords,
		"upstreams":      upstreams,
	})

	// 收集所有IP记录（最多maxIPRecords条）
	var ipRecords []dns.RR

	// 第一遍：收集直接的IP记录
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

	h.Logger.Debug("📝 直接IP记录收集完成", map[string]interface{}{
		"domain":      domain,
		"collected":   len(ipRecords),
		"max_allowed": maxIPRecords,
	})

	// 如果已经收集到足够数量的IP记录，直接返回，不需要继续解析CNAME
	if len(ipRecords) >= maxIPRecords {
		h.Logger.Debug("✅ 已收集到足够IP记录，跳过CNAME解析", map[string]interface{}{
			"domain":    domain,
			"count":     len(ipRecords),
			"requested": maxIPRecords,
		})
	} else {
		// 如果没有足够的IP记录，尝试递归解析CNAME记录
		h.Logger.Debug("🔍 开始CNAME递归解析", map[string]interface{}{
			"domain":    domain,
			"current":   len(ipRecords),
			"need_more": maxIPRecords - len(ipRecords),
		})

		// 串行解析CNAME记录（先简化实现确保正确性）
		for _, rr := range resp.Answer {
			// 检查是否已经收集了足够数量的记录
			if len(ipRecords) >= maxIPRecords {
				break
			}

			if cname, ok := rr.(*dns.CNAME); ok {
				h.Logger.Debug("🔄 解析CNAME记录", map[string]interface{}{
					"domain": domain,
					"target": cname.Target,
				})

				// 递归解析CNAME目标，使用传入的上游DNS服务器
				cnameTargetReq := &dns.Msg{}
				cnameTargetReq.SetQuestion(cname.Target, resp.Question[0].Qtype) // 使用与原始请求相同的查询类型

				cnameTargetResp, err := h.proxyQuery(cnameTargetReq, upstreams)
				if err == nil && cnameTargetResp != nil {
					// 递归处理CNAME目标的响应
					processedCnameResp := h.processDNSResponseWithCNAME(cnameTargetResp, domain, upstreams)
					if processedCnameResp != nil {
						// 从处理后的响应中提取IP记录
						for _, targetRR := range processedCnameResp.Answer {
							// 检查是否已经收集了足够数量的记录
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
				} else {
					h.Logger.Debug("❌ CNAME解析失败", map[string]interface{}{
						"domain": domain,
						"target": cname.Target,
						"error":  err,
					})
				}
			}
		}

		h.Logger.Debug("✅ CNAME递归解析完成", map[string]interface{}{
			"domain":    domain,
			"total":     len(ipRecords),
			"max_limit": maxIPRecords,
		})
	}

	// 确保不超过最大记录数
	if len(ipRecords) > maxIPRecords {
		ipRecords = ipRecords[:maxIPRecords]
		h.Logger.Debug("✂️ 超限裁剪", map[string]interface{}{
			"domain":    domain,
			"before":    len(ipRecords),
			"after":     maxIPRecords,
			"max_limit": maxIPRecords,
		})
	}

	// 复制IP记录到处理后的响应，修改域名
	for _, rr := range ipRecords {
		newRR := dns.Copy(rr)
		newRR.Header().Name = dns.Fqdn(domain)
		processedResp.Answer = append(processedResp.Answer, newRR)
	}

	h.Logger.Debug("✅ CNAME处理完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
	})

	return processedResp
}

// handleCloudReplacement 处理云服务IP替换
func (h *RefactoredHandler) handleCloudReplacement(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, cloudType int) {
	h.Logger.Info("🔄 [云IP替换处理开始] ", map[string]interface{}{
		"original_domain": domain,
		"qtype":           dns.TypeToString[qtype],
		"cloud_type":      cloudType,
		"type":            "cloud_ip_replacement_start",
	})

	// 确定替换域名
	replaceDomain := ""
	switch CloudType(cloudType) {
	case CloudTypeCloudflare:
		replaceDomain = h.config.ReplaceCFDomain
	case CloudTypeAWS:
		replaceDomain = h.config.ReplaceAWSDomain
	default:
		h.Logger.Warn("⚠️ 未知云服务类型", map[string]interface{}{
			"cloud_type": cloudType,
			"domain":     domain,
		})
		// 回退到普通处理
		if resp, hit, _, _ := h.cacheManager.Get(domain, qtype); hit {
			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 修复：确保问题部分与原始请求匹配
			if len(respCopy.Question) > 0 && len(req.Question) > 0 {
				respCopy.Question[0] = req.Question[0]
			}
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)
		}
		return
	}

	h.Logger.Info("🔍 [云服务类型确定] ", map[string]interface{}{
		"domain":          domain,
		"replace_domain":  replaceDomain,
		"cloud_type":      cloudType,
		"cloud_type_name": CloudType(cloudType).String(),
		"type":            "cloud_service_identified",
	})

	// 使用带缓存的查询方法来获取替换域名的结果
	replaceReq := &dns.Msg{}
	replaceReq.SetQuestion(dns.Fqdn(replaceDomain), qtype)
	replaceReq.RecursionDesired = true
	replaceReq.Id = req.Id

	h.Logger.Info("🔄 [开始云IP替换查询] ", map[string]interface{}{
		"original_domain": domain,
		"replace_domain":  replaceDomain,
		"cloud_type":      CloudType(cloudType).String(),
		"type":            "cloud_ip_replacement_start",
	})

	// 使用带缓存的查询方法
	replaceResp, err := h.proxyQueryWithCachingForReplace(replaceReq, h.config.Upstream, replaceDomain, qtype)
	if err != nil || replaceResp == nil {
		h.Logger.Error("❌ [云IP替换查询失败] ", map[string]interface{}{
			"domain":         domain,
			"replace_domain": replaceDomain,
			"error":          err,
			"cloud_type":     CloudType(cloudType).String(),
		})
		// 回退到原始响应
		if resp, hit, _, _ := h.cacheManager.Get(domain, qtype); hit {
			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 修复：确保问题部分与原始请求匹配
			if len(respCopy.Question) > 0 && len(req.Question) > 0 {
				respCopy.Question[0] = req.Question[0]
			}
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			w.WriteMsg(respCopy)
		}
		return
	}

	// 修复：确保替换响应中的问题部分与原始请求匹配
	if len(replaceResp.Question) > 0 && len(req.Question) > 0 {
		replaceResp.Question[0] = req.Question[0]
	}

	// 修复：将答案部分的域名替换回原始域名
	for _, answer := range replaceResp.Answer {
		if header := answer.Header(); header != nil {
			header.Name = dns.Fqdn(domain)
		}
	}

	// 由于替换域名查询已经处理了CNAME，直接使用结果
	finalResp := replaceResp

	// 确定TTL：如果是替换域名，使用replace_cache_time配置
	cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
	if h.config.ReplaceCacheTime != "" {
		if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
			cacheTTL = parsedTime
		}
	}

	// 确保最终响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(finalResp, cacheTTL)

	// 缓存云响应结果
	h.cacheManager.SetCloudResponse(domain, qtype, finalResp.Copy(), cloudType, cacheTTL)

	// 发送响应
	finalResp.Id = req.Id
	// 修复：确保发送的响应问题部分与原始请求匹配
	if len(finalResp.Question) > 0 && len(req.Question) > 0 {
		finalResp.Question[0] = req.Question[0]
	}
	w.WriteMsg(finalResp)

	originalAnswers := len(replaceResp.Answer)
	finalAnswers := len(finalResp.Answer)

	h.Logger.Info("✅ [云IP替换成功] ", map[string]interface{}{
		"domain":         domain,
		"replace_domain": replaceDomain,
		"cloud_type":     CloudType(cloudType).String(),
		"answer_count":   finalAnswers,
		"cache_ttl":      cacheTTL.String(),
		"rule":           "CLOUD_REPLACED",
		"type":           "cloud_ip_replacement_success",
	})

	h.Logger.Debug("云IP替换详细信息", map[string]interface{}{
		"original_domain":  domain,
		"replace_domain":   replaceDomain,
		"cloud_type":       CloudType(cloudType).String(),
		"original_answers": originalAnswers,
		"final_answers":    finalAnswers,
		"max_allowed":      h.config.MaxIPRecords,
		"cache_ttl":        cacheTTL.String(),
		"cached_as_cloud":  true,
		"type":             "cloud_ip_replacement_details",
	})
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

	// 检查是否为替换域名，如果是则直接查询并缓存，避免套娃
	if h.cloudDetector.IsReplaceDomain(domain) {
		h.Logger.Debug("⏭️ 跳过异步刷新（替换域名）", map[string]interface{}{
			"domain": domain,
			"type":   "replace_domain",
		})

		// 检查替换域名是否在缓存中
		if _, hit, _, _ := h.cacheManager.Get(domain, qtype); hit {
			// 替换域名缓存命中，直接延长缓存时间
			h.Logger.Debug("🔍 替换域名缓存命中，延长缓存时间", map[string]interface{}{
				"domain": domain,
				"type":   "replace_domain",
			})

			// 确定TTL：如果是替换域名，使用replace_cache_time配置
			cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
			if h.config.ReplaceCacheTime != "" {
				if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
					cacheTTL = parsedTime
				}
			}

			// 延长缓存时间
			h.cacheManager.ExtendTTL(domain, qtype, cacheTTL)

			h.Logger.Info("✅ [替换域名缓存延长完成] ", map[string]interface{}{
				"domain":    domain,
				"type":      "replace_domain",
				"cache_ttl": cacheTTL.String(),
			})
			return nil
		} else {
			// 替换域名缓存未命中，重新查询并缓存
			h.Logger.Debug("🔍 替换域名缓存未命中，重新查询", map[string]interface{}{
				"domain": domain,
				"type":   "replace_domain",
			})

			// 直接查询替换域名并缓存结果
			req := &dns.Msg{}
			req.SetQuestion(dns.Fqdn(domain), qtype)

			resp, err := h.proxyQuery(req, h.config.Upstream)
			if err != nil || resp == nil {
				h.Logger.Error("❌ [替换域名异步刷新失败] ", map[string]interface{}{
					"domain": domain,
					"type":   "replace_domain",
					"error":  err,
				})
				return err
			}

			// 确定TTL：如果是替换域名，使用replace_cache_time配置
			cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
			if h.config.ReplaceCacheTime != "" {
				if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
					cacheTTL = parsedTime
				}
			}

			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(resp, cacheTTL)

			// 缓存替换域名的响应结果
			h.cacheManager.Set(domain, qtype, resp.Copy(), false)

			h.Logger.Info("✅ [替换域名异步刷新完成] ", map[string]interface{}{
				"domain":       domain,
				"type":         "replace_domain",
				"answer_count": len(resp.Answer),
				"cache_ttl":    cacheTTL.String(),
			})
			return nil
		}
	}

	h.Logger.Info("🔄 [异步刷新开始] ", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"type":   "async_refresh_start",
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
			_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
			if isCloud && cloudType != int(CloudTypeNone) {
				// 对于云域名，检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用配置的替换缓存时间
					replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云服务域名使用普通缓存时间
					h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
				}
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
			_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
			if isCloud && cloudType != int(CloudTypeNone) {
				// 对于云域名，检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用配置的替换缓存时间
					replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云服务域名使用普通缓存时间
					h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
				}
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
			_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
			if isCloud && cloudType != int(CloudTypeNone) {
				// 对于云域名，检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用配置的替换缓存时间
					replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云服务域名使用普通缓存时间
					h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
				}
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
			_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
			if isCloud && cloudType != int(CloudTypeNone) {
				// 对于云域名，检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用配置的替换缓存时间
					replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云服务域名使用普通缓存时间
					h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
				}
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
			_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
			if isCloud && cloudType != int(CloudTypeNone) {
				// 对于云域名，检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用配置的替换缓存时间
					replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					h.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云服务域名使用普通缓存时间
					h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL)
				}
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
		result.SuccessResult.Response.Rcode == dns.RcodeSuccess {

		// 添加缓存管理器检查
		if h.cacheManager == nil {
			h.Logger.Error("❌ [异步刷新失败] 缓存管理器未初始化", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
			})
			return fmt.Errorf("cache manager is nil")
		}

		// 检查是否匹配定向域名
		dnsServer, isDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain)

		if isDesignated {
			h.Logger.Info("🎯 [异步刷新-定向域名处理开始] ", map[string]interface{}{
				"domain": domain,
				"dns":    dnsServer,
			})

			// 对于定向域名，跳过云服务检测
			h.Logger.Info("⏭️ [异步刷新-跳过云服务检测] ", map[string]interface{}{
				"domain": domain,
				"reason": "designated_domain",
			})

			// 处理CNAME记录，使用定向域名指定的DNS服务器
			processedResp := h.processDNSResponseWithCNAME(result.SuccessResult.Response, domain, []string{dnsServer})
			h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
			h.cacheManager.Set(domain, qtype, processedResp, false, 0)

			h.Logger.Info("✅ [异步刷新-定向域名处理完成] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"answer_count": len(processedResp.Answer),
				"upstreams":    []string{dnsServer},
			})
		} else {
			// 检查是否为替换域名，如果是则直接缓存并返回结果
			if h.cloudDetector.IsReplaceDomain(domain) {
				h.Logger.Info("⏭️ [异步刷新-替换域名处理] 直接缓存", map[string]interface{}{
					"domain": domain,
					"type":   "replace_domain_direct_cache",
				})

				// 确定替换域名的具体云服务类型
				var replaceCloudType int = -1 // 默认值
				if domain == h.config.ReplaceCFDomain {
					replaceCloudType = int(CloudTypeCloudflare)
				} else if domain == h.config.ReplaceAWSDomain {
					replaceCloudType = int(CloudTypeAWS)
				}

				// 处理CNAME并限制IP数量，只缓存处理后的结果
				processedResp := h.processDNSResponseWithCNAME(result.SuccessResult.Response, domain, upstreams)

				// 确定TTL：如果是替换域名，使用replace_cache_time配置
				cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						cacheTTL = parsedTime
					}
				}

				// 确保响应中的 TTL 不小于配置的最小 TTL
				h.ensureMinimumTTL(processedResp, cacheTTL)

				// 修复：缓存处理后的替换域名响应结果，使用具体的云服务类型作为标签
				// 注意：对于替换域名，isCloud参数应为false，cloudType参数用于标识具体的云服务商
				h.cacheManager.Set(domain, qtype, processedResp.Copy(), false, replaceCloudType)

				h.Logger.Info("✅ [异步刷新-替换域名处理完成] ", map[string]interface{}{
					"domain":       domain,
					"cloud_type":   replaceCloudType,
					"type":         "replace_domain",
					"answer_count": len(processedResp.Answer),
					"cache_ttl":    cacheTTL.String(),
					"source":       "async_refresh",
				})
				return nil
			}

			h.Logger.Info("🌐 [异步刷新-普通域名处理开始] ", map[string]interface{}{
				"domain": domain,
			})

			// 添加云检测器检查
			if h.cloudDetector == nil {
				h.Logger.Error("❌ [异步刷新失败] 云检测器未初始化", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[qtype],
				})
				h.cacheManager.ExtendTTL(domain, qtype, h.config.Cache.TTL/2)
				return fmt.Errorf("cloud detector is nil")
			}

			// 检查是否为云服务
			h.Logger.Info("🔍 [异步刷新-云服务检测开始] ", map[string]interface{}{
				"domain": domain,
			})
			detection := h.cloudDetector.DetectCloudService(result.SuccessResult.Response, domain)
			isCloud := detection.Type != CloudTypeNone
			cloudType := int(detection.Type)

			if isCloud {
				h.Logger.Info("☁️ [异步刷新-云服务检测结果] ", map[string]interface{}{
					"domain":     domain,
					"cloud_type": detection.Type,
				})

				// 解析缓存时间配置 - 只有替换域名才使用replace_cache_time
				cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL

				// 检查是否为替换域名来决定使用哪种缓存时间
				if h.cloudDetector.IsReplaceDomain(domain) {
					// 只有替换域名才使用replace_cache_time配置
					if h.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
							cacheTTL = parsedTime
						}
					}
				} else {
					// 普通云服务域名使用普通缓存时间
					cacheTTL = h.config.Cache.TTL
				}

				// 使用统一的云域名响应处理方法，使用上游DNS服务器
				processedResponse := h.processCloudResponse(result.SuccessResult.Response, domain)

				// 确保云域名响应的TTL不小于配置的缓存时间
				h.ensureMinimumTTL(processedResponse, cacheTTL)
				// 只更新云响应缓存，不更新普通缓存
				h.cacheManager.SetCloudResponse(domain, qtype, processedResponse, cloudType, cacheTTL)

				h.Logger.Info("✅ [异步刷新-云服务处理完成] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"answer_count": len(processedResponse.Answer),
					"upstreams":    upstreams,
					"cloud_type":   cloudType,
					"cache_ttl":    cacheTTL.String(),
				})
			} else {
				h.Logger.Info("❌ [异步刷新-非云服务域名] ", map[string]interface{}{
					"domain": domain,
				})

				// 对于普通域名，处理CNAME记录
				processedResp := h.processDNSResponseWithCNAME(result.SuccessResult.Response, domain, upstreams)
				h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
				// 对于普通域名，不需要传递云服务类型
				h.cacheManager.Set(domain, qtype, processedResp, false)

				h.Logger.Info("✅ [异步刷新-普通域名处理完成] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"answer_count": len(processedResp.Answer),
					"upstreams":    upstreams,
				})
			}
		}
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

// proxyQueryWithCaching 带缓存的DNS查询（用于替换域名查询）
func (h *RefactoredHandler) proxyQueryWithCachingForReplace(req *dns.Msg, upstream []string, domain string, qtype uint16) (*dns.Msg, error) {
	h.Logger.Info("🔄 [替换域名查询开始] ", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
		"type":   "replace_domain_query_start",
	})

	// 检查是否有替换域名的缓存
	// 修复：正确检查替换域名缓存，需要检查cloudType来确定是否为替换域名缓存
	if resp, hit, isCloud, cloudType := h.cacheManager.Get(domain, qtype); hit {
		// 检查是否为替换域名缓存（cloudType为1表示Cloudflare，2表示AWS）
		isReplaceDomain := cloudType == int(CloudTypeCloudflare) || cloudType == int(CloudTypeAWS)

		if isReplaceDomain && !isCloud {
			h.Logger.Info("✅ [替换域名查询-缓存命中] ", map[string]interface{}{
				"domain":     domain,
				"source":     "cache",
				"type":       "replace_domain_cache_hit",
				"cloud_type": cloudType,
			})

			respCopy := resp.Copy()
			respCopy.Id = req.Id
			// 修复：确保缓存命中时问题部分与原始请求匹配
			if len(respCopy.Question) > 0 && len(req.Question) > 0 {
				respCopy.Question[0] = req.Question[0]
			}
			return respCopy, nil
		}
	}

	h.Logger.Info("🔄 [替换域名查询-缓存未命中] ", map[string]interface{}{
		"domain": domain,
		"source": "query",
		"type":   "replace_domain_cache_miss",
	})

	// 执行实际查询
	h.Logger.Debug("📡 [替换域名查询-发起实际查询] ", map[string]interface{}{
		"domain":   domain,
		"upstream": upstream,
		"type":     "replace_domain_actual_query",
	})

	resp, err := h.proxyQuery(req, upstream)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [替换域名查询失败] ", map[string]interface{}{
			"domain": domain,
			"error":  err,
			"type":   "replace_domain_query_error",
		})
		return nil, err
	}

	h.Logger.Debug("✅ [替换域名查询成功] ", map[string]interface{}{
		"domain":     domain,
		"answers":    len(resp.Answer),
		"rcode":      dns.RcodeToString[resp.Rcode],
		"query_time": "unknown", // 这里可以添加实际的查询时间统计
		"type":       "replace_domain_query_success",
	})

	// 处理CNAME并限制IP数量，只缓存处理后的结果
	processedResp := h.processDNSResponseWithCNAME(resp, domain, upstream)

	// 确定TTL：如果是替换域名，使用replace_cache_time配置
	cacheTTL := h.config.Cache.TTL // 默认使用普通缓存TTL
	if h.config.ReplaceCacheTime != "" {
		if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
			cacheTTL = parsedTime
		}
	}

	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(processedResp, cacheTTL)

	// 缓存处理后的替换域名响应结果
	// 确定替换域名的具体云服务类型
	var replaceCloudType int = -1 // 默认值
	if h.cloudDetector != nil {
		if domain == h.config.ReplaceCFDomain {
			replaceCloudType = int(CloudTypeCloudflare)
		} else if domain == h.config.ReplaceAWSDomain {
			replaceCloudType = int(CloudTypeAWS)
		}
	}

	// 修复：缓存替换域名响应时传递cloudType参数
	h.cacheManager.Set(domain, qtype, processedResp.Copy(), false, replaceCloudType)

	h.Logger.Info("💾 [替换域名查询结果已缓存] ", map[string]interface{}{
		"domain":    domain,
		"answers":   len(processedResp.Answer),
		"cache_ttl": cacheTTL.String(),
		"source":    "query_and_cache",
		"type":      "replace_domain_cached",
	})

	return processedResp, nil
}
