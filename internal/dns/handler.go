package dns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
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

// DesignatedMatcherInterface 定向域名匹配器接口
type DesignatedMatcherInterface interface {
	GetDesignatedDomainOrDefault(domain string) (string, bool)
	LoadDesignatedDomains(filePath string) error
	GetStats() map[string]interface{}
}

// RefactoredHandler 重构后的DNS处理器
type RefactoredHandler struct {
	config *config.Config
	Logger *utils.EnhancedLogger // 改为公共字段

	// 核心组件
	cacheManager      *CacheManager
	cloudDetector     *CloudDetector
	queryOptimizer    interface{} // 可以是 *FastQueryOptimizer 或 *SimpleModernOptimizer
	designatedMatcher DesignatedMatcherInterface
	chinaMatcher      *ChinaDomainMatcher

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

	// 初始化YAML格式匹配器
	yamlMatcher := NewYAMLMatcher(logger)
	if cfg.DefaultDNS != "" {
		yamlMatcher.SetDefaultDNS(cfg.DefaultDNS)
	}

	// 初始化中国域名匹配器
	chinaMatcher := NewChinaDomainMatcher(logger)

	handler := &RefactoredHandler{
		config:            cfg,
		Logger:            logger, // 使用公共字段
		cacheManager:      cacheManager,
		cloudDetector:     cloudDetector,
		queryOptimizer:    queryOptimizer,
		designatedMatcher: yamlMatcher, // 使用YAML格式匹配器
		chinaMatcher:      chinaMatcher,
		ctx:               ctx,
		cancel:            cancel,
	}

	// 设置缓存回调
	cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 加载所有数据
	if err := handler.loadAllData(); err != nil {
		logger.Error("加载数据失败，但继续启动", map[string]interface{}{
			"error": err.Error(),
		})
		// 即使加载失败也继续启动，确保服务可用
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
	// 1. 缓存检查
	if resp, hit, isCloud, cloudType := h.cacheManager.Get(domain, qtype); hit {
		// 云域名缓存命中
		if isCloud {
			// 云域名需要特殊处理
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				respCopy := cloudResp.Copy()
				respCopy.Id = req.Id
				// 确保响应中的 TTL 不小于配置的最小 TTL
				h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
				w.WriteMsg(respCopy)

				cloudTypeName := "unknown"
				switch CloudType(cloudType) {
				case CloudTypeCloudflare:
					cloudTypeName = "Cloudflare"
				case CloudTypeAWS:
					cloudTypeName = "AWS"
				}

				h.Logger.Info("✅ [DNS查询完成-云域名缓存] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"client_addr":  w.RemoteAddr().String(),
					"source":       "cloud_cache",
					"cloud_type":   cloudTypeName,
					"answer_count": len(cloudResp.Answer),
					"result":       "success",
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

			h.Logger.Info("✅ [DNS查询完成-普通缓存] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"client_addr":  w.RemoteAddr().String(),
				"source":       "normal_cache",
				"answer_count": len(resp.Answer),
				"result":       "success",
			})
			return
		}
	}

	// 2. YAML定向域名检查（最高优先级）
	if dnsServer, isDesignated := h.designatedMatcher.GetDesignatedDomainOrDefault(domain); isDesignated {
		// 匹配到定向域名规则
		h.Logger.Info("🎯 [YAML定向域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"dns":    dnsServer,
		})

		resp, err := h.proxyQueryWithCaching(req, []string{dnsServer}, domain, qtype, true) // 跳过云服务检测
		if err != nil || resp == nil {
			h.Logger.Error("❌ [YAML定向域名处理失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		resp.Id = req.Id
		// 确保响应中的 TTL 不小于配置的最小 TTL
		h.ensureMinimumTTL(resp, h.config.Cache.TTL)
		w.WriteMsg(resp)

		h.Logger.Info("✅ [DNS查询完成-YAML定向域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "designated",
			"dns_server":   dnsServer,
			"answer_count": len(resp.Answer),
			"result":       "success",
		})
		return
	}

	// 3. 替换域名检查
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

		h.Logger.Info("✅ [DNS查询完成-替换域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "replace_domain",
			"answer_count": len(resp.Answer),
			"result":       "success",
		})
		return
	}

	// 4. 中国域名检查
	if h.chinaMatcher.IsChinaDomain(domain) {
		h.Logger.Info("🇨🇳 [中国域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"dns":    h.config.ChinaDNS,
		})

		// 使用中国DNS服务器处理
		upstreams := []string{h.config.ChinaDNS}
		if h.config.ChinaDNS == "" {
			// 如果没有配置中国DNS，使用默认DNS
			upstreams = h.config.Upstream
		}

		resp, err := h.proxyQueryWithCaching(req, upstreams, domain, qtype, true) // 跳过云服务检测
		if err != nil || resp == nil {
			h.Logger.Error("❌ [中国域名处理失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			h.sendErrorResponse(w, req, dns.RcodeServerFailure)
			return
		}

		resp.Id = req.Id
		// 确保响应中的 TTL 不小于配置的最小 TTL
		h.ensureMinimumTTL(resp, h.config.Cache.TTL)
		w.WriteMsg(resp)

		h.Logger.Info("✅ [DNS查询完成-中国域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "china_domain",
			"answer_count": len(resp.Answer),
			"result":       "success",
		})
		return
	}

	// 5. 普通域名处理逻辑
	resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [普通域名处理失败] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"error":       err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	resp.Id = req.Id
	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(resp, h.config.Cache.TTL)
	w.WriteMsg(resp)

	h.Logger.Info("✅ [DNS查询完成-普通域名] ", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"client_addr":  w.RemoteAddr().String(),
		"source":       "normal",
		"answer_count": len(resp.Answer),
		"result":       "success",
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

	h.Logger.Info("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
		"domain":         domain,
		"qtype":          dns.TypeToString[qtype],
		"client_addr":    w.RemoteAddr().String(),
		"source":         "cloud_replacement",
		"cloud_type":     cloudTypeName,
		"replace_domain": replaceDomain,
		"answer_count":   len(finalResp.Answer),
		"cache_ttl":      replaceCacheTime.String(),
		"result":         "success",
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
	if err := h.loadDesignatedDomains(); err != nil { // 使用loadDesignatedDomains方法，确保下载失败时保留旧文件
		h.Logger.Error("加载定向域名失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	// 加载中国域名列表
	if err := h.loadChinaDomains(); err != nil {
		h.Logger.Error("加载中国域名失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	return lastErr
}

// loadChinaDomains 加载中国域名列表
func (h *RefactoredHandler) loadChinaDomains() error {
	if h.config.ChinaDomainFile == "" {
		h.Logger.Warn("中国域名文件路径为空，跳过加载")
		return nil
	}

	// 如果配置了URL，尝试下载更新文件
	if h.config.ChinaDomainFileURL != "" {
		h.Logger.Info("尝试下载更新中国域名文件", map[string]interface{}{
			"file": h.config.ChinaDomainFile,
			"url":  h.config.ChinaDomainFileURL,
		})

		// 创建临时文件下载更新
		tempFile := h.config.ChinaDomainFile + ".tmp"
		err := h.downloadFile(h.config.ChinaDomainFileURL, tempFile)
		if err != nil {
			h.Logger.Error("下载中国域名文件失败，使用现有文件", map[string]interface{}{
				"error": err.Error(),
				"file":  h.config.ChinaDomainFile,
			})
			// 删除临时文件
			os.Remove(tempFile)
		} else {
			// 检查下载的文件是否为空
			fileInfo, err := os.Stat(tempFile)
			if err != nil {
				h.Logger.Error("获取临时文件信息失败，使用现有文件", map[string]interface{}{
					"error": err.Error(),
					"file":  tempFile,
				})
				os.Remove(tempFile)
			} else if fileInfo.Size() == 0 {
				h.Logger.Warn("下载的中国域名文件为空，使用现有文件", map[string]interface{}{
					"file": tempFile,
				})
				// 删除空的临时文件
				os.Remove(tempFile)
			} else {
				h.Logger.Info("成功下载中国域名文件，准备替换", map[string]interface{}{
					"temp_file":   tempFile,
					"target_file": h.config.ChinaDomainFile,
					"size":        fileInfo.Size(),
				})
				// 用新文件替换旧文件
				if err := os.Rename(tempFile, h.config.ChinaDomainFile); err != nil {
					h.Logger.Error("替换中国域名文件失败", map[string]interface{}{
						"error": err.Error(),
					})
					// 删除临时文件
					os.Remove(tempFile)
				} else {
					h.Logger.Info("成功更新中国域名文件", map[string]interface{}{
						"file": h.config.ChinaDomainFile,
					})
				}
			}
		}
	} else {
		// 检查文件是否存在，如果不存在则创建空文件
		if _, err := os.Stat(h.config.ChinaDomainFile); os.IsNotExist(err) {
			h.Logger.Info("创建空的中国域名文件", map[string]interface{}{
				"file": h.config.ChinaDomainFile,
			})
			if err := os.WriteFile(h.config.ChinaDomainFile, []byte{}, 0644); err != nil {
				return err
			}
		}
	}

	// 使用中国域名匹配器加载配置
	err := h.chinaMatcher.LoadChinaDomains(h.config.ChinaDomainFile)
	if err != nil {
		return fmt.Errorf("加载中国域名配置失败: %w", err)
	}

	h.Logger.Info("中国域名加载完成", map[string]interface{}{
		"file": h.config.ChinaDomainFile,
	})

	return nil
}

// loadDesignatedDomains 加载定向域名列表
func (h *RefactoredHandler) loadDesignatedDomains() error {
	if h.config.DesignatedDomain == "" {
		h.Logger.Warn("定向域名文件路径为空，跳过加载")
		return nil
	}

	// 如果配置了URL，尝试下载更新文件
	if h.config.DesignatedDomainURL != "" {
		h.Logger.Info("尝试下载更新定向域名文件", map[string]interface{}{
			"file": h.config.DesignatedDomain,
			"url":  h.config.DesignatedDomainURL,
		})

		// 创建临时文件下载更新
		tempFile := h.config.DesignatedDomain + ".tmp"
		err := h.downloadFile(h.config.DesignatedDomainURL, tempFile)
		if err != nil {
			h.Logger.Error("下载定向域名文件失败，使用现有文件", map[string]interface{}{
				"error": err.Error(),
				"file":  h.config.DesignatedDomain,
			})
			// 删除临时文件
			os.Remove(tempFile)
		} else {
			// 检查下载的文件是否为空
			fileInfo, err := os.Stat(tempFile)
			if err != nil {
				h.Logger.Error("获取临时文件信息失败，使用现有文件", map[string]interface{}{
					"error": err.Error(),
					"file":  tempFile,
				})
				os.Remove(tempFile)
			} else if fileInfo.Size() == 0 {
				h.Logger.Warn("下载的定向域名文件为空，使用现有文件", map[string]interface{}{
					"file": tempFile,
				})
				// 删除空的临时文件
				os.Remove(tempFile)
			} else {
				h.Logger.Info("成功下载定向域名文件，准备替换", map[string]interface{}{
					"temp_file":   tempFile,
					"target_file": h.config.DesignatedDomain,
					"size":        fileInfo.Size(),
				})
				// 用新文件替换旧文件
				if err := os.Rename(tempFile, h.config.DesignatedDomain); err != nil {
					h.Logger.Error("替换定向域名文件失败", map[string]interface{}{
						"error": err.Error(),
					})
					// 删除临时文件
					os.Remove(tempFile)
				} else {
					h.Logger.Info("成功更新定向域名文件", map[string]interface{}{
						"file": h.config.DesignatedDomain,
					})
				}
			}
		}
	} else {
		// 检查文件是否存在，如果不存在则创建空文件
		if _, err := os.Stat(h.config.DesignatedDomain); os.IsNotExist(err) {
			h.Logger.Info("创建空的定向域名文件", map[string]interface{}{
				"file": h.config.DesignatedDomain,
			})
			if err := os.WriteFile(h.config.DesignatedDomain, []byte{}, 0644); err != nil {
				return err
			}
		}
	}

	// 使用定向域名匹配器加载配置
	err := h.designatedMatcher.LoadDesignatedDomains(h.config.DesignatedDomain)
	if err != nil {
		return fmt.Errorf("加载定向域名配置失败: %w", err)
	}

	h.Logger.Info("定向域名加载完成", map[string]interface{}{
		"file": h.config.DesignatedDomain,
	})

	return nil
}

// downloadFile 下载文件
func (h *RefactoredHandler) downloadFile(url, filePath string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// 检查下载的数据是否为空
	if len(data) == 0 {
		h.Logger.Warn("下载的文件内容为空", map[string]interface{}{
			"url":  url,
			"file": filePath,
		})
		return fmt.Errorf("downloaded file is empty")
	}

	return os.WriteFile(filePath, data, 0644)
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

			h.Logger.Debug("🔄 [异步刷新完成-定向域名] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"source":       "designated",
				"answer_count": len(processedResp.Answer),
				"upstreams":    []string{dnsServer},
			})
		} else {
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

				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := h.config.Cache.TTL // 默认使用缓存TTL
				if h.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(h.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}

				// 使用统一的云域名响应处理方法，使用上游DNS服务器
				processedResponse := h.processCloudResponse(result.SuccessResult.Response, domain)

				// 确保云域名响应的TTL不小于配置的替换缓存时间
				h.ensureMinimumTTL(processedResponse, replaceCacheTime)
				// 只更新云响应缓存，不更新普通缓存
				h.cacheManager.SetCloudResponse(domain, qtype, processedResponse, cloudType, replaceCacheTime)

				h.Logger.Debug("🔄 [异步刷新完成-云域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"source":       "cloud",
					"cloud_type":   detection.Type,
					"answer_count": len(processedResponse.Answer),
					"upstreams":    upstreams,
				})
			} else {
				h.Logger.Info("❌ [异步刷新-非云服务域名] ", map[string]interface{}{
					"domain": domain,
				})

				// 对于普通域名，处理CNAME记录
				processedResp := h.processDNSResponseWithCNAME(result.SuccessResult.Response, domain, upstreams)
				h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
				h.cacheManager.Set(domain, qtype, processedResp, isCloud, cloudType)

				h.Logger.Debug("🔄 [异步刷新完成-普通域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"source":       "normal",
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
	// 延迟启动定时任务，避免与DNS服务器启动冲突
	go func() {
		time.Sleep(2 * time.Second) // 等待DNS服务器启动完成

		// 定向域名刷新任务
		if h.config.DesignatedDomain != "" && h.config.DesignatedRefreshInterval > 0 {
			go h.designatedRefreshTask()
		}

		// 中国域名刷新任务
		if h.config.ChinaDomainFile != "" && h.config.ChinaDomainRefreshInterval > 0 {
			go h.chinaDomainRefreshTask()
		}

		// 网络段刷新任务
		if h.config.NetworkRefreshInterval > 0 {
			go h.networkRefreshTask()
		}
	}()
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
				"url":  h.config.DesignatedDomainURL,
			})
			if err := h.loadDesignatedDomains(); err != nil { // 使用loadDesignatedDomains方法，确保下载失败时保留旧文件
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

// chinaDomainRefreshTask 中国域名刷新任务
func (h *RefactoredHandler) chinaDomainRefreshTask() {
	ticker := time.NewTicker(h.config.ChinaDomainRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [中国域名定时刷新启动] ", map[string]interface{}{
		"rule":     "CHINA_DOMAIN_REFRESH_TASK",
		"interval": h.config.ChinaDomainRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时中国域名刷新", map[string]interface{}{
				"file": h.config.ChinaDomainFile,
				"url":  h.config.ChinaDomainFileURL,
			})
			if err := h.loadChinaDomains(); err != nil {
				h.Logger.Error("❌ [中国域名刷新失败] ", map[string]interface{}{
					"rule":  "CHINA_DOMAIN_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [中国域名刷新成功] ", map[string]interface{}{
					"rule": "CHINA_DOMAIN_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [中国域名刷新任务停止] ", map[string]interface{}{
				"rule": "CHINA_DOMAIN_REFRESH_STOPPED",
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
