package dns

import (
	"context"
	"fmt"
	"net/netip"
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
	// 初始化配置
	if err := matcherHandler.InitializeConfig(); err != nil {
		logger.Error("初始化匹配器配置失败", map[string]interface{}{
			"error": err.Error(),
		})
	}
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

	// 设置缓存回调
	cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 加载所有数据
	if err := handler.fileLoader.LoadAllData(); err != nil {
		logger.Error("加载数据失败，但继续启动", map[string]interface{}{
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
	// 1. 缓存检查
	resp, hit, _, cloudType := h.cacheManager.Get(domain, qtype)
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
				h.ensureMinimumTTL(respCopy, replaceCacheTime)
				respCopy.Id = req.Id
				w.WriteMsg(respCopy)
				h.Logger.Info("✅ [DNS查询完成-缓存命中-云域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"client_addr":  w.RemoteAddr().String(),
					"source":       "cache_cloud",
					"answer_count": len(respCopy.Answer),
					"result":       "success",
				})
				return
			} else {
				// 没有云响应缓存，调用替换处理
				h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, cloudType)
				return
			}
		} else {
			// 缓存命中 - 检查域名类型以提供准确日志
			respCopy := resp.Copy()
			// 确保响应中的 TTL 不小于配置的最小 TTL
			h.ensureMinimumTTL(respCopy, h.config.Cache.TTL)
			respCopy.Id = req.Id
			w.WriteMsg(respCopy)

			// 检查域名是否为云服务域名，提供更准确的日志
			isDomainCloud := h.cacheManager.IsDomainCloud(domain)
			source := "cache_normal"
			if isDomainCloud {
				source = "cache_cloud"
			}

			h.Logger.Info("✅ [DNS查询完成-缓存命中] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"client_addr":  w.RemoteAddr().String(),
				"source":       source,
				"answer_count": len(respCopy.Answer),
				"result":       "success",
			})
			return
		}
	}

	// 2. YAML定向域名检查（最高优先级）
	if upstream, isDesignated := h.matcherHandler.GetYAMLMatcher().GetDesignatedDomainOrDefault(domain); isDesignated {
		h.Logger.Info("🎯 [YAML定向域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"dns":    upstream,
		})

		// 执行定向查询
		resp, err := h.matcherHandler.HandleYAMLMatcher(domain, qtype, upstream)
		if err != nil || resp == nil {
			h.Logger.Error("❌ [YAML定向域名处理失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			return
		}

		h.Logger.Info("✅ [DNS查询完成-YAML定向域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "designated",
			"dns_server":   upstream,
			"answer_count": len(resp.Answer),
			"result":       "success",
		})

		// 处理CNAME记录
		processedResp := h.processDNSResponseWithCNAME(resp, domain, []string{upstream})
		h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
		h.cacheManager.Set(domain, qtype, processedResp, false, 0)

		processedResp.Id = req.Id
		w.WriteMsg(processedResp)
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

		// 使用替换域名的TTL配置
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

		// 确保响应中的 TTL 不小于替换域名的TTL配置
		h.ensureMinimumTTL(respCopy, replaceCacheTime)

		// 缓存替换域名的响应结果，使用替换域名的TTL
		h.cacheManager.Set(domain, qtype, respCopy, false)

		// 同时缓存替换域名的响应到专门的云响应缓存（使用替换域名的TTL）
		h.cacheManager.SetCloudResponse(domain, qtype, respCopy, 0, replaceCacheTime)

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
	if h.matcherHandler.GetChinaMatcher().IsChinaDomain(domain) {
		h.Logger.Info("🇨🇳 [中国域名处理开始] ", map[string]interface{}{
			"domain": domain,
			"dns":    h.config.ChinaDNS,
		})

		// 确定上游DNS服务器
		upstreams := []string{h.config.ChinaDNS}
		if h.config.ChinaDNS == "" {
			// 如果没有配置中国DNS，使用默认DNS
			upstreams = h.config.Upstream
		}

		// 执行查询
		resp, err := h.matcherHandler.HandleChinaDomain(domain, qtype, upstreams)
		if err != nil || resp == nil {
			h.Logger.Error("❌ [中国域名处理失败] ", map[string]interface{}{
				"domain": domain,
				"error":  err,
			})
			return
		}

		h.Logger.Info("✅ [DNS查询完成-中国域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "china_domain",
			"answer_count": len(resp.Answer),
			"result":       "success",
		})

		// 处理CNAME记录
		processedResp := h.processDNSResponseWithCNAME(resp, domain, upstreams)
		h.ensureMinimumTTL(processedResp, h.config.Cache.TTL)
		h.cacheManager.Set(domain, qtype, processedResp, false, 0)

		processedResp.Id = req.Id
		w.WriteMsg(processedResp)
		return
	}

	// 5. 普通域名处理逻辑
	resp, err := h.proxyQueryWithCaching(req, h.config.Upstream, domain, qtype)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [上游域名查询失败，请检查上游] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"error":       err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 检查响应是否包含云服务IP，如果是云域名则需要进行替换处理
	detection := h.cloudDetector.DetectCloudService(resp, domain)
	isCloud := detection.Type != CloudTypeNone

	if isCloud {
		// 这是一个云域名，需要进行IP替换
		h.Logger.Info("☁️ [云域名检测到，开始替换处理] ", map[string]interface{}{
			"domain":         domain,
			"cloud_type":     detection.Type,
			"replace_domain": detection.ReplaceDomain,
		})

		// 使用云处理器进行替换处理
		h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, int(detection.Type))
		return
	}

	resp.Id = req.Id
	// 确保响应中的 TTL 不小于配置的最小 TTL
	h.ensureMinimumTTL(resp, h.config.Cache.TTL)
	w.WriteMsg(resp)

	// 检查域名级别的云服务状态来判断是否为云服务域名（确保A/AAAA记录处理一致性）
	isDomainCloud := h.cacheManager.IsDomainCloud(domain)
	if isDomainCloud {
		// 从缓存中获取特定类型的云服务类型用于日志记录
		_, _, isCloud, cloudType := h.cacheManager.Get(domain, qtype)
		cloudTypeName := "unknown"
		if isCloud { // 如果特定类型有云服务类型标记
			switch CloudType(cloudType) {
			case CloudTypeCloudflare:
				cloudTypeName = "Cloudflare"
			case CloudTypeAWS:
				cloudTypeName = "AWS"
			}
		}

		h.Logger.Info("✅ [DNS查询完成-云服务域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "cloud",
			"cloud_type":   cloudTypeName,
			"answer_count": len(resp.Answer),
			"result":       "success",
		})
	} else {
		h.Logger.Info("✅ [DNS查询完成-普通域名] ", map[string]interface{}{
			"domain":       domain,
			"qtype":        dns.TypeToString[qtype],
			"client_addr":  w.RemoteAddr().String(),
			"source":       "normal",
			"answer_count": len(resp.Answer),
			"result":       "success",
		})
	}
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
// 完整实现：收集所有CNAME记录并递归解析，获取IP后按需补充原始IP记录
func (h *RefactoredHandler) processDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 分离CNAME记录和IP记录
	var cnames []*dns.CNAME
	var ipRecords []dns.RR

	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, cname)
		} else if _, ok := rr.(*dns.A); ok || isAAAARecord(rr) {
			ipRecords = append(ipRecords, rr)
		}
	}

	// 获取最大IP记录数配置，默认为2
	maxIPRecords := h.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	// 创建结果存储
	var finalIPRecords []dns.RR

	// 如果有CNAME记录，优先递归解析
	if len(cnames) > 0 {
		h.Logger.Debug("🔍 检测到CNAME记录，开始递归解析", map[string]interface{}{
			"domain":         domain,
			"cname_count":    len(cnames),
			"max_ip_records": maxIPRecords,
		})

		// 递归解析所有CNAME记录
		for _, cname := range cnames {
			if len(finalIPRecords) >= maxIPRecords {
				break // 已达到最大数量
			}

			h.Logger.Debug("🔄 解析CNAME记录", map[string]interface{}{
				"domain": domain,
				"target": cname.Target,
			})

			// 递归解析CNAME目标，使用传入的上游DNS服务器
			cnameTargetReq := &dns.Msg{}
			cnameTargetReq.SetQuestion(cname.Target, resp.Question[0].Qtype)

			cnameTargetResp, err := h.proxyQuery(cnameTargetReq, upstreams)
			if err == nil && cnameTargetResp != nil {
				// 递归处理CNAME目标的响应
				// 注意：这里不应该再次应用IP数量限制，而是获取所有可能的IP，
				// 然后由外层逻辑统一控制最终数量
				processedCnameResp := h.processDNSResponseWithCNAME(cnameTargetResp, domain, upstreams)
				if processedCnameResp != nil {
					// 收集解析出的IP记录，不超过剩余配额
					for _, targetRR := range processedCnameResp.Answer {
						if len(finalIPRecords) >= maxIPRecords {
							break
						}
						if _, ok := targetRR.(*dns.A); ok || isAAAARecord(targetRR) {
							// 检查是否已存在相同的IP记录，避免重复
							isDuplicate := false
							for _, existing := range finalIPRecords {
								if existing.String() == targetRR.String() {
									isDuplicate = true
									break
								}
							}
							if !isDuplicate {
								finalIPRecords = append(finalIPRecords, targetRR)
							}
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

	// 按IPv4和IPv6分别计数
	var ipv4Records []dns.RR
	var ipv6Records []dns.RR

	for _, record := range finalIPRecords {
		if _, ok := record.(*dns.A); ok {
			ipv4Records = append(ipv4Records, record)
		} else if isAAAARecord(record) {
			ipv6Records = append(ipv6Records, record)
		}
	}

	// IPv4和IPv6各自独立限制为配置的最大值
	maxIPv4 := maxIPRecords
	maxIPv6 := maxIPRecords

	// 截取IPv4和IPv6记录
	var resultRecords []dns.RR

	// 添加IPv4记录（最多maxIPv4个）
	for i, record := range ipv4Records {
		if i >= maxIPv4 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 添加IPv6记录（最多maxIPv6个）
	for i, record := range ipv6Records {
		if i >= maxIPv6 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 如果数量不足，尝试补充原始IP记录
	remainingSlots := maxIPRecords - len(resultRecords)
	if remainingSlots > 0 {
		// 按IPv4和IPv6分别补充
		var additionalIPv4 []dns.RR
		var additionalIPv6 []dns.RR

		for _, record := range ipRecords {
			// 检查记录是否已经存在于resultRecords中
			isAlreadyAdded := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isAlreadyAdded = true
					break
				}
			}
			if isAlreadyAdded {
				continue // 跳过已添加的记录
			}

			if _, ok := record.(*dns.A); ok {
				// 检查是否已达到IPv4最大数量
				currentIPv4Count := 0
				for _, res := range resultRecords {
					if _, ok := res.(*dns.A); ok {
						currentIPv4Count++
					}
				}
				if currentIPv4Count < maxIPv4 {
					additionalIPv4 = append(additionalIPv4, record)
				}
			} else if isAAAARecord(record) {
				// 检查是否已达到IPv6最大数量
				currentIPv6Count := 0
				for _, res := range resultRecords {
					if isAAAARecord(res) {
						currentIPv6Count++
					}
				}
				if currentIPv6Count < maxIPv6 {
					additionalIPv6 = append(additionalIPv6, record)
				}
			}
		}

		// 补充IPv4记录
		for _, record := range additionalIPv4 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}

		// 补充IPv6记录
		for _, record := range additionalIPv6 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}
	}

	// 创建并填充最终响应
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	processedResp.Id = resp.Id

	// 添加IP记录到响应，同时确保去重
	for _, record := range resultRecords {
		newRecord := dns.Copy(record)
		newRecord.Header().Name = dns.Fqdn(domain)

		// 检查是否已经添加了相同的IP记录，只比较IP地址部分
		alreadyAdded := false
		for _, existing := range processedResp.Answer {
			// 比较IP地址部分
			existingIP := ""
			newIP := ""

			if a, ok := existing.(*dns.A); ok {
				existingIP = a.A.String()
			} else if aaaa, ok := existing.(*dns.AAAA); ok {
				existingIP = aaaa.AAAA.String()
			}

			if a, ok := newRecord.(*dns.A); ok {
				newIP = a.A.String()
			} else if aaaa, ok := newRecord.(*dns.AAAA); ok {
				newIP = aaaa.AAAA.String()
			}

			if existingIP != "" && existingIP == newIP {
				alreadyAdded = true
				break
			}
		}
		if !alreadyAdded {
			processedResp.Answer = append(processedResp.Answer, newRecord)
		}
	}

	h.Logger.Debug("✅ CNAME处理完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  countType(processedResp.Answer, "A"),
		"ipv6_count":  countType(processedResp.Answer, "AAAA"),
	})

	return processedResp
}

// isAAAARecord 检查记录是否为AAAA记录
func isAAAARecord(rr dns.RR) bool {
	_, ok := rr.(*dns.AAAA)
	return ok
}

// countType 计算指定类型的记录数量
func countType(records []dns.RR, recordType string) int {
	count := 0
	for _, record := range records {
		switch recordType {
		case "A":
			if _, ok := record.(*dns.A); ok {
				count++
			}
		case "AAAA":
			if _, ok := record.(*dns.AAAA); ok {
				count++
			}
		}
	}
	return count
}

// replaceCloudIPs 用替换域名的IP替换原始响应中的云服务IP
func (h *RefactoredHandler) replaceCloudIPs(originalResp *dns.Msg, originalDetection *CloudDetectionResult) *dns.Msg {
	if originalResp == nil || originalDetection == nil {
		return originalResp
	}

	// 查询替换域名获取IP地址
	replaceDomain := originalDetection.ReplaceDomain
	if replaceDomain == "" {
		return originalResp
	}

	// 查询替换域名的A和AAAA记录
	replaceReqA := &dns.Msg{}
	replaceReqA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeA)

	replaceReqAAAA := &dns.Msg{}
	replaceReqAAAA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeAAAA)

	var replaceIPs []netip.Addr

	// 获取替换域名的A记录
	if replaceRespA, err := h.proxyQuery(replaceReqA, h.config.Upstream); err == nil && replaceRespA != nil && replaceRespA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespA.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, err := netip.ParseAddr(a.A.String()); err == nil {
					replaceIPs = append(replaceIPs, ip)
				}
			}
		}
	}

	// 获取替换域名的AAAA记录
	if replaceRespAAAA, err := h.proxyQuery(replaceReqAAAA, h.config.Upstream); err == nil && replaceRespAAAA != nil && replaceRespAAAA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				if ip, err := netip.ParseAddr(aaaa.AAAA.String()); err == nil {
					replaceIPs = append(replaceIPs, ip)
				}
			}
		}
	}

	if len(replaceIPs) == 0 {
		h.Logger.Warn("⚠️ 替换域名无有效IP记录", map[string]interface{}{
			"replace_domain": replaceDomain,
		})
		return originalResp
	}

	// 创建新的响应并替换IP
	newResp := &dns.Msg{}
	*newResp = *originalResp // 复制原始响应结构
	newResp.Answer = nil     // 清空答案部分

	// 复制非IP的记录
	for _, rr := range originalResp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 跳过云服务IP记录，稍后用替换IP替换
		default:
			// 保留非IP记录
			newResp.Answer = append(newResp.Answer, dns.Copy(rr))
		}
	}

	// 添加替换IP，保持原始查询类型
	for _, ip := range replaceIPs {
		// 根据IP类型创建相应的记录
		if ip.Is4() && originalResp.Question[0].Qtype == dns.TypeA {
			for _, originalRR := range originalResp.Answer {
				if _, ok := originalRR.(*dns.A); ok {
					newA := &dns.A{
						Hdr: dns.RR_Header{
							Name:   originalRR.Header().Name,
							Rrtype: dns.TypeA,
							Class:  originalRR.Header().Class,
							Ttl:    originalRR.Header().Ttl,
						},
						A: ip.AsSlice(),
					}
					newResp.Answer = append(newResp.Answer, newA)
					break
				}
			}
		} else if ip.Is6() && originalResp.Question[0].Qtype == dns.TypeAAAA {
			for _, originalRR := range originalResp.Answer {
				if _, ok := originalRR.(*dns.AAAA); ok {
					newAAAA := &dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   originalRR.Header().Name,
							Rrtype: dns.TypeAAAA,
							Class:  originalRR.Header().Class,
							Ttl:    originalRR.Header().Ttl,
						},
						AAAA: ip.AsSlice(),
					}
					newResp.Answer = append(newResp.Answer, newAAAA)
					break
				}
			}
		}
	}

	h.Logger.Debug("🔄 云IP替换完成", map[string]interface{}{
		"original_ips_count": len(originalDetection.DetectedIPs),
		"replace_ips_count":  len(replaceIPs),
	})

	return newResp
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
