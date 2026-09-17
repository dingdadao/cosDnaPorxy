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

	// 连接池
	dotConnPool *DoTConnPool
	dohConnPool *DoHConnPool
	udpConnPool *UDPConnPool
	tcpConnPool *TCPConnPool

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

	// 创建连接池
	dotConnPool := NewDoTConnPool()
	dohConnPool := NewDoHConnPool()
	udpConnPool := NewUDPConnPool()
	tcpConnPool := NewTCPConnPool()

	// 创建缓存管理器（云检测统一在查询流程中执行，缓存层不做云检测）
	cacheManager := NewCacheManager(cfg, logger)

	// 初始化处理器结构体
	handler := &RefactoredHandler{
		config:        cfg,
		Logger:        logger, // 使用公共字段
		cacheManager:  cacheManager,
		cloudDetector: cloudDetector,
		dotConnPool:   dotConnPool,
		dohConnPool:   dohConnPool,
		udpConnPool:   udpConnPool,
		tcpConnPool:   tcpConnPool,
		ctx:           ctx,
		cancel:        cancel,
	}

	// 根据上游配置选择查询优化器
	var queryOptimizer interface{}
	if hasModernProtocols(cfg.Upstream) {
		// 使用简化的现代查询优化器，传入现代协议超时
		modernOptimizer := NewSimpleModernOptimizer(logger, cfg.Timeout, cfg.ModernTimeout)
		// 设置各种协议的查询函数，使用连接池
		modernOptimizer.udpQueryFunc = handler.getUDPQueryFunc()
		modernOptimizer.tcpQueryFunc = handler.getTCPQueryFunc()
		modernOptimizer.doHQueryFunc = handler.getDoHQueryFunc()
		modernOptimizer.doTQueryFunc = handler.getDoTQueryFunc()
		queryOptimizer = modernOptimizer
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

	// 将查询优化器设置到handler
	handler.queryOptimizer = queryOptimizer

	// 初始化匹配处理器 - 传递完整的handler实例
	matcherHandler := NewMatcherHandler(cfg, logger, handler)
	handler.matcherHandler = matcherHandler
	if cfg.DefaultDNS != "" {
		matcherHandler.GetYAMLMatcher().SetDefaultDNS(cfg.DefaultDNS)
	}

	// 初始化云服务处理器（统一响应出口回调，保证EDNS/TC处理一致）
	cloudHandler := NewCloudHandler(cfg, logger, cacheManager, cloudDetector, handler.proxyQuery, handler.writeResponse)
	handler.cloudHandler = cloudHandler

	// 初始化文件加载处理器
	fileLoader := NewFileLoader(cfg, logger, cloudDetector, matcherHandler)
	handler.fileLoader = fileLoader

	// 初始化任务调度器
	taskScheduler := NewTaskScheduler(cfg, logger, fileLoader, cloudDetector)
	handler.taskScheduler = taskScheduler

	// 初始化刷新处理器（云域名刷新时通过该回调重建替换响应，保证与查询路径一致）
	refreshHandler := NewRefreshHandler(cfg, logger, cacheManager, cloudDetector, queryOptimizer, matcherHandler, handler.proxyQuery,
		func(originalResp *dns.Msg, domain string, qtype uint16, cloudType int) *dns.Msg {
			v4, v6, err := cloudHandler.ResolveReplaceIPs(0, domain, qtype, cloudType)
			if err != nil {
				return nil
			}
			if qtype == dns.TypeA && len(v4) == 0 {
				return nil
			}
			if qtype == dns.TypeAAAA && len(v6) == 0 {
				return nil
			}
			return buildCloudResponse(originalResp, qtype, v4, v6)
		})
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

// ServeDNS 实现dns.Handler接口（带panic恢复与协议守卫）
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

	if req == nil {
		return
	}

	// 协议守卫：QR=1的是响应而非查询，忽略以防请求回环（RFC 1035 §4.1.1）
	if req.Response {
		h.Logger.Debug("⏭️ 忽略QR=1的DNS消息", map[string]interface{}{
			"client_addr": w.RemoteAddr().String(),
		})
		return
	}

	// 协议守卫：仅支持标准查询Opcode，其他回NOTIMP
	if req.Opcode != dns.OpcodeQuery {
		h.Logger.Debug("⏭️ 非QUERY Opcode，回NOTIMP", map[string]interface{}{
			"opcode": req.Opcode,
		})
		h.sendErrorResponse(w, req, dns.RcodeNotImplemented)
		return
	}

	// 协议守卫：问题段为空回FORMERR
	if len(req.Question) == 0 {
		h.Logger.Warn("⚠️ 收到空DNS请求")
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	// 协议守卫：QDCOUNT>1回FORMERR（RFC 1035 §4.1.2，本服务仅支持单问题）
	if len(req.Question) > 1 {
		h.Logger.Debug("⏭️ QDCOUNT>1，回FORMERR", map[string]interface{}{
			"qdcount": len(req.Question),
		})
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	q := req.Question[0]

	// 域名合法性检查：非法域名回FORMERR，绝不静默丢弃让客户端空等
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
	if _, ok := dns.IsDomainName(domain); !ok {
		h.Logger.Warn("⚠️ 非法域名请求", map[string]interface{}{
			"domain": domain,
		})
		h.sendErrorResponse(w, req, dns.RcodeFormatError)
		return
	}

	// 协议守卫：RD=0的非递归请求仅用缓存回答，缓存未命中回REFUSED
	if !req.RecursionDesired {
		resp, hit, _, _ := h.cacheManager.Get(domain, q.Qtype)
		if !hit {
			h.sendErrorResponse(w, req, dns.RcodeRefused)
			return
		}
		h.writeResponse(w, req, resp)
		return
	}

	// 目前重点处理A和AAAA记录（IP地址记录）
	// 其他记录类型（如NS、MX等）也会被处理，但不经过云服务检测优化
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// 对于非A/AAAA记录，仍然进行查询，但跳过云服务检测和替换逻辑
		h.processNonIPQuery(w, req, domain, q.Qtype)
		return
	}

	h.processQuery(w, req, domain, q.Qtype)
}

// processNonIPQuery 处理非IP记录类型的DNS查询（如NS、MX、TXT等）
func (h *RefactoredHandler) processNonIPQuery(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16) {
	// 1. 检查缓存（命中返回递减TTL后的副本）
	resp, hit, _, _ := h.cacheManager.Get(domain, qtype)
	if hit {
		h.writeResponse(w, req, resp)
		h.Logger.Debug("✅ [DNS查询完成-非IP记录-缓存命中] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"source":      "cache_non_ip",
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

	// 4. 验证响应是否有效（NOERROR或NXDOMAIN均可缓存返回）
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		h.Logger.Error("❌ [非IP记录响应无效] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"rcode":       dns.RcodeToString[resp.Rcode],
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		return
	}

	// 5. 缓存并原样返回上游响应（不重建owner、不裁剪RRset）
	h.cacheManager.Set(domain, qtype, resp, false)
	h.writeResponse(w, req, resp)

	h.Logger.Debug("✅ [DNS查询完成-非IP记录] ", map[string]interface{}{
		"domain":       domain,
		"qtype":        dns.TypeToString[qtype],
		"client_addr":  w.RemoteAddr().String(),
		"source":       "non_ip",
		"answer_count": len(resp.Answer),
		"rcode":        dns.RcodeToString[resp.Rcode],
	})
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
		if h.cacheManager.IsDomainCloud(domain) {
			// 云域名：返回云替换响应缓存
			if cloudResp, cloudHit, _ := h.cacheManager.GetCloudResponse(domain, qtype); cloudHit {
				h.writeResponse(w, req, cloudResp)
				totalTime := totalTimer.End()
				h.Logger.Debug("✅ [DNS查询完成-缓存命中-云域名] ", map[string]interface{}{
					"domain":      domain,
					"qtype":       dns.TypeToString[qtype],
					"client_addr": w.RemoteAddr().String(),
					"source":      "cache_cloud",
					"total_time":  totalTime,
				})
				return
			}
		} else {
			// 普通域名缓存命中：resp已是递减TTL后的副本
			h.writeResponse(w, req, resp)
			totalTime := totalTimer.End()
			h.Logger.Debug("✅ [DNS查询完成-缓存命中] ", map[string]interface{}{
				"domain":      domain,
				"qtype":       dns.TypeToString[qtype],
				"client_addr": w.RemoteAddr().String(),
				"source":      "cache_normal",
				"total_time":  totalTime,
			})
			return
		}
	}

	// 确定上游服务器
	upstreams := h.determineUpstreamsForDomain(domain)

	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query")

	// 2. 代理查询上游DNS服务器（ fastest-wins，失败回退BackupDNS ）
	resp, err := h.proxyQueryWithCaching(req, upstreams, domain, qtype)
	upstreamTime := upstreamTimer.End()

	if err != nil || resp == nil {
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

	// 3. 云服务检测：沿CNAME链收集IP仅用于内部检测，不改写客户端响应
	var detection *CloudDetectionResult
	isCloud := false

	if _, hasDesignated := h.matcherHandler.GetYAMLMatcher().GetDesignatedDomainOrDefault(domain); hasDesignated {
		// 定向域名：跳过云服务检测
		h.Logger.Debug("⏭️ 跳过云服务检测（定向域名配置）", map[string]interface{}{
			"domain": domain,
		})
	} else if !h.cloudDetector.IsReplaceDomain(domain) {
		chainIPs := h.cnameProcessor.CollectChainIPs(resp, domain, qtype)
		if len(chainIPs) > 0 {
			probe := &dns.Msg{Answer: chainIPs}
			if h.config.EnableCloudflareCheck {
				if d := h.cloudDetector.DetectCloudflareService(probe); d.Type != CloudTypeNone {
					detection = d
					isCloud = true
				}
			}
			if !isCloud && h.config.EnableAWSCheck {
				if d := h.cloudDetector.DetectAWSService(probe); d.Type != CloudTypeNone {
					detection = d
					isCloud = true
				}
			}
		}
	}

	if isCloud && detection != nil {
		h.Logger.Debug("☁️ [云域名检测到，开始替换处理] ", map[string]interface{}{
			"domain":         domain,
			"cloud_type":     detection.Type,
			"replace_domain": detection.ReplaceDomain,
		})

		// 云替换内部会自行写响应（与查询路径一致的缓存与出口处理）
		_ = h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, int(detection.Type), resp)
		totalTime := totalTimer.End()
		h.Logger.Debug("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"client_addr":   w.RemoteAddr().String(),
			"source":        "cloud_replacement",
			"total_time":    totalTime,
			"upstream_time": upstreamTime,
		})
		return
	}

	// 4. 非云域名：原样返回上游响应（owner、RRset完整保留）
	h.writeResponse(w, req, resp)

	// 检查域名是否为中国域名
	isChinaDomain := h.config.EnableChinaDomainCheck && h.matcherHandler.GetChinaMatcher().IsChinaDomain(domain)
	isDomainCloud := h.cacheManager.IsDomainCloud(domain)

	var logSource string
	if isDomainCloud {
		logSource = "cloud"
	} else if isChinaDomain {
		logSource = "china"
	} else {
		logSource = "normal"
	}

	totalTime := totalTimer.End()
	h.Logger.Debug("✅ [DNS查询完成] ", map[string]interface{}{
		"domain":        domain,
		"qtype":         dns.TypeToString[qtype],
		"client_addr":   w.RemoteAddr().String(),
		"source":        logSource,
		"answer_count":  len(resp.Answer),
		"total_time":    totalTime,
		"upstream_time": upstreamTime,
	})
}

// writeResponse 统一响应出口：所有路径（缓存命中/上游/云替换/错误）唯一WriteMsg的地方
// 统一处理：回写原始Question（保留客户端QNAME大小写）、清除AD位、回带EDNS OPT、UDP截断（TC位）
func (h *RefactoredHandler) writeResponse(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) {
	if resp == nil {
		return
	}

	resp.Id = req.Id
	resp.Question = req.Question   // 保留客户端原始QNAME（含大小写，0x20随机化客户端可正常校验）
	resp.AuthenticatedData = false // 未做DNSSEC校验且可能改写响应，AD断言不成立，清零（RFC 4035）

	// 去掉上游可能携带的OPT记录，避免与下方回带的OPT重复
	extra := resp.Extra[:0]
	for _, rr := range resp.Extra {
		if _, isOPT := rr.(*dns.OPT); !isOPT {
			extra = append(extra, rr)
		}
	}
	resp.Extra = extra

	// 按请求回带EDNS OPT（RFC 6891）
	opt := req.IsEdns0()
	if opt != nil {
		resp.SetEdns0(opt.UDPSize(), opt.Do())
	}

	resp.Compress = true

	// UDP截断：超过客户端通告payload size（无EDNS时为512）时设置TC=1，让客户端转TCP重试
	if w.RemoteAddr().Network() == "udp" {
		size := 512
		if opt != nil && opt.UDPSize() > 512 {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}

	w.WriteMsg(resp)
}

// sendErrorResponse 发送错误响应（走统一响应出口）
func (h *RefactoredHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	h.writeResponse(w, req, resp)
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

	// 关闭连接池
	if h.dotConnPool != nil {
		h.dotConnPool.Close()
	}
	if h.dohConnPool != nil {
		h.dohConnPool.Close()
	}
	if h.udpConnPool != nil {
		h.udpConnPool.Close()
	}
	if h.tcpConnPool != nil {
		h.tcpConnPool.Close()
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
		h.Logger.Debug("定向域名或默认DNS", map[string]interface{}{
			"domain":     domain,
			"dns_server": dnsServer,
		})
		return []string{dnsServer}
	}

	// 检查是否为中国域名（如果启用了中国域名检查）
	if h.config.EnableChinaDomainCheck && h.matcherHandler.GetChinaMatcher().IsChinaDomain(domain) {
		if h.config.ChinaDNS != "" {
			h.Logger.Debug("🇨🇳 中国域名处理", map[string]interface{}{
				"domain": domain,
				"dns":    h.config.ChinaDNS,
			})
			return []string{h.config.ChinaDNS}
		} else {
			h.Logger.Warn("⚠️ [中国域名但未配置ChinaDNS] ", map[string]interface{}{
				"domain": domain,
			})
		}
	}

	// 如果没有匹配到任何配置，使用上游DNS作为备用
	return h.config.Upstream
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

// getUDPQueryFunc 返回UDP查询函数
func (h *RefactoredHandler) getUDPQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryUDP
}

// getTCPQueryFunc 返回TCP查询函数
func (h *RefactoredHandler) getTCPQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryTCP
}

// getDoHQueryFunc 返回DoH查询函数
func (h *RefactoredHandler) getDoHQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryDoH
}

// getDoTQueryFunc 返回DoT查询函数
func (h *RefactoredHandler) getDoTQueryFunc() func(*dns.Msg, string) (*dns.Msg, error) {
	return h.queryDoT
}
