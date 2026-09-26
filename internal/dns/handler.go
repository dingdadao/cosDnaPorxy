package dns

import (
	"context"
	"fmt"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/querylog"
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
	cfgMu  sync.RWMutex
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
	cnameProcessor  *CNAMEProcessor
	cloudProcessor  *CloudProcessor
	overrideMatcher *OverrideMatcher // 本地域名篡改匹配器（最高优先级）

	// 解析日志（进程级，独立于处理器生命周期，可为 nil 表示不记录）
	queryLog *querylog.Store

	// 连接池
	dotConnPool *DoTConnPool
	dohConnPool *DoHConnPool
	udpConnPool *UDPConnPool
	tcpConnPool *TCPConnPool

	ctx    context.Context
	cancel context.CancelFunc
}

// NewRefactoredHandler 创建新的重构后处理器（qlog 为进程级解析日志库，可为 nil）
func NewRefactoredHandler(cfg *config.Config, logger *utils.EnhancedLogger, qlog *querylog.Store) (*RefactoredHandler, error) {
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
		queryLog:      qlog,
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

	// 初始化匹配处理器 - 传递完整的handler实例（各列表DNS由buildMatchers按配置注入）
	matcherHandler := NewMatcherHandler(cfg, logger, handler)
	handler.matcherHandler = matcherHandler

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

	// 初始化本地域名篡改匹配器（最高优先级）
	handler.overrideMatcher = NewOverrideMatcher(logger)

	// 设置缓存回调
	handler.cacheManager.SetRefreshCallback(handler.refreshDNSRecord)

	// 根据开关决定是否加载数据
	if err := handler.fileLoader.LoadSelectiveData(
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

// getConfig 获取当前配置（web保存后热切换）
func (h *RefactoredHandler) getConfig() *config.Config {
	h.cfgMu.RLock()
	defer h.cfgMu.RUnlock()
	return h.config
}

// LoadOverrides 加载本地域名篡改规则（web变更后全量重建索引）
func (h *RefactoredHandler) LoadOverrides(list []*config.Override) {
	h.overrideMatcher.Reload(list)
}

// overrideMatcherGetter 供web层获取篡改匹配器
func (h *RefactoredHandler) GetOverrideMatcher() *OverrideMatcher {
	return h.overrideMatcher
}

// RefreshSplitList 按索引强制下载并重新加载该分流列表的域名文件，返回加载后的规则条数
// （供 Web 管理端「立即更新」按钮调用；下载或加载失败时保留原有规则）
func (h *RefactoredHandler) RefreshSplitList(i int) (int, error) {
	if h.fileLoader == nil {
		return 0, fmt.Errorf("文件加载器不可用")
	}
	if err := h.fileLoader.ForceDownloadAndReloadSplitList(i); err != nil {
		return 0, err
	}
	if m := h.matcherHandler.MatcherFor(i); m != nil {
		return m.RuleCount(), nil
	}
	return 0, nil
}

// ApplyConfig 热更新配置：立即生效可热切换部分，返回是否需要重启生效
func (h *RefactoredHandler) ApplyConfig(cfg *config.Config) bool {
	old := h.getConfig()

	// 热切换查询路径与各组件持有的配置指针
	h.cfgMu.Lock()
	h.config = cfg
	h.cfgMu.Unlock()

	h.cacheManager.UpdateConfig(cfg)
	h.cloudHandler.UpdateConfig(cfg)
	h.refreshHandler.UpdateConfig(cfg)
	h.cloudProcessor.UpdateConfig(cfg)
	h.cnameProcessor.UpdateConfig(cfg)
	h.cloudDetector.SetReplaceDomains(cfg.ReplaceCFDomain, cfg.ReplaceAWSDomain)
	h.matcherHandler.UpdateConfig(cfg)
	h.Logger.SetLevel(cfg.LogLevel)
	if h.queryLog != nil {
		h.queryLog.UpdateOptions(querylog.Options{
			Enabled:   cfg.QueryLog.Enabled,
			Retention: cfg.QueryLog.Retention,
			MaxRows:   cfg.QueryLog.MaxRows,
		})
	}
	if modern, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		modern.UpdateTimeouts(cfg.Timeout, cfg.ModernTimeout)
	} else if traditional, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		traditional.UpdateTimeouts(cfg.Timeout)
	}

	// 分流路由（顺序/取反/DNS/ECS/A-AAAA偏好）变更后，缓存里仍是按旧路由取回的结果，必须清空避免串味
	// 替换接口地址/条数变更后同理：缓存里还是旧接口给出的替换 IP
	if splitListsRoutingChanged(old.SplitLists, cfg.SplitLists) || old.IPPrefer != cfg.IPPrefer ||
		old.ReplaceCFAPI != cfg.ReplaceCFAPI || old.ReplaceAPICount != cfg.ReplaceAPICount {
		h.cacheManager.Clear()
		h.Logger.Info("🧹 [分流路由变更，已清空缓存] ", map[string]interface{}{
			"rule":           "SPLIT_ROUTING_CHANGED_CACHE_CLEARED",
			"ip_prefer":      cfg.IPPrefer,
			"replace_cf_api": cfg.ReplaceCFAPI,
		})
	}

	h.Logger.Info("🔥 [配置已热更新] ", map[string]interface{}{
		"rule": "CONFIG_HOT_APPLIED",
	})

	// 以下字段仅启动时生效，变更后需重启
	return old.ListenPort != cfg.ListenPort ||
		old.WebAddr != cfg.WebAddr ||
		old.LogFormat != cfg.LogFormat ||
		old.Cache.MaxItems != cfg.Cache.MaxItems ||
		old.Cache.MaxAsyncWorkers != cfg.Cache.MaxAsyncWorkers ||
		splitListsNeedRestart(old.SplitLists, cfg.SplitLists) ||
		old.CloudflareNetFile != cfg.CloudflareNetFile ||
		old.CloudflareNetFile6 != cfg.CloudflareNetFile6 ||
		old.AWSNetFile != cfg.AWSNetFile ||
		old.NetworkRefreshInterval != cfg.NetworkRefreshInterval
}

// splitListsNeedRestart 判断分流列表是否发生需重启才生效的结构性变更
// （列表增删/启用状态/域名文件/URL/刷新间隔；顺序、DNS、取反、ECS 变更均可热更新）
func splitListsNeedRestart(old, cur []config.SplitList) bool {
	if len(old) != len(cur) {
		return true
	}
	// 与顺序无关：按身份（名称/文件/URL）排序后逐条比对，避免仅调换顺序被误判为需重启
	a := sortedSplitLists(old)
	b := sortedSplitLists(cur)
	for i := range a {
		if a[i].Name != b[i].Name || a[i].DomainFile != b[i].DomainFile ||
			a[i].DomainURL != b[i].DomainURL || a[i].Enabled != b[i].Enabled ||
			a[i].Refresh != b[i].Refresh {
			return true
		}
	}
	return false
}

// sortedSplitLists 返回按身份（名称/文件/URL）排序的副本，供与顺序无关的比对使用
func sortedSplitLists(lists []config.SplitList) []config.SplitList {
	out := append([]config.SplitList(nil), lists...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		if out[i].DomainFile != out[j].DomainFile {
			return out[i].DomainFile < out[j].DomainFile
		}
		return out[i].DomainURL < out[j].DomainURL
	})
	return out
}

// splitListsRoutingChanged 判断「域名→上游」的路由是否变化
// （顺序、取反、DNS、解析模式、ECS、A/AAAA 偏好、启用状态、域名文件；任一变化后缓存里的旧结果都不再适用）
func splitListsRoutingChanged(old, cur []config.SplitList) bool {
	if len(old) != len(cur) {
		return true
	}
	for i := range old {
		a, b := old[i], cur[i]
		if a.Invert != b.Invert || a.Enabled != b.Enabled || a.ECS != b.ECS ||
			a.DomainFile != b.DomainFile || a.DomainURL != b.DomainURL ||
			a.DNSMode != b.DNSMode || a.IPPrefer != b.IPPrefer ||
			!slices.Equal(a.DNS, b.DNS) {
			return true
		}
	}
	return false
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

	// 本地域名篡改检查（最高优先级）：命中域名一律本地作答，不走缓存与上游
	if h.overrideMatcher.Match(domain) {
		if records := h.overrideMatcher.Lookup(domain, q.Qtype); len(records) > 0 {
			overrideResp := buildOverrideResponse(req, q.Qtype, records)
			if overrideResp == nil {
				h.Logger.Warn("⚠️ 域名篡改记录全部无效", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[q.Qtype],
				})
				h.sendErrorResponse(w, req, dns.RcodeServerFailure)
				h.recordQuery(querylog.Entry{
					Domain: domain, QType: dns.TypeToString[q.Qtype], Client: clientAddr(w),
					Action: querylog.ActionError, Rcode: "SERVFAIL", Answers: "篡改记录全部无效",
				})
				return
			}
			h.writeResponse(w, req, overrideResp)
			h.Logger.Info("🔀 [域名篡改命中] ", map[string]interface{}{
				"rule":        "OVERRIDE_HIT",
				"domain":      domain,
				"qtype":       dns.TypeToString[q.Qtype],
				"client_addr": w.RemoteAddr().String(),
				"records":     len(overrideResp.Answer),
			})
			h.recordQuery(querylog.Entry{
				Domain: domain, QType: dns.TypeToString[q.Qtype], Client: clientAddr(w),
				Action: querylog.ActionOverride, Rcode: dns.RcodeToString[overrideResp.Rcode],
				Answers: answersSummary(overrideResp),
			})
			return
		}

		// 已篡改域名但未配置该记录类型（如只配了A却查AAAA/HTTPS）：回NODATA，
		// 避免上游真CNAME等数据外泄导致客户端绕过篡改
		h.writeResponse(w, req, buildNODATAResponse(req))
		h.Logger.Info("🔀 [域名篡改NODATA] ", map[string]interface{}{
			"rule":        "OVERRIDE_NODATA",
			"domain":      domain,
			"qtype":       dns.TypeToString[q.Qtype],
			"client_addr": w.RemoteAddr().String(),
		})
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[q.Qtype], Client: clientAddr(w),
			Action: querylog.ActionOverride, Rcode: dns.RcodeToString[dns.RcodeSuccess],
			Answers: "NODATA（域名已篡改，无该类型记录）",
		})
		return
	}

	// 协议守卫：RD=0的非递归请求仅用缓存回答，缓存未命中回REFUSED
	if !req.RecursionDesired {
		resp, hit, _, _ := h.cacheManager.Get(domain, q.Qtype)
		if !hit {
			h.sendErrorResponse(w, req, dns.RcodeRefused)
			h.recordQuery(querylog.Entry{
				Domain: domain, QType: dns.TypeToString[q.Qtype], Client: clientAddr(w),
				Action: querylog.ActionRefused, Rcode: dns.RcodeToString[dns.RcodeRefused],
				Answers: "RD=0 且缓存未命中",
			})
			return
		}
		h.writeResponse(w, req, resp)
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[q.Qtype], Client: clientAddr(w),
			Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
			Answers: answersSummary(resp),
		})
		return
	}

	// A/AAAA 偏好档位：本地篡改优先级最高（已在上面处理），此处先于缓存判定，
	// 使「只A/优先A」能压过缓存里的 AAAA；RD=0 的「缓存或REFUSED」约束保持在前，不被本策略改写
	if h.filterAAAA(w, req, domain, q.Qtype) {
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
	start := time.Now()

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
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
			Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
			Answers: answersSummary(resp), ElapsedMS: time.Since(start).Milliseconds(),
		})
		return
	}

	// 2. 分流决策 + 确定上游服务器（与 A/AAAA 路径共用同一套路由与解析模式）
	decision := h.matcherHandler.MatchDomain(domain)
	upstreams := h.upstreamsFor(domain, decision)

	// 3. 执行查询（不经过云服务检测和替换逻辑）
	resp, server, err := h.queryWithFallback(req, upstreams, decision.DNSMode)
	if err != nil || resp == nil {
		h.Logger.Error("❌ [非IP记录查询失败] ", map[string]interface{}{
			"domain":      domain,
			"qtype":       dns.TypeToString[qtype],
			"client_addr": w.RemoteAddr().String(),
			"error":       err,
		})
		h.sendErrorResponse(w, req, dns.RcodeServerFailure)
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
			Action: querylog.ActionError, Rcode: "SERVFAIL",
			Answers: "上游查询失败", ElapsedMS: time.Since(start).Milliseconds(),
		})
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
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
			Action: querylog.ActionError, Rcode: "SERVFAIL",
			Answers: "上游响应无效: " + dns.RcodeToString[resp.Rcode], ElapsedMS: time.Since(start).Milliseconds(),
		})
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

	action, listName, mode := splitLogFields(decision)
	h.recordQuery(querylog.Entry{
		Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
		Action: action, ListName: listName, DNS: server, DNSMode: mode,
		Rcode: dns.RcodeToString[resp.Rcode], Answers: answersSummary(resp),
		ElapsedMS: time.Since(start).Milliseconds(),
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
				h.recordQuery(querylog.Entry{
					Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
					Action: querylog.ActionCache, Rcode: dns.RcodeToString[cloudResp.Rcode],
					Answers: answersSummary(cloudResp), ElapsedMS: totalTime.Milliseconds(),
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
			h.recordQuery(querylog.Entry{
				Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
				Action: querylog.ActionCache, Rcode: dns.RcodeToString[resp.Rcode],
				Answers: answersSummary(resp), ElapsedMS: totalTime.Milliseconds(),
			})
			return
		}
	}

	// 分流决策：一次匹配同时得出上游 DNS、云检测开关与 ECS 策略
	decision := h.matcherHandler.MatchDomain(domain)
	upstreams := h.upstreamsFor(domain, decision)
	ecs := ecsSummary(req, decision)

	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query")

	// 2. 代理查询上游DNS服务器（按列表解析模式：竞速 / 串行故障转移；全部失败回退 BackupDNS）
	//    命中分流列表时按列表 ECS 策略处理请求副本（剥离客户端 ECS / 注入本地 ECS）
	resp, server, err := h.proxyQueryWithCaching(applySplitECS(req, decision), upstreams, domain, qtype, decision.DNSMode)
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
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
			Action: querylog.ActionError, ListName: decision.ListName, DNSMode: decision.DNSMode,
			ECS: ecs, Rcode: "SERVFAIL", Answers: "上游查询失败", ElapsedMS: totalTime.Milliseconds(),
		})
		return
	}

	// 3. 云服务检测：沿CNAME链收集IP仅用于内部检测，不改写客户端响应
	var detection *CloudDetectionResult
	isCloud := false

	if decision.Matched && !decision.EnableCloudCheck {
		h.Logger.Debug("⏭️ 跳过云服务检测（分流列表未开启云检测）", map[string]interface{}{
			"domain": domain,
			"list":   decision.ListName,
		})
	} else if !h.cloudDetector.IsReplaceDomain(domain) {
		chainIPs := h.cnameProcessor.CollectChainIPs(resp, domain, qtype)
		if len(chainIPs) > 0 {
			probe := &dns.Msg{Answer: chainIPs}
			if h.getConfig().EnableCloudflareCheck {
				if d := h.cloudDetector.DetectCloudflareService(probe); d.Type != CloudTypeNone {
					detection = d
					isCloud = true
				}
			}
			if !isCloud && h.getConfig().EnableAWSCheck {
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
		finalResp, _ := h.cloudHandler.HandleCloudReplacement(w, req, domain, qtype, int(detection.Type), resp,
			effectiveIPPrefer(h.getConfig().IPPrefer, decision))
		totalTime := totalTimer.End()
		h.Logger.Debug("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"client_addr":   w.RemoteAddr().String(),
			"source":        "cloud_replacement",
			"total_time":    totalTime,
			"upstream_time": upstreamTime,
		})
		h.recordQuery(querylog.Entry{
			Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
			Action: querylog.ActionCloud, ListName: decision.ListName, DNS: server, DNSMode: decision.DNSMode,
			ECS: ecs, Rcode: rcodeName(finalResp), Answers: answersSummary(finalResp),
			ElapsedMS: totalTime.Milliseconds(),
		})
		return
	}

	// 4. 非云域名：原样返回上游响应（owner、RRset完整保留）
	h.writeResponse(w, req, resp)

	// 检查域名是否命中分流列表
	isDomainCloud := h.cacheManager.IsDomainCloud(domain)

	var logSource string
	if isDomainCloud {
		logSource = "cloud"
	} else if decision.Matched {
		logSource = decision.ListName
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

	// 记录解析日志：命中的分流列表、实际应答的上游、解析模式与最终结果
	action, listName, mode := splitLogFields(decision)
	h.recordQuery(querylog.Entry{
		Domain: domain, QType: dns.TypeToString[qtype], Client: clientAddr(w),
		Action: action, ListName: listName, DNS: server, DNSMode: mode,
		ECS: ecs, Rcode: rcodeName(resp), Answers: answersSummary(resp),
		ElapsedMS: totalTime.Milliseconds(),
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

// upstreamsFor 由分流决策得出上游DNS服务器（未命中分流列表时回退全局上游）
func (h *RefactoredHandler) upstreamsFor(domain string, d SplitDecision) []string {
	if d.Matched {
		h.Logger.Debug("🎯 命中分流列表", map[string]interface{}{
			"domain":      domain,
			"list":        d.ListName,
			"dns_servers": d.DNS,
		})
		return d.DNS
	}
	return h.getConfig().Upstream
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
