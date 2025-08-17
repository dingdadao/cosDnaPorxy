package dns

import (
	"context"
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/geosite"
	"cosDnaPorxy/internal/metrics"
	"cosDnaPorxy/internal/utils"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Handler DNS请求处理器
type Handler struct {
	config            *config.Config
	logger            *utils.Logger
	geositeManager    *geosite.Manager
	metrics           *metrics.Collector
	hotCache          *HotCache              // 使用热点缓存替换原来的ristretto缓存
	cfNetSet4         *NetIPX
	cfNetSet6         *NetIPX
	aWSNetSet4        *NetIPX
	aWSNetSet6        *NetIPX
	whitelistPattern  []string
	designatedRules   []DesignatedDomain
	lastCFUpdate      time.Time
	cfExpire          time.Duration
	replaceExpire     time.Duration
	serverHealth      map[string]*ServerHealth
	cacheStatsCounter int // 缓存统计计数器

	// 连接池
	dotPool *DoTConnPool
	dohPool *DoHConnPool

	// 异步缓存刷新
	asyncRefreshChan chan *AsyncRefreshTask
	asyncWorkers     int32 // 当前活跃的异步工作线程数

	sync.RWMutex
}

// AsyncRefreshTask 异步刷新任务
type AsyncRefreshTask struct {
	Domain      string
	QType       uint16
	OriginalTTL time.Duration
	ExpireTime  time.Time
	Handler     *Handler
}

// NewHandler 创建新的DNS处理器
func NewHandler(cfg *config.Config) *Handler {
	cfExpire, err := time.ParseDuration(cfg.CFCacheTime)
	if err != nil {
		log.Fatalf("Invalid CF cache time: %v", err)
	}

	replaceExpire, err := time.ParseDuration(cfg.ReplaceCacheTime)
	if err != nil {
		log.Fatalf("Invalid replace cache time: %v", err)
	}

	// 创建热点缓存 - 固定大小，只保留最热门的域名
	var maxCacheSize int
	if cfg.Cache.MaxSize != "" {
		// 解析配置中的缓存大小，如 "50MB" -> 5000个域名（更保守的估算）
		if size, err := parseCacheSize(cfg.Cache.MaxSize); err == nil {
			// 假设每个域名平均占用10KB内存，更保守的估算
			maxCacheSize = int(size / (10 * 1024)) // 每10KB对应1个域名
		}
	}
	if maxCacheSize <= 0 {
		maxCacheSize = 5000 // 默认5000个域名，更保守
	}
	
	// 限制最大缓存大小，防止内存爆炸
	if maxCacheSize > 10000 {
		maxCacheSize = 10000
		log.Printf("缓存大小超过限制，已调整为: %d 个域名", maxCacheSize)
	}
	
	hotCache := NewHotCache(maxCacheSize)
	log.Printf("创建热点缓存，最大容量: %d 个域名", maxCacheSize)

	handler := &Handler{
		config:            cfg,
		logger:            utils.NewLogger(cfg.LogLevel),
		metrics:           metrics.NewCollector(),
		hotCache:          hotCache,
		cfNetSet4:         &NetIPX{},
		cfNetSet6:         &NetIPX{},
		aWSNetSet4:        &NetIPX{},
		aWSNetSet6:        &NetIPX{},
		cfExpire:          cfExpire,
		replaceExpire:     replaceExpire,
		serverHealth:      make(map[string]*ServerHealth),
		cacheStatsCounter: 10000, // 初始化缓存统计计数器

		// 初始化连接池
		dotPool: NewDoTConnPool(),
		dohPool: NewDoHConnPool(),

		// 初始化异步刷新 - 增加缓冲区大小，防止阻塞
		asyncRefreshChan: make(chan *AsyncRefreshTask, 5000), // 增加缓冲到5000个任务
		asyncWorkers:     0,
	}

	// 注册Prometheus指标
	handler.metrics.Register()

	// 初始化加载数据
	handler.loadWhitelist()
	handler.loadDesignatedDomains()
	handler.updateNetworks(cfg)

	geositeMgr, err := geosite.NewManager(cfg.GeositeURL, cfg.GeositeRefresh)
	if err != nil {
		log.Fatalf("初始化 GeositeManager 失败: %v", err)
	}
	geositeMgr.UpdateGeoSite()
	handler.geositeManager = geositeMgr

	// 启动后台更新任务
	go handler.runBackgroundTasks(cfg)

	// 启动异步健康检查（不影响查询性能）
	go handler.runAsyncHealthCheck()

	// 启动异步缓存刷新工作线程
	if cfg.Cache.EnableAsyncRefresh {
		handler.startAsyncRefreshWorkers(cfg.Cache.MaxAsyncWorkers)
	}

	// 启动标签系统清理
	go handler.periodicTagCleanup()
	
	// 启动内存监控
	handler.StartMemoryMonitor()
	
	// 启动主动缓存清理
	go handler.aggressiveCacheCleanup()

	return handler
}

// parseCacheSize 解析缓存大小配置，如 "100MB" -> 100*1024*1024
func parseCacheSize(sizeStr string) (int64, error) {
	// 这里简化处理，实际可以根据需要支持更多单位
	if len(sizeStr) < 2 {
		return 0, fmt.Errorf("invalid cache size format")
	}
	
	unit := sizeStr[len(sizeStr)-2:]
	valueStr := sizeStr[:len(sizeStr)-2]
	
	var multiplier int64
	switch unit {
	case "MB":
		multiplier = 1024 * 1024
	case "KB":
		multiplier = 1024
	case "GB":
		multiplier = 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unsupported unit: %s", unit)
	}
	
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return 0, err
	}
	
	return value * multiplier, nil
}

// handleSpecialQuery 处理特殊查询
func (h *Handler) handleSpecialQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question, rule *DesignatedDomain) {
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	h.metrics.GetDesignatedHits().Inc()

	var resp *dns.Msg
	var err error
	if rule.UpstreamType == "cn_upstream" {
		resp, err = h.proxyQuery(req, h.config.CNUpstream)
	} else if rule.UpstreamType == "not_cn_upstream" {
		resp, err = h.proxyQuery(req, h.config.NotCNUpstream)
	} else {
		resp, err = h.resolveViaDesignatedDNS(req, rule.DNS)
	}

	if err != nil || resp == nil {
		h.logger.Error("Designated query failed for %s via %s: %v", domain, rule.DNS, err)
		h.handleNormalQueryFallback(w, req, q)
		return
	}

	h.logger.Debug("designated query success: domain=%s dns=%s", domain, rule.DNS)
	// 设置缓存
	h.setCachedResponse(req, resp)
	if err := w.WriteMsg(resp); err != nil {
		h.logger.Error("WriteMsg失败: %v", err)
	}
	return
}

// handleQuery 处理查询
func (h *Handler) handleQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question, iptype int, Upstream []string) {
	var ipd *NetIPX
	domain := utils.SanitizeDomainName(q.Name)
	qtype := q.Qtype
	resp, err := h.proxyQuery(req, Upstream)
	if err != nil || resp == nil {
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
		if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		return
	}
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet4
			case AWSType:
				ipd = h.aWSNetSet4
			}
			if ip, err := netip.ParseAddr(v.A.String()); err == nil && ipd.Contains(ip) {
				h.handleReplacement(w, req, resp, qtype, domain, ip, iptype)
				return
			}
		case *dns.AAAA:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet6
			case AWSType:
				ipd = h.aWSNetSet6
			}
			if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && ipd.Contains(ip) {
				h.handleReplacement(w, req, resp, qtype, domain, ip, iptype)
				return
			}
		}
	}
	// 默认返回
	if err := w.WriteMsg(resp); err != nil {
		h.logger.Error("WriteMsg失败: %v", err)
	}
}

// handleNormalQueryFallback 普通查询回退处理
func (h *Handler) handleNormalQueryFallback(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp, err := h.proxyQuery(req, h.config.CNUpstream)
	if err != nil {
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[q.Qtype], "failed").Inc()
		if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		h.logger.Error("WriteMsg失败: %v", err)
	}
	h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[q.Qtype], "passed").Inc()
}

// recoverPanic 恢复panic
func recoverPanic(w dns.ResponseWriter, req *dns.Msg) {
	if err := recover(); err != nil {
		log.Printf("[PANIC] Recovered from panic: %v", err)
		if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
			log.Printf("WriteMsg失败: %v", err)
		}
	}
}

// ServeDNS 实现dns.Handler接口
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer recoverPanic(w, req)

	start := time.Now()
	cfg := h.config

	for _, q := range req.Question {
		domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		if _, ok := dns.IsDomainName(domain); !ok {
			h.logger.Info("请求查询的是非法域名: %s", domain)
			continue
		}

		qtype := q.Qtype
		if qtype != dns.TypeA && qtype != dns.TypeAAAA {
			continue
		}

		// 1. 缓存检查 - 缓存命中直接返回
		if cachedResp, hit := h.getCachedResponse(req); hit {
			if err := w.WriteMsg(cachedResp); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "cached").Inc()
			return
		}

		// 2. 域名查询检查 - 记录域名查询信息
		h.logger.Debug("【域名查询】开始处理域名: %s, 类型: %s", domain, dns.TypeToString[qtype])

		// 3. 定向域名检查 - 强制指定DNS策略
		h.logger.Debug("【定向域名检查】开始检查域名: %s", domain)
		if rule, matched := h.matchDesignatedDomain(domain); matched {
			h.logger.Info("【定向域名命中】%s，使用指定DNS: %s", domain, rule.DNS)
			AddOrUpdateDomainTagSimple(domain, TAG_DINGXIANG) // TAG_DINGXIANG = 1
			h.logger.Info("标签系统：%s 标记为定向域名", domain)
			h.metrics.GetDesignatedHits().Inc()
			h.handleSpecialQuery(w, req, q, rule)
			return
		}
		h.logger.Debug("【定向域名检查】域名 %s 未匹配定向规则", domain)

		// 4. 白名单检查 - 白名单域名跳过云服务检查，不进行IP替换
		if h.isWhitelisted(domain) {
			h.logger.Info("【白名单命中】%s，跳过云服务检查，直接进行分流", domain)
			AddOrUpdateDomainTagSimple(domain, TAG_WHITELIST) // TAG_WHITELIST = 6
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "whitelist").Inc()

			// 白名单域名直接进行geosite分流，跳过Cloudflare/AWS检查
			isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
			var upstream []string

			// 检查是否已经标记过，避免重复标记
			if existingTag, exists := QueryDomainTag(domain); exists {
				// 使用已有标签
				if existingTag.Tag == "2" { // TAG_CN = 2
					upstream = cfg.CNUpstream
					h.logger.Debug("白名单域名使用已有标签，国内DNS解析: %s", domain)
				} else {
					upstream = cfg.NotCNUpstream
					h.logger.Debug("白名单域名使用已有标签，国外DNS解析: %s", domain)
				}
			} else {
				// 首次标记
				if isCN {
					upstream = cfg.CNUpstream
					h.logger.Debug("白名单域名使用国内DNS解析: %s", domain)
					AddOrUpdateDomainTagSimple(domain, TAG_CN) // TAG_CN = 2
					h.logger.Info("标签系统：%s 标记为国内", domain)
				} else {
					upstream = cfg.NotCNUpstream
					h.logger.Debug("白名单域名使用国外DNS解析: %s", domain)
					AddOrUpdateDomainTagSimple(domain, TAG_NOT_CN) // TAG_NOT_CN = 3
					h.logger.Info("标签系统：%s 标记为国外", domain)
				}
			}

			resp, err := h.proxyQuery(req, upstream)
			if err != nil || resp == nil {
				h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
				if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
					h.logger.Error("WriteMsg失败: %v", err)
				}
				return
			}
			// 缓存已在proxyQuery内部设置，这里不需要重复设置
			if err := w.WriteMsg(resp); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
			return
		}

		//5. 云服务检查 - 使用定向域名指定的DNS策略进行查询
		h.logger.Debug("【云服务检查】开始检查域名: %s", domain)
		// 检查是否有定向域名配置，如果有则使用指定的DNS，否则使用默认策略
		var upstreamForCloudCheck []string
		if designatedRule, exists := h.getDesignatedRuleForDomain(domain); exists {
			// 使用定向域名指定的DNS策略
			if designatedRule.UpstreamType == "cn_upstream" {
				upstreamForCloudCheck = cfg.CNUpstream
				h.logger.Debug("云服务检查使用定向域名指定的国内DNS: %s", domain)
			} else if designatedRule.UpstreamType == "not_cn_upstream" {
				upstreamForCloudCheck = cfg.NotCNUpstream
				h.logger.Debug("云服务检查使用定向域名指定的国外DNS: %s", domain)
			} else {
				// 使用指定的具体DNS服务器
				upstreamForCloudCheck = []string{designatedRule.DNS}
				h.logger.Debug("云服务检查使用定向域名指定的DNS服务器: %s -> %s", domain, designatedRule.DNS)
			}
		} else {
			// 没有定向域名配置，使用默认策略（所有上游）
			upstreamForCloudCheck = append(cfg.CNUpstream, cfg.NotCNUpstream...)
			h.logger.Debug("云服务检查使用默认DNS策略: %s", domain)
		}

		h.logger.Debug("【云服务检查】执行DNS查询，使用上游: %v", upstreamForCloudCheck)
		resp, err := h.proxyQuery(req, upstreamForCloudCheck)
		if err != nil || resp == nil {
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
			if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			return
		}
		if h.isCloudResponse(resp, CFType) {
			AddOrUpdateDomainTagSimple(domain, TAG_CF) // TAG_CF = 4
			h.logger.Info("标签系统：%s 标记为Cloudflare", domain)
			h.handleReplacement(w, req, resp, qtype, domain, netip.Addr{}, CFType)
			return
		}
		if h.isCloudResponse(resp, AWSType) {
			AddOrUpdateDomainTagSimple(domain, TAG_AWS) // TAG_AWS = 5
			h.logger.Info("标签系统：%s 标记为AWS", domain)
			h.handleReplacement(w, req, resp, qtype, domain, netip.Addr{}, AWSType)
			return
		}

		//6. geosite国内外分流
		h.logger.Debug("【标签分流】开始进行geosite分流: %s", domain)
		isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
		var upstream []string

		// 检查是否已经标记过，避免重复标记
		if existingTag, exists := QueryDomainTag(domain); exists {
			// 使用已有标签
			if existingTag.Tag == "2" { // TAG_CN = 2
				upstream = cfg.CNUpstream
				h.logger.Debug("使用已有标签，国内DNS解析: %s", domain)
			} else {
				upstream = cfg.NotCNUpstream
				h.logger.Debug("使用已有标签，国外DNS解析: %s", domain)
			}
		} else {
			// 首次标记
			if isCN {
				upstream = cfg.CNUpstream
				h.logger.Debug("使用国内DNS解析: %s", domain)
				AddOrUpdateDomainTagSimple(domain, TAG_CN) // TAG_CN = 2
				h.logger.Info("标签系统：%s 标记为国内", domain)
			} else {
				upstream = cfg.NotCNUpstream
				h.logger.Debug("使用国外DNS解析: %s", domain)
				AddOrUpdateDomainTagSimple(domain, TAG_NOT_CN) // TAG_NOT_CN = 3
				h.logger.Info("标签系统：%s 标记为国外", domain)
			}
		}
		h.logger.Debug("【标签分流】执行DNS查询，使用上游: %v", upstream)
		resp, err = h.proxyQuery(req, upstream)
		if err != nil || resp == nil {
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
			if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
		} else {
			// 设置缓存
			h.setCachedResponse(req, resp)
			if err := w.WriteMsg(resp); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
		}
	}

	// 记录响应延迟
	latency := time.Since(start)
	h.metrics.GetResponseLatency().Observe(latency.Seconds())

	// 定期输出缓存统计信息
	if h.shouldLogCacheStats() {
		h.logCacheStats()
	}
}

// startAsyncRefreshWorkers 启动异步刷新工作线程
func (h *Handler) startAsyncRefreshWorkers(maxWorkers int) {
	if maxWorkers <= 0 {
		maxWorkers = 10 // 增加默认工作线程数到10
	}

	for i := 0; i < maxWorkers; i++ {
		go h.asyncRefreshWorker()
	}
	h.logger.Info("启动 %d 个异步缓存刷新工作线程", maxWorkers)
}

// asyncRefreshWorker 异步刷新工作线程
func (h *Handler) asyncRefreshWorker() {
	defer func() {
		if r := recover(); r != nil {
			h.logger.Error("异步刷新工作线程panic: %v", r)
			// 重新启动工作线程
			go h.asyncRefreshWorker()
		}
	}()
	
	for task := range h.asyncRefreshChan {
		// 检查任务是否仍然有效
		if time.Now().After(task.ExpireTime) {
			h.logger.Debug("异步刷新任务已过期，跳过: %s", task.Domain)
			atomic.AddInt32(&h.asyncWorkers, -1)
			continue
		}
		
		h.processAsyncRefresh(task)
	}
}

// processAsyncRefresh 处理异步刷新任务
func (h *Handler) processAsyncRefresh(task *AsyncRefreshTask) {
	// 检查是否已经过期
	if time.Now().After(task.ExpireTime) {
		h.logger.Debug("异步刷新任务已过期，跳过: %s", task.Domain)
		return
	}

	// 减少工作线程计数
	atomic.AddInt32(&h.asyncWorkers, -1)

	h.logger.Debug("【异步刷新】开始刷新域名: %s, 原始TTL: %v, 过期时间: %v",
		task.Domain, task.OriginalTTL, task.ExpireTime)

	// 创建DNS查询
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(task.Domain), task.QType)

	// 根据域名类型选择上游
	var upstream []string
	if h.isWhitelisted(task.Domain) {
		// 白名单域名使用geosite分流
		isCN := h.geositeManager.CheckDomainInTag(task.Domain, h.config.GeositeGroup)
		if isCN {
			upstream = h.config.CNUpstream
			h.logger.Debug("【异步刷新】白名单域名使用国内DNS: %s", task.Domain)
		} else {
			upstream = h.config.NotCNUpstream
			h.logger.Debug("【异步刷新】白名单域名使用国外DNS: %s", task.Domain)
		}
	} else if rule, matched := h.matchDesignatedDomain(task.Domain); matched {
		// 定向域名使用指定策略
		if rule.UpstreamType == "cn_upstream" {
			upstream = h.config.CNUpstream
			h.logger.Debug("【异步刷新】定向域名使用国内DNS: %s", task.Domain)
		} else if rule.UpstreamType == "not_cn_upstream" {
			upstream = h.config.NotCNUpstream
			h.logger.Debug("【异步刷新】定向域名使用国外DNS: %s", task.Domain)
		} else {
			upstream = []string{rule.DNS}
			h.logger.Debug("【异步刷新】定向域名使用指定DNS: %s -> %s", task.Domain, rule.DNS)
		}
	} else {
		// 默认使用所有上游
		upstream = append(h.config.CNUpstream, h.config.NotCNUpstream...)
		h.logger.Debug("【异步刷新】使用默认DNS策略: %s", task.Domain)
	}

	h.logger.Debug("【异步刷新】执行DNS查询，使用上游: %v", upstream)

	// 执行查询
	resp, err := h.proxyQuery(req, upstream)
	if err != nil {
		h.logger.Debug("【异步刷新】查询失败: %s, 错误: %v", task.Domain, err)
		return
	}

	if resp != nil && resp.Rcode == dns.RcodeSuccess {
		// 记录刷新前的信息
		h.logger.Debug("【异步刷新】查询成功: %s, 响应码: %s", task.Domain, dns.RcodeToString[resp.Rcode])

		// 记录响应详情
		if len(resp.Answer) > 0 {
			for i, rr := range resp.Answer {
				h.logger.Debug("【异步刷新】响应记录 %d: %s, TTL: %ds", i+1, rr.String(), rr.Header().Ttl)
			}
		}

		// 计算新的缓存TTL
		newTTL := h.calculateCacheTTL(resp)
		h.logger.Debug("【异步刷新】计算新TTL: %v", newTTL)

		// 查询成功，更新缓存
		h.setCachedResponse(req, resp)
		h.logger.Debug("【异步刷新】缓存更新完成: %s, 新TTL: %v", task.Domain, newTTL)
	} else {
		h.logger.Debug("【异步刷新】查询返回无效响应: %s, 响应码: %s", task.Domain, dns.RcodeToString[resp.Rcode])
	}
}

// Close 关闭Handler，清理资源
func (h *Handler) Close() {
	if h.dotPool != nil {
		h.dotPool.Close()
	}
	if h.dohPool != nil {
		h.dohPool.Close()
	}
	if h.hotCache != nil {
		h.hotCache.Clear()
	}

	// 关闭异步刷新通道
	if h.asyncRefreshChan != nil {
		close(h.asyncRefreshChan)
	}
}

// handleAsyncRefreshQuery 处理异步刷新的完整DNS查询流程
// 跳过缓存检查，重新进行分流和查询
func (h *Handler) handleAsyncRefreshQuery(req *dns.Msg, domain string, qtype uint16) *dns.Msg {
	cfg := h.config

	h.logger.Debug("【异步刷新】开始完整DNS查询流程: %s", domain)

	// 1. 域名查询检查（日志记录）
	h.logger.Debug("【异步刷新】【域名查询】开始处理域名: %s, 类型: %s", domain, dns.TypeToString[qtype])

	// 2. 定向域名检查 - 强制指定DNS策略
	if rule, matched := h.matchDesignatedDomain(domain); matched {
		h.logger.Info("【异步刷新】【定向域名命中】%s，使用指定DNS: %s", domain, rule.DNS)
		AddOrUpdateDomainTagSimple(domain, TAG_DINGXIANG)
		h.logger.Info("【异步刷新】标签系统：%s 标记为定向域名", domain)
		h.metrics.GetDesignatedHits().Inc()
		return h.handleSpecialQueryForAsync(req, domain, qtype, rule)
	}
	h.logger.Debug("【异步刷新】【定向域名检查】域名 %s 未匹配定向规则", domain)

	// 3. 白名单检查 - 白名单域名跳过云服务检查，不进行IP替换
	if h.isWhitelisted(domain) {
		h.logger.Info("【异步刷新】【白名单命中】%s，跳过云服务检查，直接进行分流", domain)
		AddOrUpdateDomainTagSimple(domain, TAG_WHITELIST)
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "whitelist").Inc()

		// 白名单域名直接进行geosite分流，跳过Cloudflare/AWS检查
		isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
		var upstream []string

		// 检查是否已经标记过，避免重复标记
		if existingTag, exists := QueryDomainTag(domain); exists {
			if existingTag.Tag == "2" { // TAG_CN = 2
				upstream = cfg.CNUpstream
				h.logger.Debug("【异步刷新】白名单域名使用已有标签，国内DNS解析: %s", domain)
			} else {
				upstream = cfg.NotCNUpstream
				h.logger.Debug("【异步刷新】白名单域名使用已有标签，国外DNS解析: %s", domain)
			}
		} else {
			// 首次标记
			if isCN {
				upstream = cfg.CNUpstream
				h.logger.Debug("【异步刷新】白名单域名使用国内DNS解析: %s", domain)
				AddOrUpdateDomainTagSimple(domain, TAG_CN)
				h.logger.Info("【异步刷新】标签系统：%s 标记为国内", domain)
			} else {
				upstream = cfg.NotCNUpstream
				h.logger.Debug("【异步刷新】白名单域名使用国外DNS解析: %s", domain)
				AddOrUpdateDomainTagSimple(domain, TAG_NOT_CN)
				h.logger.Info("【异步刷新】标签系统：%s 标记为国外", domain)
			}
		}

		resp, err := h.proxyQuery(req, upstream)
		if err != nil || resp == nil {
			h.logger.Error("【异步刷新】白名单域名查询失败: %s", domain)
			return nil
		}
		return resp
	}

	// 4. 云服务检查 - 使用定向域名指定的DNS策略进行查询
	h.logger.Debug("【异步刷新】【云服务检查】开始检查域名: %s", domain)
	var upstreamForCloudCheck []string
	if designatedRule, exists := h.getDesignatedRuleForDomain(domain); exists {
		// 使用定向域名指定的DNS策略
		if designatedRule.UpstreamType == "cn_upstream" {
			upstreamForCloudCheck = cfg.CNUpstream
			h.logger.Debug("【异步刷新】云服务检查使用定向域名指定的国内DNS: %s", domain)
		} else if designatedRule.UpstreamType == "not_cn_upstream" {
			upstreamForCloudCheck = cfg.NotCNUpstream
			h.logger.Debug("【异步刷新】云服务检查使用定向域名指定的国外DNS: %s", domain)
		} else {
			upstreamForCloudCheck = []string{designatedRule.DNS}
			h.logger.Debug("【异步刷新】云服务检查使用定向域名指定的DNS服务器: %s -> %s", domain, designatedRule.DNS)
		}
	} else {
		// 没有定向域名配置，使用默认策略（所有上游）
		upstreamForCloudCheck = append(cfg.CNUpstream, cfg.NotCNUpstream...)
		h.logger.Debug("【异步刷新】云服务检查使用默认DNS策略: %s", domain)
	}

	h.logger.Debug("【异步刷新】【云服务检查】执行DNS查询，使用上游: %v", upstreamForCloudCheck)
	resp, err := h.proxyQuery(req, upstreamForCloudCheck)
	if err != nil || resp == nil {
		h.logger.Error("【异步刷新】云服务检查查询失败: %s", domain)
		return nil
	}

	// 检查是否为云服务响应
	if h.isCloudResponse(resp, CFType) {
		AddOrUpdateDomainTagSimple(domain, TAG_CF)
		h.logger.Info("【异步刷新】标签系统：%s 标记为Cloudflare", domain)
		// 处理IP替换
		return h.handleReplacementForAsync(req, resp, qtype, domain, netip.Addr{}, CFType)
	}
	if h.isCloudResponse(resp, AWSType) {
		AddOrUpdateDomainTagSimple(domain, TAG_AWS)
		h.logger.Info("【异步刷新】标签系统：%s 标记为AWS", domain)
		// 处理IP替换
		return h.handleReplacementForAsync(req, resp, qtype, domain, netip.Addr{}, AWSType)
	}

	// 5. geosite国内外分流
	h.logger.Debug("【异步刷新】【标签分流】开始进行geosite分流: %s", domain)
	isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
	var upstream []string

	// 检查是否已经标记过，避免重复标记
	if existingTag, exists := QueryDomainTag(domain); exists {
		if existingTag.Tag == "2" { // TAG_CN = 2
			upstream = cfg.CNUpstream
			h.logger.Debug("【异步刷新】使用已有标签，国内DNS解析: %s", domain)
		} else {
			upstream = cfg.NotCNUpstream
			h.logger.Debug("【异步刷新】使用已有标签，国外DNS解析: %s", domain)
		}
	} else {
		// 首次标记
		if isCN {
			upstream = cfg.CNUpstream
			h.logger.Debug("【异步刷新】使用国内DNS解析: %s", domain)
			AddOrUpdateDomainTagSimple(domain, TAG_CN)
			h.logger.Info("【异步刷新】标签系统：%s 标记为国内", domain)
		} else {
			upstream = cfg.NotCNUpstream
			h.logger.Debug("【异步刷新】使用国外DNS解析: %s", domain)
			h.logger.Info("【异步刷新】标签系统：%s 标记为国外", domain)
			AddOrUpdateDomainTagSimple(domain, TAG_NOT_CN)
		}
	}

	h.logger.Debug("【异步刷新】【标签分流】执行DNS查询，使用上游: %v", upstream)
	resp, err = h.proxyQuery(req, upstream)
	if err != nil || resp == nil {
		h.logger.Error("【异步刷新】标签分流查询失败: %s", domain)
		return nil
	}

	return resp
}

// handleSpecialQueryForAsync 异步刷新时的特殊查询处理
func (h *Handler) handleSpecialQueryForAsync(req *dns.Msg, domain string, qtype uint16, rule *DesignatedDomain) *dns.Msg {
	h.logger.Debug("【异步刷新】处理定向域名查询: %s via %s", domain, rule.DNS)

	var resp *dns.Msg
	var err error
	if rule.UpstreamType == "cn_upstream" {
		resp, err = h.proxyQuery(req, h.config.CNUpstream)
	} else if rule.UpstreamType == "not_cn_upstream" {
		resp, err = h.proxyQuery(req, h.config.NotCNUpstream)
	} else {
		// 使用指定的具体DNS服务器
		network, timeout := h.getNetworkAndTimeout(rule.DNS)
		c := &dns.Client{
			Net:     network,
			Timeout: timeout,
		}
		resp, _, err = c.ExchangeContext(context.Background(), req, rule.DNS)
	}

	if err != nil || resp == nil {
		h.logger.Error("【异步刷新】定向域名查询失败: %s via %s: %v", domain, rule.DNS, err)
		return nil
	}

	h.logger.Debug("【异步刷新】定向域名查询成功: %s via %s", domain, rule.DNS)
	return resp
}

// handleReplacementForAsync 异步刷新时的IP替换处理
func (h *Handler) handleReplacementForAsync(req *dns.Msg, resp *dns.Msg, qtype uint16, domain string, originalIP netip.Addr, iptype int) *dns.Msg {
	h.logger.Debug("【异步刷新】处理IP替换: %s, 类型: %d", domain, iptype)

	// 这里可以添加IP替换逻辑，但异步刷新主要是更新缓存
	// 所以直接返回原始响应即可
	return resp
}

// periodicTagCleanup 定期清理标签系统
func (h *Handler) periodicTagCleanup() {
	ticker := time.NewTicker(10 * time.Minute) // 每10分钟清理一次
	defer ticker.Stop()
	
	for range ticker.C {
		h.cleanupExpiredTags()
		
		// 强制刷新标签到文件，释放内存
		TagMapMu.Lock()
		if len(TagDirtySimple) > 0 {
			go FlushDomainTagsSimpleToFile()
		}
		TagMapMu.Unlock()
	}
}
