package dns

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/geosite"
	"cosDnaPorxy/internal/metrics"
	"cosDnaPorxy/internal/utils"
	"crypto/tls"
	"fmt"
	"github.com/dgraph-io/ristretto"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Handler DNS请求处理器
type Handler struct {
	config            *config.Config
	logger            *utils.Logger
	geositeManager    *geosite.Manager
	metrics           *metrics.Collector
	cache             *ristretto.Cache
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
	sync.RWMutex
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

	// 优化缓存配置 - 增加缓存大小和性能
	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 100,      // 增加计数器数量 (10x 预期缓存项数)
		MaxCost:     10 << 20, // 增加最大成本到100MB
		BufferItems: 64,       // 保持默认值
		Metrics:     true,     // 启用指标收集
		OnEvict: func(item *ristretto.Item) {
			log.Printf("[缓存] 项目被驱逐: key=%v, cost=%d", item.Key, item.Cost)
		},
	})
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	handler := &Handler{
		config:            cfg,
		logger:            utils.NewLogger(cfg.LogLevel),
		metrics:           metrics.NewCollector(),
		cache:             cache,
		cfNetSet4:         &NetIPX{},
		cfNetSet6:         &NetIPX{},
		aWSNetSet4:        &NetIPX{},
		aWSNetSet6:        &NetIPX{},
		cfExpire:          cfExpire,
		replaceExpire:     replaceExpire,
		serverHealth:      make(map[string]*ServerHealth),
		cacheStatsCounter: 10000, // 初始化缓存统计计数器
	}

	// 注册Prometheus指标
	handler.metrics.Register()

	// 初始化加载数据
	//handler.loadWhitelist()
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

	return handler
}

// loadWhitelist 加载白名单
func (h *Handler) loadWhitelist() {
	if h.config.WhitelistFile == "" {
		h.logger.Warn("Whitelist file not configured")
		return
	}

	// 尝试创建文件（如果不存在）
	if _, err := os.Stat(h.config.WhitelistFile); os.IsNotExist(err) {
		h.logger.Warn("Whitelist file does not exist, creating: %s", h.config.WhitelistFile)
		err := os.WriteFile(h.config.WhitelistFile, []byte("# Whitelist domains\nexample.com\n"), 0644)
		if err != nil {
			h.logger.Error("Failed to create whitelist file: %v", err)
			return
		}
	}

	f, err := os.Open(h.config.WhitelistFile)
	if err != nil {
		h.logger.Error("Failed to open whitelist: %v", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var newList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			newList = append(newList, line)
		}
	}

	if err := scanner.Err(); err != nil {
		h.logger.Error("Error reading whitelist file: %v", err)
		return
	}

	h.Lock()
	h.whitelistPattern = newList
	h.Unlock()

	h.logger.Info("✅ Whitelist updated successfully: %d entries", len(newList))
}

// loadDesignatedDomains 加载定向域名规则
func (h *Handler) loadDesignatedDomains() {
	if h.config.DesignatedDomain == "" {
		h.logger.Warn("Designated domains file not configured")
		return
	}

	// 文件不存在则创建默认
	if _, err := os.Stat(h.config.DesignatedDomain); os.IsNotExist(err) {
		h.logger.Warn("Designated domains file not found, creating: %s", h.config.DesignatedDomain)
		defaultContent := []byte("# Format: domain dns_server\n*.example.com 8.8.8.8\n")
		if err := os.WriteFile(h.config.DesignatedDomain, defaultContent, 0644); err != nil {
			h.logger.Error("Failed to create designated domains file: %v", err)
			return
		}
	}

	f, err := os.Open(h.config.DesignatedDomain)
	if err != nil {
		h.logger.Error("Failed to open designated domains file: %v", err)
		return
	}
	defer f.Close()

	var newRules []DesignatedDomain
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			h.logger.Warn("Invalid line format, skipping: %s", line)
			continue
		}

		rawPattern := strings.ToLower(parts[0])
		var regexPattern string
		if strings.Contains(rawPattern, "*") {
			// 通配符转正则
			regexPattern = "^" + regexp.QuoteMeta(rawPattern) + "$"
			regexPattern = strings.ReplaceAll(regexPattern, `\\*`, ".*")
		} else if strings.HasPrefix(rawPattern, "/") && strings.HasSuffix(rawPattern, "/") && len(rawPattern) > 2 {
			// 允许用户直接写正则，如 /mgstage.*/
			regexPattern = rawPattern[1 : len(rawPattern)-1]
		} else {
			// 关键词自动模糊匹配
			regexPattern = ".*" + regexp.QuoteMeta(rawPattern) + ".*"
		}

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			h.logger.Warn("Invalid regex for pattern: %s (%v)", rawPattern, err)
			continue
		}

		upstreamType := ""
		upstreamVal := strings.ToLower(parts[1])
		if upstreamVal == "cn_upstream" || upstreamVal == "not_cn_upstream" {
			upstreamType = upstreamVal
		}

		newRules = append(newRules, DesignatedDomain{
			Domain:       rawPattern,
			DNS:          parts[1],
			Regex:        re,
			UpstreamType: upstreamType,
		})
	}

	if err := scanner.Err(); err != nil {
		h.logger.Error("Error reading designated domains file: %v", err)
		return
	}

	h.Lock()
	h.designatedRules = newRules
	h.Unlock()

	h.logger.Info("✅ Designated domains updated successfully: %d entries", len(newRules))
}

// updateNetworks 更新网络列表
func (h *Handler) updateNetworks(cfg *config.Config) {
	h.Lock()
	defer h.Unlock()

	if time.Since(h.lastCFUpdate) < h.cfExpire {
		return
	}

	h.logger.Info("Loading Cloudflare and AWS IP ranges from local cache...")

	cfCachePath4 := cfg.CFMrsFile4
	cfCachePath6 := cfg.CFMrsFile6
	aWSCachePath := cfg.AWSMrsFile46

	// 加载 Cloudflare IPv4
	if _, err := os.Stat(cfCachePath4); err == nil {
		if err := h.cfNetSet4.LoadFromFile(cfCachePath4); err != nil {
			h.logger.Error("Failed to load IPv4 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv4 prefixes", len(h.cfNetSet4.list))
		}
	} else {
		h.logger.Warn("IPv4 cache file not found: %s", cfCachePath4)
	}

	// 加载 Cloudflare IPv6
	if _, err := os.Stat(cfCachePath6); err == nil {
		if err := h.cfNetSet6.LoadFromFile(cfCachePath6); err != nil {
			h.logger.Error("Failed to load IPv6 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv6 prefixes", len(h.cfNetSet6.list))
		}
	} else {
		h.logger.Warn("IPv6 cache file not found: %s", cfCachePath6)
	}

	// 加载 AWS IP 段
	if _, err := os.Stat(aWSCachePath); err == nil {
		err := LoadAWSIPRanges(aWSCachePath, h.aWSNetSet4, h.aWSNetSet6)
		if err != nil {
			h.logger.Error("Failed to load AWS IP ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv4 prefixes and %d IPv6 prefixes from AWS",
				len(h.aWSNetSet4.list), len(h.aWSNetSet6.list))
		}
	} else {
		h.logger.Warn("AWS cache file not found: %s", aWSCachePath)
	}

	h.lastCFUpdate = time.Now()
}

// runBackgroundTasks 运行后台任务
func (h *Handler) runBackgroundTasks(cfg *config.Config) {
	// 定时更新Cloudflare网络列表
	cfTicker := time.NewTicker(5 * time.Minute)
	defer cfTicker.Stop()

	// 定时重新加载白名单和定向域名
	reloadTicker := time.NewTicker(1 * time.Minute)
	defer reloadTicker.Stop()

	geositeTicker := time.NewTicker(h.geositeManager.GetRefreshDuration())
	defer geositeTicker.Stop()

	for {
		select {
		case <-cfTicker.C:
			h.updateNetworks(cfg)
		case <-reloadTicker.C:
			h.loadDesignatedDomains()
			//h.loadWhitelist()
		case <-geositeTicker.C:
			h.geositeManager.UpdateGeoSite()
		}
	}
}

// isWhitelisted 检查域名是否在白名单中
func (h *Handler) isWhitelisted(qname string) bool {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, pattern := range h.whitelistPattern {
		pattern = strings.ToLower(pattern)
		if utils.MatchDomain(pattern, domain) {
			return true
		}
	}
	return false
}

// matchDesignatedDomain 匹配定向域名
func (h *Handler) matchDesignatedDomain(qname string) (*DesignatedDomain, bool) {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, rule := range h.designatedRules {
		if rule.Regex != nil {
			if rule.Regex.(*regexp.Regexp).MatchString(domain) {
				h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
				return &rule, true
			}
		} else {
			pattern := strings.ToLower(rule.Domain)
			if utils.MatchDomain(pattern, domain) {
				h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
				return &rule, true
			}
		}
	}
	return nil, false
}

// checkServerHealth 检查服务器健康状态
func (h *Handler) checkServerHealth(server string) bool {
	// 生成缓存键
	cacheKey := fmt.Sprintf("health:%s", server)

	// 尝试从缓存获取健康状态
	if cached, found := h.cache.Get(cacheKey); found {
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

	// 如果距离上次检查时间太短，直接返回上次结果
	if time.Since(health.LastCheck) < 5*time.Second {
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
	} else {
		health.FailureCount++
		health.SuccessCount = 0
	}

	// 缓存健康状态（短期缓存，5秒）
	h.cache.SetWithTTL(cacheKey, isHealthy, 1, 15*time.Second)

	return isHealthy
}

// performHealthCheck 执行实际的健康检查
func (h *Handler) performHealthCheck(server string) bool {
	// 创建测试查询
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)

	// 设置超时
	_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// 根据服务器类型选择查询方法
	if strings.HasPrefix(server, "https://") {
		// DoH查询
		resp, err := h.queryDoH(req, server, false)
		return err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess
	} else {
		// UDP/TCP查询
		resp, err := h.querySingleServer(req, server)
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

// queryDoH 通过DoH协议查询DNS
// 增加参数: isCN，true表示国内分流，false表示国外分流
func (h *Handler) queryDoH(req *dns.Msg, dohURL string, isCN bool) (*dns.Msg, error) {
	var dohConf config.DoHConfig
	if isCN {
		dohConf = h.config.DoH.CN
	} else {
		dohConf = h.config.DoH.NotCN
	}
	if !dohConf.Enabled {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "DoH not enabled", nil)
	}

	parsedURL, err := url.Parse(dohURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}
	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid DoH URL hostname")
	}

	resolverIP, err := h.resolveDoHHostname(host, isCN)
	if err != nil {
		h.logger.Warn("无法解析DoH域名", "host", host, "err", err)
		return nil, err
	}

	// IPv6 地址加中括号处理
	if ip := net.ParseIP(resolverIP); ip != nil && ip.To4() == nil {
		resolverIP = "[" + resolverIP + "]"
	}

	// 提取端口或使用默认 443
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	dialAddr := net.JoinHostPort(resolverIP, port)

	// 打包 DNS 查询
	dnsQuery, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	httpReq, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "cosDnaProxy/1.0")
	httpReq.Header.Set("Accept-Encoding", "gzip")

	// 设置超时
	timeout, err := time.ParseDuration(dohConf.Timeout)
	if err != nil {
		h.logger.Warn("DoH 超时时间格式无效，使用默认值", "raw", dohConf.Timeout, "default", "5s")
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 所有 DoH 请求都定向到解析出的 IP 和端口
				return net.Dial(network, dialAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host, // 保证 TLS 证书校验通过
			},
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w (耗时: %v)", err, duration)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d (耗时: %v)", resp.StatusCode, duration)
	}

	// 是否是 gzip 响应
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return dnsResp, nil
}

// resolveDoHHostname 解析DoH域名，isCN区分国内/国外
func (h *Handler) resolveDoHHostname(hostname string, isCN bool) (string, error) {
	var dohConf config.DoHConfig
	if isCN {
		dohConf = h.config.DoH.CN
	} else {
		dohConf = h.config.DoH.NotCN
	}
	// 创建DNS查询
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	c := &dns.Client{
		Timeout: 3 * time.Second,
		Net:     "udp",
	}

	resp, _, err := c.Exchange(req, dohConf.Resolver)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DoH hostname: %w", err)
	}

	if resp == nil || len(resp.Answer) == 0 {
		return "", fmt.Errorf("no answer for DoH hostname")
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("no A record found for DoH hostname")
}

// querySingleServer 查询单个DNS服务器
func (h *Handler) querySingleServer(req *dns.Msg, server string) (*dns.Msg, error) {
	var c *dns.Client
	var resp *dns.Msg
	var err error

	start := time.Now()

	if strings.HasPrefix(server, "https://") {
		// DoH 查询
		isCN := h.isCNUpstream(server)
		resp, err = h.queryDoH(req, server, isCN)
	} else {
		network, timeout := h.getNetworkAndTimeout(server)
		c = &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		serverAddr := h.getServerAddress(server)
		resp, _, err = c.Exchange(req, serverAddr)
	}

	latency := time.Since(start)
	h.metrics.GetUpstreamLatency().Observe(latency.Seconds())

	if err != nil {
		h.logger.Debug("DNS查询失败 %s: %v (耗时: %v)", server, err, latency)
		return nil, err
	}

	if resp == nil {
		h.logger.Debug("DNS服务器 %s 返回空响应 (耗时: %v)", server, latency)
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "empty response from server", nil)
	}

	if resp.Rcode != dns.RcodeSuccess {
		h.logger.Debug("DNS服务器 %s 返回错误码: %s (耗时: %v)",
			server, dns.RcodeToString[resp.Rcode], latency)
	}

	h.logger.Debug("DNS查询成功 %s: %s (耗时: %v)",
		server, dns.RcodeToString[resp.Rcode], latency)
	return resp, nil
}

// getNetworkAndTimeout 根据服务器地址获取网络协议和超时时间
func (h *Handler) getNetworkAndTimeout(server string) (network string, timeout time.Duration) {
	switch {
	case strings.HasPrefix(server, "https://"):
		return "https", 5 * time.Second
	case strings.HasPrefix(server, "tls://"):
		return "tcp-tls", 4 * time.Second
	case strings.HasPrefix(server, "tcp://"):
		return "tcp", 3 * time.Second
	case strings.HasPrefix(server, "udp://"):
		return "udp", 3 * time.Second
	default:
		return "udp", 3 * time.Second
	}
}

// getServerAddress 获取服务器地址（去除协议前缀）
func (h *Handler) getServerAddress(server string) string {
	switch {
	case strings.HasPrefix(server, "https://"):
		return server // DoH 保持原样
	case strings.HasPrefix(server, "tls://"):
		return strings.TrimPrefix(server, "tls://")
	case strings.HasPrefix(server, "tcp://"):
		return strings.TrimPrefix(server, "tcp://")
	case strings.HasPrefix(server, "udp://"):
		return strings.TrimPrefix(server, "udp://")
	default:
		return server
	}
}

// queryMultipleServers 并发查询多个DNS服务器，选择最快的有效响应
func (h *Handler) queryMultipleServers(req *dns.Msg, servers []string) (*dns.Msg, error) {
	type result struct {
		resp    *dns.Msg
		err     error
		server  string
		latency time.Duration
	}

	// 创建结果通道
	resultChan := make(chan result, len(servers))

	// 并发查询所有服务器
	for _, server := range servers {
		go func(srv string) {
			start := time.Now()
			resp, err := h.querySingleServer(req, srv)
			latency := time.Since(start)

			resultChan <- result{
				resp:    resp,
				err:     err,
				server:  srv,
				latency: latency,
			}
		}(server)
	}

	// 等待第一个成功响应或所有服务器都失败
	var lastError error
	timeout := time.After(5 * time.Second)

	for i := 0; i < len(servers); i++ {
		select {
		case res := <-resultChan:
			if res.err == nil && res.resp != nil && res.resp.Rcode == dns.RcodeSuccess {
				h.logger.Debug("选择最快的DNS响应: %s (耗时: %v)", res.server, res.latency)
				return res.resp, nil
			}
			lastError = res.err

		case <-timeout:
			h.logger.Warn("DNS查询超时")
			return nil, utils.NewDNSError(dns.RcodeServerFailure, "query timeout", nil)
		}
	}

	// 所有服务器都失败了
	if lastError != nil {
		return nil, lastError
	}

	return nil, utils.NewDNSError(dns.RcodeServerFailure, "all upstream servers failed", nil)
}

// generateCacheKey 生成缓存键 - 只使用域名和查询类型
func (h *Handler) generateCacheKey(req *dns.Msg) string {
	var key strings.Builder
	for _, q := range req.Question {
		key.WriteString(q.Name)
		key.WriteString(fmt.Sprintf(":%d", q.Qtype))
	}
	return key.String()
}

// getCachedResponse 获取缓存的DNS响应
func (h *Handler) getCachedResponse(req *dns.Msg) (*dns.Msg, bool) {
	cacheKey := h.generateCacheKey(req)

	if cached, found := h.cache.Get(cacheKey); found {
		if cachedResp, ok := cached.(*dns.Msg); ok {
			h.logger.Debug("缓存命中: %s, Rcode=%d, Answer数=%d", cacheKey, cachedResp.Rcode, len(cachedResp.Answer))
			if cachedResp != nil && len(cachedResp.Answer) > 0 {
				h.metrics.GetCacheHits().WithLabelValues("dns_query").Inc()
				// 创建响应副本以避免并发问题
				resp := cachedResp.Copy()
				resp.Id = req.Id // 保持请求ID一致
				return resp, true
			} else {
				h.logger.Warn("缓存命中但内容无效: %s", cacheKey)
			}
		}
	}

	h.logger.Debug("缓存未命中: %s", cacheKey)
	return nil, false
}

// setCachedResponse 设置DNS响应到缓存
func (h *Handler) setCachedResponse(req *dns.Msg, resp *dns.Msg) {
	if resp == nil {
		return
	}

	cacheKey := h.generateCacheKey(req)
	cacheCost := h.calculateCacheCost(resp)
	cacheTTL := h.calculateCacheTTL(resp)

	h.cache.SetWithTTL(cacheKey, resp, cacheCost, cacheTTL)
	h.logger.Debug("缓存已设置: %s, TTL=%v", cacheKey, cacheTTL)
}

// proxyQuery 代理查询 - 重新设计版本
func (h *Handler) proxyQuery(req *dns.Msg, upstream []string) (*dns.Msg, error) {
	if len(upstream) == 0 {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "no upstream servers configured", nil)
	}

	// 获取健康的上游服务器
	healthyServers := h.getHealthyServers(upstream)
	if len(healthyServers) == 0 {
		return nil, fmt.Errorf("no healthy upstream servers available")
	}

	// 并发查询多个上游服务器
	resp, err := h.queryMultipleServers(req, healthyServers)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// calculateCacheCost 计算缓存成本
func (h *Handler) calculateCacheCost(resp *dns.Msg) int64 {
	if resp == nil {
		return 1
	}
	packed, err := resp.Pack()
	if err != nil {
		return 1
	}
	return int64(len(packed))
}

// calculateCacheTTL 计算缓存TTL
func (h *Handler) calculateCacheTTL(resp *dns.Msg) time.Duration {
	if resp == nil || len(resp.Answer) == 0 {
		return 30 * time.Second // 默认30秒
	}

	// 找到最小的TTL
	minTTL := uint32(600) // 默认1小时
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	// 限制TTL范围
	if minTTL < 30 {
		minTTL = 30
	} else if minTTL > 3600 {
		minTTL = 3600
	}

	return time.Duration(minTTL) * time.Second
}

// isCloudResponse 检查是否为云服务响应
func (h *Handler) isCloudResponse(msg *dns.Msg, iptype int) bool {
	var ipd *NetIPX
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet4
			case AWSType:
				ipd = h.aWSNetSet4
			}
			if ipd != nil {
				if ip, err := netip.ParseAddr(v.A.String()); err == nil && ipd.Contains(ip) {
					h.logger.Debug("IPv4 %s is in known IP range", ip)
					return true
				}
			}
		case *dns.AAAA:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet6
			case AWSType:
				ipd = h.aWSNetSet6
			}
			if ipd != nil {
				if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && ipd.Contains(ip) {
					h.logger.Debug("IPv6 %s is in known IP range", ip)
					return true
				}
			}
		}
	}
	return false
}

// resolveReplaceCNAME 解析替换CNAME
func (h *Handler) resolveReplaceCNAME(cname string) []netip.Addr {
	// 生成缓存键
	cacheKey := fmt.Sprintf("replace_cname:%s", cname)

	// 尝试从缓存获取
	if cached, found := h.cache.Get(cacheKey); found {
		if cachedAddrs, ok := cached.([]netip.Addr); ok {
			h.logger.Debug("替换域名缓存命中: %s", cname)
			h.metrics.GetCacheHits().WithLabelValues("replace_cname").Inc()
			return cachedAddrs
		}
	}

	// 缓存未命中，执行解析
	h.logger.Debug("替换域名缓存未命中，执行解析: %s", cname)

	var addrs []netip.Addr

	// 使用所有上游解析
	allUpstreams := append(h.config.CNUpstream, h.config.NotCNUpstream...)

	// 创建A记录查询
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(cname), dns.TypeA)

	resp, err := h.proxyQuery(req, allUpstreams)
	if err == nil && resp != nil {
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, err := netip.ParseAddr(a.A.String()); err == nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}

	// 创建AAAA记录查询
	reqAAAA := &dns.Msg{}
	reqAAAA.SetQuestion(dns.Fqdn(cname), dns.TypeAAAA)

	respAAAA, err := h.proxyQuery(reqAAAA, allUpstreams)
	if err == nil && respAAAA != nil {
		for _, rr := range respAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				if ip, err := netip.ParseAddr(aaaa.AAAA.String()); err == nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}

	// 去重
	addrs = h.uniqueAddrs(addrs)

	// 缓存结果（使用较长的TTL，因为替换域名相对稳定）
	if len(addrs) > 0 {
		h.cache.SetWithTTL(cacheKey, addrs, int64(len(addrs)*16), h.replaceExpire)
		h.logger.Debug("替换域名解析结果已缓存: %s -> %v", cname, addrs)
	}

	return addrs
}

// uniqueAddrs 去重IP地址
func (h *Handler) uniqueAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	result := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if _, exists := seen[a]; !exists {
			seen[a] = struct{}{}
			result = append(result, a)
		}
	}
	return result
}

// buildReplacedResponse 构建替换后的响应
func (h *Handler) buildReplacedResponse(req *dns.Msg, original *dns.Msg, addrs []netip.Addr, qtype uint16) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = original.Authoritative
	resp.RecursionAvailable = original.RecursionAvailable
	resp.Rcode = original.Rcode

	// 保留非A/AAAA记录
	for _, ans := range original.Answer {
		if ans.Header().Rrtype != dns.TypeA && ans.Header().Rrtype != dns.TypeAAAA {
			resp.Answer = append(resp.Answer, ans)
		}
	}

	// 添加替换记录
	for _, ip := range addrs {
		if (qtype == dns.TypeA && ip.Is4()) || (qtype == dns.TypeAAAA && ip.Is6()) {
			hdr := dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: qtype,
				Class:  dns.ClassINET,
				Ttl:    300,
			}
			if ip.Is4() {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: hdr,
					A:   net.ParseIP(ip.String()),
				})
			} else {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  hdr,
					AAAA: net.ParseIP(ip.String()),
				})
			}
		}
	}
	return resp
}

// resolveViaDesignatedDNS 通过指定DNS解析
func (h *Handler) resolveViaDesignatedDNS(req *dns.Msg, dnsServer string) (*dns.Msg, error) {
	// 根据服务器地址判断协议类型
	network, timeout := h.getNetworkAndTimeout(dnsServer)
	c := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}

	resp, _, err := c.Exchange(req, dnsServer)
	if err != nil {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "designated DNS query failed", err)
	}
	return resp, nil
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

// handleReplacement 处理命中IP替换
func (h *Handler) handleReplacement(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg, qtype uint16, domain string, ip netip.Addr, iptype int) {
	var replaceDomain string

	switch iptype {
	case CFType:
		replaceDomain = h.config.ReplaceCFDomain
	case AWSType:
		replaceDomain = h.config.ReplaceAWSDomain
	}

	replaceAddrs := h.resolveReplaceCNAME(replaceDomain)

	// 新增：收集原始IP
	var originalIPs []string
	if resp != nil {
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				originalIPs = append(originalIPs, v.A.String())
			case *dns.AAAA:
				originalIPs = append(originalIPs, v.AAAA.String())
			}
		}
	}

	if len(replaceAddrs) > 0 {
		newResp := h.buildReplacedResponse(req, resp, replaceAddrs, qtype)
		h.logger.Info("【Cloudflare命中】%s，原IP: %v，替换为: %v", domain, originalIPs, replaceAddrs)
		h.metrics.GetReplacedCount().Inc()
		// 设置缓存 - 缓存替换后的响应
		h.setCachedResponse(req, newResp)
		if err := w.WriteMsg(newResp); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
		h.logger.Debug("handleReplacement matched: %s -> %v", domain, originalIPs)
	} else {
		// 设置缓存 - 缓存原始响应
		h.setCachedResponse(req, resp)
		if err := w.WriteMsg(resp); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
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

// 判断是否为Cloudflare域名
func (h *Handler) isCloudflareDomain(domain string) bool {
	return strings.HasSuffix(domain, ".cloudflare.com") || strings.HasSuffix(domain, ".cf.cloudflare.com")
}

// 判断是否为AWS域名
func (h *Handler) isAWSDomain(domain string) bool {
	return strings.HasSuffix(domain, ".amazonaws.com") || strings.HasSuffix(domain, ".cloudfront.net")
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

		// 0 首先检查缓存 - 缓存命中直接返回
		if cachedResp, hit := h.getCachedResponse(req); hit {
			if err := w.WriteMsg(cachedResp); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "cached").Inc()
			return
		}

		// 1 白名单优先（已注释）
		// if h.isWhitelisted(domain) {
		// 	isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
		// 	var upstream []string
		// 	if isCN {
		// 		upstream = cfg.CNUpstream
		// 		h.logger.Info("【白名单命中-国内】%s，走国内上游", domain)
		// 	} else {
		// 		upstream = cfg.NotCNUpstream
		// 		h.logger.Info("【白名单命中-国外】%s，走国外上游", domain)
		// 	}
		// 	resp, err := h.proxyQuery(req, upstream)
		// 	if err != nil || resp == nil {
		// 		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
		// 		if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
		// 			h.logger.Error("WriteMsg失败: %v", err)
		// 		}
		// 		return
		// 	}
		// 	// 设置缓存
		// 	h.setCachedResponse(req, resp)
		// 	if err := w.WriteMsg(resp); err != nil {
		// 		h.logger.Error("WriteMsg失败: %v", err)
		// 	}
		// 	h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "whitelist").Inc()
		// 	return
		// }

		// 2. 定向域名优先
		if rule, matched := h.matchDesignatedDomain(domain); matched {
			h.logger.Info("【定向域名命中】%s，使用指定DNS: %s", domain, rule.DNS)
			h.metrics.GetDesignatedHits().Inc()
			h.handleSpecialQuery(w, req, q, rule)
			return
		}

		//3. 先用所有上游查IP，判断是否命中cf/aws网段
		allUpstreams := append(cfg.CNUpstream, cfg.NotCNUpstream...)
		resp, err := h.proxyQuery(req, allUpstreams)
		if err != nil || resp == nil {
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
			if err := w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)); err != nil {
				h.logger.Error("WriteMsg失败: %v", err)
			}
			return
		}
		switch {
		case h.isCloudResponse(resp, CFType):
			h.logger.Info("【Cloudflare IP命中】%s，优选节点替换", domain)
			h.handleReplacement(w, req, resp, qtype, domain, netip.Addr{}, CFType)
			return
		case h.isCloudResponse(resp, AWSType):
			h.logger.Info("【AWS IP命中】%s，优选节点替换", domain)
			h.handleReplacement(w, req, resp, qtype, domain, netip.Addr{}, AWSType)
			return
		}

		//4 geosite国内外分流
		isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
		var upstream []string
		if isCN {
			upstream = cfg.CNUpstream
			h.logger.Debug("使用国内DNS解析: %s", domain)
		} else {
			upstream = cfg.NotCNUpstream
			h.logger.Debug("使用国外DNS解析: %s", domain)
		}
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

// shouldLogCacheStats 判断是否应该输出缓存统计
func (h *Handler) shouldLogCacheStats() bool {
	// 每1000询输出一次统计
	h.Lock()
	defer h.Unlock()

	// 使用简单的计数器
	if h.cacheStatsCounter == 0 {
		h.cacheStatsCounter = 1000
	}
	h.cacheStatsCounter--

	return h.cacheStatsCounter == 0
}

// logCacheStats 输出缓存统计信息
func (h *Handler) logCacheStats() {
	if h.cache == nil {
		return
	}
	// 获取缓存指标
	metrics := h.cache.Metrics
	if metrics == nil {
		return
	}
	// 正确访问Hits和Misses方法，KeysEvicted和SetsRejected方法
	h.logger.Info("【缓存统计】命中率: %0.2f%%, 驱逐: %d, 拒绝: %d",
		float64(metrics.Hits())/float64(metrics.Hits()+metrics.Misses())*100,
		metrics.KeysEvicted(),
		metrics.SetsRejected())
}

// 新增：判断上游是否为国内分流
func (h *Handler) isCNUpstream(server string) bool {
	for _, s := range h.config.CNUpstream {
		if s == server {
			return true
		}
	}
	return false
}
