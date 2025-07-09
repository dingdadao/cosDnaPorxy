package dns

import (
	"bufio"
	"context"
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/geosite"
	"cosDnaPorxy/internal/metrics"
	"cosDnaPorxy/internal/utils"
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
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// Handler DNS请求处理器
type Handler struct {
	config           *config.Config
	logger           *utils.Logger
	geositeManager   *geosite.Manager
	metrics          *metrics.Collector
	cache            *ristretto.Cache
	cfNetSet4        *NetIPX
	cfNetSet6        *NetIPX
	aWSNetSet4       *NetIPX
	aWSNetSet6       *NetIPX
	whitelistPattern []string
	designatedRules  []DesignatedDomain
	lastCFUpdate     time.Time
	cfExpire         time.Duration
	replaceExpire    time.Duration
	serverHealth     map[string]*ServerHealth
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

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 10_000,
		MaxCost:     1 << 20,
		BufferItems: 64,
	})
	if err != nil {
		log.Fatalf("Failed to create cache: %v", err)
	}

	handler := &Handler{
		config:        cfg,
		logger:        utils.NewLogger(cfg.LogLevel),
		metrics:       metrics.NewCollector(),
		cache:         cache,
		cfNetSet4:     &NetIPX{},
		cfNetSet6:     &NetIPX{},
		aWSNetSet4:    &NetIPX{},
		aWSNetSet6:    &NetIPX{},
		cfExpire:      cfExpire,
		replaceExpire: replaceExpire,
		serverHealth:  make(map[string]*ServerHealth),
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

		// 将通配符 *.example.com 转换为正则表达式
		regexPattern := "^" + regexp.QuoteMeta(rawPattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			h.logger.Warn("Invalid regex for pattern: %s (%v)", rawPattern, err)
			continue
		}

		newRules = append(newRules, DesignatedDomain{
			Domain: rawPattern,
			DNS:    parts[1],
			Regex:  re,
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
			h.loadWhitelist()
			h.loadDesignatedDomains()
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
		pattern := strings.ToLower(rule.Domain)
		if utils.MatchDomain(pattern, domain) {
			h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
			return &rule, true
		}
	}
	return nil, false
}

// checkServerHealth 检查DNS服务器健康状态
func (h *Handler) checkServerHealth(server string) bool {
	h.RLock()
	health, exists := h.serverHealth[server]
	h.RUnlock()
	
	if !exists {
		health = &ServerHealth{}
		h.Lock()
		h.serverHealth[server] = health
		h.Unlock()
	}
	
	health.Lock()
	defer health.Unlock()
	
	// 如果最近检查过且健康，直接返回
	if time.Since(health.LastCheck) < 30*time.Second && health.IsHealthy {
		return true
	}
	
	// 执行健康检查
	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)
	
	var c *dns.Client
	var resp *dns.Msg
	var err error
	
	start := time.Now()
	
	// 根据服务器地址判断协议类型
	network, timeout := h.getNetworkAndTimeout(server)
	serverAddr := h.getServerAddress(server)
	
	// 对于DoH协议，使用DoH健康检查
	if strings.HasPrefix(server, "https://") {
		resp, err = h.queryDoH(req, server, h.isCNUpstream(server))
	} else {
		c = &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		
		resp, _, err = c.Exchange(req, serverAddr)
	}
	
	latency := time.Since(start)
	
	health.LastCheck = time.Now()
	health.Latency = latency
	
	if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
		health.IsHealthy = true
		health.SuccessCount++
		health.FailureCount = 0
		h.logger.Debug("DNS服务器健康检查通过: %s (延迟: %v)", server, latency)
		return true
	} else {
		health.IsHealthy = false
		health.FailureCount++
		h.logger.Warn("DNS服务器健康检查失败: %s (错误: %v)", server, err)
		return false
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
		h.logger.Warn("无法解析DoH域名 %s: %v", host, err)
		return nil, err
	}

	dnsQuery, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	httpReq, err := http.NewRequest("POST", dohURL, strings.NewReader(string(dnsQuery)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "cosDnaPorxy/1.0")

	timeout, err := time.ParseDuration(dohConf.Timeout)
	if err != nil {
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if strings.Contains(addr, host) {
					addr = strings.Replace(addr, host, resolverIP, 1)
				}
				return net.Dial(network, addr)
			},
		},
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
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
	
	// 根据服务器地址判断协议类型
	network, timeout := h.getNetworkAndTimeout(server)
	serverAddr := h.getServerAddress(server)
	
	// 对于DoH协议，使用DoH查询，isCN由上游分流决定
	isCN := h.isCNUpstream(server)
	if strings.HasPrefix(server, "https://") {
		resp, err = h.queryDoH(req, server, isCN)
	} else {
		c = &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		
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
		// DoH (DNS over HTTPS) - 需要特殊处理
		return "https", 5 * time.Second
	case strings.HasPrefix(server, "tls://"):
		// DoT (DNS over TLS)
		return "tcp-tls", 4 * time.Second
	case strings.HasPrefix(server, "tcp://"):
		// TCP DNS
		return "tcp", 3 * time.Second
	case strings.HasPrefix(server, "udp://"):
		// UDP DNS (显式指定)
		return "udp", 3 * time.Second
	default:
		// 默认UDP DNS
		return "udp", 3 * time.Second
	}
}

// getServerAddress 获取服务器地址（去除协议前缀）
func (h *Handler) getServerAddress(server string) string {
	switch {
	case strings.HasPrefix(server, "https://"):
		// DoH地址保持不变
		return server
	case strings.HasPrefix(server, "tls://"):
		// 移除tls://前缀
		return strings.TrimPrefix(server, "tls://")
	case strings.HasPrefix(server, "tcp://"):
		// 移除tcp://前缀
		return strings.TrimPrefix(server, "tcp://")
	case strings.HasPrefix(server, "udp://"):
		// 移除udp://前缀
		return strings.TrimPrefix(server, "udp://")
	default:
		// 默认地址保持不变
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

// proxyQuery 代理查询 - 优化版本
func (h *Handler) proxyQuery(req *dns.Msg, upstream []string) (*dns.Msg, error) {
	if len(upstream) == 0 {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "no upstream servers configured", nil)
	}

	// 获取健康的服务器列表
	healthyServers := h.getHealthyServers(upstream)
	
	// 如果只有一个上游服务器，直接使用
	if len(healthyServers) == 1 {
		return h.querySingleServer(req, healthyServers[0])
	}

	// 多个服务器时，使用并发查询选择最快的响应
	return h.queryMultipleServers(req, healthyServers)
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
	// 检查缓存
	if val, ok := h.cache.Get(cname); ok {
		if addrs, ok := val.([]netip.Addr); ok {
			h.metrics.GetCacheHits().WithLabelValues("replace").Inc()
			return addrs
		}
	}

	// 域名前处理：空值、无效跳过
	cname = strings.TrimSpace(cname)
	if cname == "" {
		h.logger.Info("优选域名不能为空，需要检查")
		return nil
	}
	_, ok := dns.IsDomainName(cname)
	if !ok {
		// 处理非法域名
		h.logger.Info("不是一个合法域名: %s", cname)
		return nil
	}
	cname = dns.Fqdn(cname) // 确保结尾带 "."

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var mu sync.Mutex
	var addrs []netip.Addr
	var wg sync.WaitGroup

	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	for _, qtype := range queryTypes {
		for _, server := range h.config.CNUpstream {
			wg.Add(1)
			go func(server string, qtype uint16) {
				defer wg.Done()

				// 加 recover 防止 panic 让服务挂掉
				defer func() {
					if r := recover(); r != nil {
						h.logger.Warn("panic recovered in resolveReplaceCNAME: %v\n%s", r, debug.Stack())
					}
				}()

				m := new(dns.Msg)
				m.SetQuestion(cname, qtype)
				
				// 根据服务器地址判断协议类型
				network, timeout := h.getNetworkAndTimeout(server)
				c := &dns.Client{
					Timeout: timeout,
					Net:     network,
				}
				resp, _, err := c.ExchangeContext(ctx, m, server)
				if err != nil || resp == nil || len(resp.Answer) == 0 {
					h.logger.Warn("Query failed for %s (type %d): %v", cname, qtype, err)
					return
				}

				mu.Lock()
				defer mu.Unlock()
				for _, a := range resp.Answer {
					switch rr := a.(type) {
					case *dns.A:
						if ip, err := netip.ParseAddr(rr.A.String()); err == nil {
							addrs = append(addrs, ip)
						}
					case *dns.AAAA:
						if ip, err := netip.ParseAddr(rr.AAAA.String()); err == nil {
							addrs = append(addrs, ip)
						}
					}
				}
			}(server, qtype)
		}
	}
	wg.Wait()

	addrs = h.uniqueAddrs(addrs)
	if len(addrs) > 0 {
		// 写入缓存，cost 简单用 1，TTL 使用 replaceExpire 配置
		ok := h.cache.SetWithTTL(cname, addrs, 1, h.replaceExpire)
		if !ok {
			h.logger.Warn("Failed to set cache for %s", cname)
		}
	} else {
		h.logger.Warn("No addresses found for %s", cname)
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

	resp, err := h.resolveViaDesignatedDNS(req, rule.DNS)
	if err != nil || resp == nil {
		h.logger.Error("Designated query failed for %s via %s: %v", domain, rule.DNS, err)
		h.handleNormalQueryFallback(w, req, q)
		return
	}

	h.logger.Debug("designated query success: domain=%s dns=%s", domain, rule.DNS)
	_ = w.WriteMsg(resp)
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
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
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
	_ = w.WriteMsg(resp)
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

	if len(replaceAddrs) > 0 {
		newResp := h.buildReplacedResponse(req, resp, replaceAddrs, qtype)
		h.logger.Debug("Replaced CNAME: %s -> %v", domain, replaceAddrs)
		h.metrics.GetReplacedCount().Inc()
		_ = w.WriteMsg(newResp)
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
		h.logger.Debug("handleReplacement matched: %s -> %s", domain, ip)
	} else {
		_ = w.WriteMsg(resp)
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
	}
}

// handleNormalQueryFallback 普通查询回退处理
func (h *Handler) handleNormalQueryFallback(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp, err := h.proxyQuery(req, h.config.CNUpstream)
	if err != nil {
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[q.Qtype], "failed").Inc()
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
		return
	}
	_ = w.WriteMsg(resp)
	h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[q.Qtype], "passed").Inc()
}

// recoverPanic 恢复panic
func recoverPanic(w dns.ResponseWriter, req *dns.Msg) {
	if err := recover(); err != nil {
		log.Printf("[PANIC] Recovered from panic: %v", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
	}
}

// ServeDNS 实现dns.Handler接口
func (h *Handler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer recoverPanic(w, req)

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

		// 1. 首先检查白名单 - 最高优先级
		if h.isWhitelisted(domain) {
			h.logger.Debug("域名在白名单中: %s", domain)
			resp, err := h.proxyQuery(req, cfg.CNUpstream)
			if err != nil || resp == nil {
				h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
				_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
				return
			}
			_ = w.WriteMsg(resp)
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "whitelist").Inc()
			return
		}

		// 2. 检查定向域名 - 次高优先级
		if rule, matched := h.matchDesignatedDomain(domain); matched {
			h.logger.Debug("匹配定向域名: %s -> %s", domain, rule.DNS)
			h.metrics.GetDesignatedHits().Inc()
			h.handleSpecialQuery(w, req, q, rule)
			return
		}

		// 3. 根据地理位置选择上游DNS
		isCN := h.geositeManager.CheckDomainInTag(domain, cfg.GeositeGroup)
		var upstream []string
		if isCN {
			upstream = cfg.CNUpstream
			h.logger.Debug("使用国内DNS解析: %s", domain)
		} else {
			upstream = cfg.NotCNUpstream
			h.logger.Debug("使用国外DNS解析: %s", domain)
		}

		// 4. 查询上游DNS
		resp, err := h.proxyQuery(req, upstream)
		if err != nil || resp == nil {
			h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
			_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
			return
		}

		// 5. 检查是否为云服务响应并处理替换
		switch {
		case h.isCloudResponse(resp, CFType):
			h.logger.Debug("检测到Cloudflare响应: %s", domain)
			h.handleQuery(w, req, q, CFType, upstream)
			return
		case h.isCloudResponse(resp, AWSType):
			h.logger.Debug("检测到AWS响应: %s", domain)
			h.handleQuery(w, req, q, AWSType, upstream)
			return
		default:
			// 6. 正常响应
			if err := w.WriteMsg(resp); err != nil {
				h.logger.Error("写入响应失败: %v", err)
				h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
				_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
			} else {
				h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
			}
		}
	}
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