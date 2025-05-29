package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// 常量定义
const (
	defaultConfigPath      = "config.yaml"
	defaultCFCacheTime     = "1h"
	defaultReplaceCacheTTL = "30m"
	defaultLogLevel        = "info"
	defaultMetricsPort     = 0
)

// Config 配置结构体
type Config struct {
	ListenPort       int      `yaml:"listen_port"`
	Upstream         []string `yaml:"upstream"`
	CFMrsURL4        string   `yaml:"cf_mrs_url4"`
	CFMrsURL6        string   `yaml:"cf_mrs_url6"`
	CFMrsCache       string   `yaml:"cf_mrs_cache"`
	ReplaceDomain    string   `yaml:"replace_domain"`
	CFCacheTime      string   `yaml:"cf_cache_time"`
	ReplaceCacheTime string   `yaml:"replace_cache_time"`
	WhitelistFile    string   `yaml:"whitelist_file"`
	DesignatedDomain string   `yaml:"designated_domain"`
	LogLevel         string   `yaml:"log_level"`
	MetricsPort      int      `yaml:"metrics_port"`
}

// DesignatedDomain 定向域名配置
type DesignatedDomain struct {
	Domain string `yaml:"domain"`
	DNS    string `yaml:"dns"`
	Regex  *regexp.Regexp
}

// DNSError 自定义错误类型
type DNSError struct {
	Code    int
	Message string
	Err     error
}

func (e *DNSError) Error() string {
	return fmt.Sprintf("DNS error %d: %s (%v)", e.Code, e.Message, e.Err)
}

// Logger 日志记录器
type Logger struct {
	level string
}

func (l *Logger) Debug(format string, v ...interface{}) {
	if l.level == "debug" {
		log.Printf("[DEBUG] "+format, v...)
	}
}

func (l *Logger) Info(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func (l *Logger) Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

func (l *Logger) Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

// CacheItem 缓存项
type CacheItem struct {
	value interface{}
	time  time.Time
}

// SizedCache 带大小限制的缓存
type SizedCache struct {
	sync.RWMutex
	items   map[string]CacheItem
	maxSize int
	ttl     time.Duration
	keys    []string // LRU队列
}

func NewSizedCache(maxSize int, ttl time.Duration) *SizedCache {
	return &SizedCache{
		items:   make(map[string]CacheItem),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

func (c *SizedCache) Get(key string) (interface{}, bool) {
	c.RLock()
	defer c.RUnlock()

	item, ok := c.items[key]
	if !ok {
		return nil, false
	}

	if time.Since(item.time) > c.ttl {
		delete(c.items, key)
		return nil, false
	}

	return item.value, true
}

func (c *SizedCache) Set(key string, value interface{}) {
	c.Lock()
	defer c.Unlock()

	// 清理过期项
	for k, item := range c.items {
		if time.Since(item.time) > c.ttl {
			delete(c.items, k)
		}
	}

	// 如果达到最大大小，移除最旧项
	if len(c.keys) >= c.maxSize {
		oldest := c.keys[0]
		delete(c.items, oldest)
		c.keys = c.keys[1:]
	}

	c.items[key] = CacheItem{
		value: value,
		time:  time.Now(),
	}
	c.keys = append(c.keys, key)
}

// DNSHandler DNS请求处理器
type DNSHandler struct {
	config           *Config
	logger           *Logger
	metrics          *MetricsCollector
	cache            *SizedCache
	cfNetSet4        *netipx
	cfNetSet6        *netipx
	whitelistPattern []string
	designatedRules  []DesignatedDomain
	lastCFUpdate     time.Time
	cfExpire         time.Duration
	replaceExpire    time.Duration
	sync.RWMutex
}

// MetricsCollector 指标收集器
type MetricsCollector struct {
	queriesTotal    *prometheus.CounterVec
	whitelistHits   prometheus.Counter
	designatedHits  prometheus.Counter
	replacedCount   prometheus.Counter
	upstreamLatency prometheus.Histogram
	responseLatency prometheus.Histogram
	cacheHits       *prometheus.CounterVec
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		queriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dns_queries_total",
				Help: "Total DNS queries processed",
			},
			[]string{"type", "status"},
		),
		whitelistHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "whitelist_hits_total",
				Help: "Total whitelist hits",
			},
		),
		designatedHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "designated_hits_total",
				Help: "Total designated hits",
			},
		),
		replacedCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "replaced_records_total",
				Help: "Total records replaced",
			},
		),
		upstreamLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "upstream_query_latency_seconds",
				Help:    "Latency of upstream DNS queries",
				Buckets: []float64{0.1, 0.5, 1, 2, 5},
			},
		),
		responseLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "dns_response_latency_seconds",
				Help:    "Latency of DNS responses",
				Buckets: []float64{0.1, 0.5, 1, 2, 5},
			},
		),
		cacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "Total cache hits",
			},
			[]string{"type"},
		),
	}
}

// netipx IP前缀集合
type netipx struct {
	sync.RWMutex
	list []netip.Prefix
}

func (n *netipx) Contains(ip netip.Addr) bool {
	n.RLock()
	defer n.RUnlock()
	for _, p := range n.list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (n *netipx) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var prefixes []netip.Prefix
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err == nil {
			prefixes = append(prefixes, p)
		}
	}

	n.Lock()
	n.list = prefixes
	n.Unlock()
	return nil
}

// loadConfig 加载配置文件
func loadConfig(path string) (*Config, error) {
	cfgData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(cfgData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// 设置默认值
	if config.CFCacheTime == "" {
		config.CFCacheTime = defaultCFCacheTime
	}
	if config.ReplaceCacheTime == "" {
		config.ReplaceCacheTime = defaultReplaceCacheTTL
	}
	if config.LogLevel == "" {
		config.LogLevel = defaultLogLevel
	}
	if config.MetricsPort == 0 {
		config.MetricsPort = defaultMetricsPort
	}

	return &config, nil
}

// validateConfig 验证配置
func validateConfig(cfg *Config) error {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", cfg.ListenPort)
	}
	if len(cfg.Upstream) == 0 {
		return fmt.Errorf("no upstream servers configured")
	}
	if cfg.ReplaceDomain == "" {
		return fmt.Errorf("replace_domain must be set")
	}
	if cfg.CFMrsURL4 == "" || cfg.CFMrsURL6 == "" {
		return fmt.Errorf("Cloudflare IP ranges URLs must be configured")
	}
	return nil
}

// NewDNSHandler 创建DNS处理器
func NewDNSHandler(cfg *Config) *DNSHandler {
	cfExpire, err := time.ParseDuration(cfg.CFCacheTime)
	if err != nil {
		log.Fatalf("Invalid CF cache time: %v", err)
	}

	replaceExpire, err := time.ParseDuration(cfg.ReplaceCacheTime)
	if err != nil {
		log.Fatalf("Invalid replace cache time: %v", err)
	}

	handler := &DNSHandler{
		config:        cfg,
		logger:        &Logger{level: cfg.LogLevel},
		metrics:       NewMetricsCollector(),
		cache:         NewSizedCache(1000, replaceExpire),
		cfNetSet4:     &netipx{},
		cfNetSet6:     &netipx{},
		cfExpire:      cfExpire,
		replaceExpire: replaceExpire,
	}

	// 注册Prometheus指标
	prometheus.MustRegister(handler.metrics.queriesTotal)
	prometheus.MustRegister(handler.metrics.whitelistHits)
	prometheus.MustRegister(handler.metrics.designatedHits)
	prometheus.MustRegister(handler.metrics.replacedCount)
	prometheus.MustRegister(handler.metrics.upstreamLatency)
	prometheus.MustRegister(handler.metrics.responseLatency)
	prometheus.MustRegister(handler.metrics.cacheHits)

	// 初始化加载数据
	handler.loadWhitelist()
	handler.loadDesignatedDomains()
	handler.updateCloudflareNetworks()

	// 启动后台更新任务
	go handler.runBackgroundTasks()

	return handler
}

// loadWhitelist 加载白名单
func (h *DNSHandler) loadWhitelist() {
	if h.config.WhitelistFile == "" {
		h.logger.Warn("Whitelist file not configured")
		return
	}

	// 尝试创建文件（如果不存在）
	if _, err := os.Stat(h.config.WhitelistFile); os.IsNotExist(err) {
		h.logger.Warn("Whitelist file does not exist, creating: %s", h.config.WhitelistFile)
		if err := os.WriteFile(h.config.WhitelistFile, []byte("# Whitelist domains\nexample.com\n"), 0644); err != nil {
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
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	h.Lock()
	h.whitelistPattern = patterns
	h.Unlock()
	h.logger.Info("Whitelist loaded: %d entries", len(patterns))
}

// loadDesignatedDomains 加载定向域名规则
func (h *DNSHandler) loadDesignatedDomains() {
	if h.config.DesignatedDomain == "" {
		h.logger.Warn("Designated domains file not configured")
		return
	}

	if _, err := os.Stat(h.config.DesignatedDomain); os.IsNotExist(err) {
		h.logger.Warn("Designated domains file does not exist, creating: %s", h.config.DesignatedDomain)
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

	var rules []DesignatedDomain
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
		// 转换为正则表达式
		regexPattern := "^" + regexp.QuoteMeta(rawPattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			h.logger.Warn("Invalid regex for pattern: %s (%v)", rawPattern, err)
			continue
		}

		rules = append(rules, DesignatedDomain{
			Domain: rawPattern,
			DNS:    parts[1],
			Regex:  re,
		})
	}

	h.Lock()
	h.designatedRules = rules
	h.Unlock()
	h.logger.Info("Designated domains loaded: %d entries", len(rules))
}

// downloadToFile 下载文件
func (h *DNSHandler) downloadToFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// updateCloudflareNetworks 更新Cloudflare网络列表
func (h *DNSHandler) updateCloudflareNetworks() {
	h.Lock()
	defer h.Unlock()

	if time.Since(h.lastCFUpdate) < h.cfExpire {
		return
	}

	h.logger.Info("Updating Cloudflare IP ranges...")

	cfCachePath4 := "./cloudflare-v4.txt"
	cfCachePath6 := "./cloudflare-v6.txt"

	// 原子下载模式
	download := func(url, path string) bool {
		tmpPath := path + ".tmp"
		if err := h.downloadToFile(url, tmpPath); err != nil {
			h.logger.Warn("Download failed %s: %v", url, err)
			return false
		}
		if err := os.Rename(tmpPath, path); err != nil {
			h.logger.Warn("File replace failed %s: %v", path, err)
			return false
		}
		return true
	}

	// 并行下载
	var wg sync.WaitGroup
	success4, success6 := false, false

	wg.Add(1)
	go func() {
		defer wg.Done()
		success4 = download(h.config.CFMrsURL4, cfCachePath4)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		success6 = download(h.config.CFMrsURL6, cfCachePath6)
	}()
	wg.Wait()

	// 加载成功的数据
	if success4 {
		if err := h.cfNetSet4.LoadFromFile(cfCachePath4); err != nil {
			h.logger.Error("Failed to load IPv4 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv4 prefixes", len(h.cfNetSet4.list))
		}
	}

	if success6 {
		if err := h.cfNetSet6.LoadFromFile(cfCachePath6); err != nil {
			h.logger.Error("Failed to load IPv6 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv6 prefixes", len(h.cfNetSet6.list))
		}
	}

	h.lastCFUpdate = time.Now()
}

// runBackgroundTasks 运行后台任务
func (h *DNSHandler) runBackgroundTasks() {
	// 定时更新Cloudflare网络列表
	cfTicker := time.NewTicker(5 * time.Minute)
	defer cfTicker.Stop()

	// 定时重新加载白名单和定向域名
	reloadTicker := time.NewTicker(1 * time.Minute)
	defer reloadTicker.Stop()

	for {
		select {
		case <-cfTicker.C:
			h.updateCloudflareNetworks()
		case <-reloadTicker.C:
			h.loadWhitelist()
			h.loadDesignatedDomains()
		}
	}
}

// isWhitelisted 检查域名是否在白名单中
func (h *DNSHandler) isWhitelisted(qname string) bool {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, pattern := range h.whitelistPattern {
		pattern = strings.ToLower(pattern)

		// 精确匹配
		if pattern == domain {
			return true
		}

		// 通配符 *.example.com
		if strings.HasPrefix(pattern, "*.") {
			if strings.HasSuffix(domain, pattern[1:]) || domain == pattern[2:] {
				return true
			}
		}

		// 复杂通配符 *aa11*
		if strings.Contains(pattern, "*") {
			regexPattern := "^" + strings.ReplaceAll(pattern, ".", `\.`) + "$"
			regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
			if matched, _ := regexp.MatchString(regexPattern, domain); matched {
				return true
			}
		}
	}
	return false
}

// matchDesignatedDomain 匹配定向域名
func (h *DNSHandler) matchDesignatedDomain(qname string) (DesignatedDomain, bool) {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, rule := range h.designatedRules {
		if rule.Regex.MatchString(domain) {
			h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
			return rule, true
		}
	}

	h.logger.Debug("Designated domain not found: %s", domain)
	return DesignatedDomain{}, false
}

// isCloudflareResponse 检查响应是否来自Cloudflare
func (h *DNSHandler) isCloudflareResponse(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if ip, err := netip.ParseAddr(v.A.String()); err == nil && h.cfNetSet4.Contains(ip) {
				h.logger.Debug("IP %s is in Cloudflare IPv4 range", ip)
				return true
			}
		case *dns.AAAA:
			if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && h.cfNetSet6.Contains(ip) {
				h.logger.Debug("IP %s is in Cloudflare IPv6 range", ip)
				return true
			}
		}
	}
	return false
}

// resolveReplaceCNAME 解析替换CNAME
func (h *DNSHandler) resolveReplaceCNAME(cname string) []netip.Addr {
	// 检查缓存
	if val, ok := h.cache.Get(cname); ok {
		h.metrics.cacheHits.WithLabelValues("replace").Inc()
		return val.([]netip.Addr)
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
		for _, server := range h.config.Upstream {
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
				m.SetQuestion(cname, qtype) // 仍可能panic，加了recover保护
				c := new(dns.Client)
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
		h.cache.Set(cname, addrs)
	} else {
		h.logger.Warn("No addresses found for %s", cname)
	}

	return addrs
}

// uniqueAddrs 去重IP地址
func (h *DNSHandler) uniqueAddrs(addrs []netip.Addr) []netip.Addr {
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
func (h *DNSHandler) buildReplacedResponse(req *dns.Msg, original *dns.Msg, addrs []netip.Addr, qtype uint16) *dns.Msg {
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
func (h *DNSHandler) resolveViaDesignatedDNS(req *dns.Msg, dnsServer string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	resp, _, err := c.Exchange(req, dnsServer)
	if err != nil {
		return nil, &DNSError{
			Code:    dns.RcodeServerFailure,
			Message: "designated DNS query failed",
			Err:     err,
		}
	}
	return resp, nil
}

// proxyQuery 代理查询
func (h *DNSHandler) proxyQuery(w dns.ResponseWriter, req *dns.Msg, upstream []string) (*dns.Msg, error) {
	for _, server := range upstream {
		c := &dns.Client{
			Timeout: 2 * time.Second,
			Net:     "udp",
		}
		start := time.Now()
		resp, _, err := c.Exchange(req, server)
		h.metrics.upstreamLatency.Observe(time.Since(start).Seconds())

		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return nil, &DNSError{
		Code:    dns.RcodeServerFailure,
		Message: "all upstream servers failed",
	}
}

// handleSpecialQuery 处理特殊查询
func (h *DNSHandler) handleSpecialQuery(rule DesignatedDomain, w dns.ResponseWriter, req *dns.Msg, q dns.Question) bool {
	domain := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	h.logger.Debug("matchDesignatedDomain: domain=%s matched=%v ruleDNS=%s", domain, rule.DNS)

	h.metrics.designatedHits.Inc()
	resp, err := h.resolveViaDesignatedDNS(req, rule.DNS)
	if err != nil {
		h.logger.Error("Designated query failed for %s via %s: %v", domain, rule.DNS, err)
		h.handleNormalQueryFallback(w, req, q)
		return true
	}

	if resp == nil {
		h.logger.Warn("Designated query returned nil response for %s via %s", domain, rule.DNS)
		h.handleNormalQueryFallback(w, req, q)
		return true
	}

	h.logger.Debug("Designated query success for %s via %s", domain, rule.DNS)
	_ = w.WriteMsg(resp)
	return true
}

// handleWhitelistedQuery 处理白名单查询
func (h *DNSHandler) handleWhitelistedQuery(w dns.ResponseWriter, req *dns.Msg) {
	h.metrics.whitelistHits.Inc()
	resp, err := h.proxyQuery(w, req, h.config.Upstream)
	if err != nil {
		h.logger.Error("Failed to proxy whitelisted query: %v", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
		return
	}
	_ = w.WriteMsg(resp)
}

// handleNormalQuery 处理普通查询
func (h *DNSHandler) handleNormalQuery(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	start := time.Now()
	defer func() {
		h.metrics.responseLatency.Observe(time.Since(start).Seconds())
	}()

	domain := sanitizeDomainName(q.Name)
	qtype := q.Qtype

	h.logger.Debug("Processing query for %s (type %d)", domain, qtype)
	h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[qtype], "received").Inc()

	// 上游查询
	resp, err := h.proxyQuery(w, req, h.config.Upstream)
	if err != nil || resp == nil {
		h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
		return
	}

	// Cloudflare检测和替换
	if h.isCloudflareResponse(resp) {
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if ip, err := netip.ParseAddr(v.A.String()); err == nil && h.cfNetSet4.Contains(ip) {
					h.handleCFReplacement(w, req, resp, qtype, domain, ip)
					return
				}
			case *dns.AAAA:
				if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && h.cfNetSet6.Contains(ip) {
					h.handleCFReplacement(w, req, resp, qtype, domain, ip)
					return
				}
			}
		}
	}

	// 默认返回
	_ = w.WriteMsg(resp)
	h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
}

// handleCFReplacement 处理Cloudflare替换
func (h *DNSHandler) handleCFReplacement(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg, qtype uint16, domain string, ip netip.Addr) {
	replaceAddrs := h.resolveReplaceCNAME(h.config.ReplaceDomain)
	if len(replaceAddrs) > 0 {
		newResp := h.buildReplacedResponse(req, resp, replaceAddrs, qtype)
		h.logger.Debug("Replaced CNAME: %s -> %v", domain, replaceAddrs)
		h.metrics.replacedCount.Inc()
		_ = w.WriteMsg(newResp)
		h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
		h.logger.Debug("Cloudflare network matched: %s -> %s", domain, ip)
	} else {
		_ = w.WriteMsg(resp)
		h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
	}
}

// handleNormalQueryFallback 普通查询回退处理
func (h *DNSHandler) handleNormalQueryFallback(w dns.ResponseWriter, req *dns.Msg, q dns.Question) {
	resp, err := h.proxyQuery(w, req, h.config.Upstream)
	if err != nil {
		h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[q.Qtype], "failed").Inc()
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
		return
	}
	_ = w.WriteMsg(resp)
	h.metrics.queriesTotal.WithLabelValues(dns.TypeToString[q.Qtype], "passed").Inc()
}

// sanitizeDomainName 清理域名
func sanitizeDomainName(name string) string {
	if idx := strings.Index(name, `\`); idx != -1 {
		return name[:idx]
	}
	return name
}

// recoverPanic 恢复panic
func recoverPanic(w dns.ResponseWriter, req *dns.Msg) {
	if err := recover(); err != nil {
		log.Printf("[PANIC] Recovered from panic: %v", err)
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeServerFailure))
	}
}

// ServeDNS 实现dns.Handler接口
func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	defer recoverPanic(w, req)

	for _, q := range req.Question {
		qtype := q.Qtype
		if qtype != dns.TypeA && qtype != dns.TypeAAAA {
			continue
		}
		_, ok := dns.IsDomainName(q.Name)
		if !ok {
			h.logger.Info("请求查询的是非法域名: %s", q.Name)
			continue
		}
		rule, matched := h.matchDesignatedDomain(q.Name)
		switch {
		case h.isWhitelisted(q.Name):
			h.handleWhitelistedQuery(w, req)
			return
		case matched:
			h.handleSpecialQuery(rule, w, req, q)
			return
		default:
			h.handleNormalQuery(w, req, q)
			return
		}
	}
}

// startMetricsServer 启动指标服务器
func startMetricsServer(port int) {
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting metrics server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Metrics server failed: %v", err)
	}
}

// main 主函数
func main() {
	configPath := flag.String("c", defaultConfigPath, "Path to config file")
	flag.Parse()

	// 加载和验证配置
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := validateConfig(config); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// 初始化DNS处理器
	handler := NewDNSHandler(config)

	// 启动指标服务器
	if config.MetricsPort > 0 {
		go startMetricsServer(config.MetricsPort)
	}

	// 启动DNS服务器
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", config.ListenPort),
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}

	log.Printf("Starting DNS server on :%d", config.ListenPort)
	log.Printf("Using upstreams: %v", config.Upstream)
	log.Printf("Whitelist file: %s", config.WhitelistFile)
	log.Printf("DesignatedDomain file: %s", config.DesignatedDomain)
	log.Printf("Replace CNAME: %s", config.ReplaceDomain)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
