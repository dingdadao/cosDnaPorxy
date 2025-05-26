package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// 常量定义
//const (
//	LOG_HIT_WHITELIST  = "[WHITELIST] Hit: %s"
//	LOG_HIT_CFNET      = "[CFNET] Cloudflare network matched: %s -> %s"
//	LOG_REPLACE_CNAME  = "[REPLACE] Replaced CNAME: %s -> %v"
//	LOG_UPSTREAM_QUERY = "[UPSTREAM] Query: %s (Type: %d)"
//)

// Config 配置结构体
type Config struct {
	ListenPort       int      `yaml:"listen_port"`
	Upstream         []string `yaml:"upstream"`
	CFMrsURL4        string   `yaml:"cf_mrs_url4"`
	CFMrsURL6        string   `yaml:"cf_mrs_url6"`
	CFMrsCache       string   `yaml:"cf_mrs_cache"`
	REplaceDomain    string   `yaml:"replace_domain"`
	CFCacheTime      string   `yaml:"cf_cache_time"`
	ReplaceCacheTime string   `yaml:"replace_cache_time"`
	WhitelistFile    string   `yaml:"whitelist_file"`
	DesignatedDomain string   `yaml:"designated_domain"`
	LogLevel         string   `yaml:"log_level"`
	MetricsPort      int      `yaml:"metrics_port"`
}

type DesignatedDomain struct {
	Domain string
	DNS    string
}

// 全局变量
var (
	cfLoadMutex       sync.Mutex
	cfNetSet4         = &netipx{}
	cfNetSet6         = &netipx{}
	cfLastLoaded      time.Time
	cfExpire          time.Duration
	replaceCache      = sync.Map{}
	replaceExpire     time.Duration
	config            Config
	designatedMutex   sync.RWMutex
	designatedDomains []DesignatedDomain

	// Prometheus指标
	queriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_queries_total",
			Help: "Total DNS queries processed",
		},
		[]string{"type", "status"},
	)
	whitelistHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "whitelist_hits_total",
			Help: "Total whitelist hits",
		},
	)
	designatedHits = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "designated_hits_total",
			Help: "Total designated hits",
		},
	)
	replacedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "replaced_records_total",
			Help: "Total records replaced",
		},
	)
)

func init() {
	prometheus.MustRegister(queriesTotal)
	prometheus.MustRegister(whitelistHits)
	prometheus.MustRegister(designatedHits)
	prometheus.MustRegister(replacedCount)
}

// netipx 结构体
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
	cfLastLoaded = time.Now()
	log.Printf("[INFO] Loaded %d Cloudflare prefixes from %s", len(prefixes), path)
	return nil
}

// 白名单相关
var (
	whitelistPatterns []string
	whitelistMutex    sync.RWMutex
)

func loadWhitelist(path string) {
	if path == "" {
		log.Printf("[WARN] 未配置白名单文件路径")
		return
	}

	// 尝试创建文件（如果不存在）
	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("[WARN] 白名单文件不存在，已自动创建: %s", path)
		if err := os.WriteFile(path, []byte("# 白名单域名列表\nexample.com\n"), 0644); err != nil {
			log.Printf("[ERROR] 创建白名单文件失败: %v", err)
			return
		}
	}
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[ERROR] Failed to open whitelist: %v", err)
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	scanner := bufio.NewScanner(f)
	var patterns []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	whitelistMutex.Lock()
	whitelistPatterns = patterns
	whitelistMutex.Unlock()
	log.Printf("[INFO] Whitelist loaded: %d entries", len(patterns))
}

func loadDesignatedDomains(path string) {
	if path == "" {
		log.Printf("[WARN] 未配置定向域名规则文件路径")
		return
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		log.Printf("[WARN] 定向域名规则文件不存在，已自动创建: %s", path)
		defaultContent := []byte("# 格式: 域名 DNS服务器\n*.example.com 8.8.8.8\n")
		if err := os.WriteFile(path, defaultContent, 0644); err != nil {
			log.Printf("[ERROR] 创建 designated 文件失败: %v", err)
			return
		}
	}

	f, err := os.Open(path)
	if err != nil {
		log.Printf("[ERROR] 打开 designated 文件失败: %v", err)
		return
	}
	defer func(f *os.File) {
		_ = f.Close()
	}(f)

	var rules []DesignatedDomain
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			log.Printf("[WARN] 格式不合法，跳过行: %s", line)
			continue
		}
		rules = append(rules, DesignatedDomain{
			Domain: parts[0],
			DNS:    parts[1],
		})
	}

	designatedMutex.Lock()
	designatedDomains = rules
	designatedMutex.Unlock()

	log.Printf("[INFO] Designated domains loaded: %d entries", len(rules))
}

// 指定域名走dns
func matchDesignatedDomain(qname string) (DesignatedDomain, bool) {
	// 去除末尾点，小写
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))

	designatedMutex.RLock()
	defer designatedMutex.RUnlock()

	for _, rule := range designatedDomains {
		pattern := strings.ToLower(rule.Domain)

		// 精确匹配
		if pattern == domain {
			return rule, true
		}

		// 前缀通配符 *.example.com
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:] // ".example.com"
			if strings.HasSuffix(domain, suffix) || domain == pattern[2:] {
				return rule, true
			}
		}

		// 全通配符 *abc*.xyz
		if strings.Contains(pattern, "*") {
			regexPattern := "^" + strings.ReplaceAll(pattern, ".", `\.`)
			regexPattern = strings.ReplaceAll(regexPattern, "*", ".*") + "$"
			if matched, _ := regexp.MatchString(regexPattern, domain); matched {
				return rule, true
			}
		}
	}
	return DesignatedDomain{}, false
}

func isWhitelisted(qname string) bool {
	// 统一转换为小写并移除末尾点
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	whitelistMutex.RLock()
	defer whitelistMutex.RUnlock()

	for _, pattern := range whitelistPatterns {
		// 模式也转换为小写
		pattern = strings.ToLower(pattern)

		// 精确匹配（如 x.com）
		if pattern == domain {
			return true
		}

		// 处理通配符（如 *.x.com）
		if strings.HasPrefix(pattern, "*.") {
			// 匹配 xxx.x.com 或 x.com
			if strings.HasSuffix(domain, pattern[1:]) || domain == pattern[2:] {
				return true
			}
		}

		// 处理复杂通配符（如 *aa11*）
		if strings.Contains(pattern, "*") {
			// 转换为正则表达式
			regexPattern := "^" + strings.ReplaceAll(pattern, ".", `\.`) + "$"
			regexPattern = strings.ReplaceAll(regexPattern, "*", ".*")
			if matched, _ := regexp.MatchString(regexPattern, domain); matched {
				return true
			}
		}
	}
	return false
}

// 缓存相关
type cacheItem struct {
	addr []netip.Addr
	time time.Time
}

func downloadToFile(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		_ = out.Close()
	}(out)

	_, err = io.Copy(out, resp.Body)
	return err
}

func updateCloudflareNetworks(config *Config) {
	cfCachePath4 := "./cloudflare-v4.txt"
	cfCachePath6 := "./cloudflare-v6.txt"

	// 首次启动立即加载
	loadFiles := func() {
		cfLoadMutex.Lock()
		defer cfLoadMutex.Unlock()

		if time.Since(cfLastLoaded) < cfExpire {
			return
		}

		log.Printf("[INFO] 开始更新Cloudflare IP列表...")

		// 原子下载模式
		download := func(url, path string) bool {
			tmpPath := path + ".tmp"
			if err := downloadToFile(url, tmpPath); err != nil {
				log.Printf("[WARN] 下载失败 %s: %v", url, err)
				return false
			}
			if err := os.Rename(tmpPath, path); err != nil {
				log.Printf("[WARN] 文件替换失败 %s: %v", path, err)
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
			success4 = download(config.CFMrsURL4, cfCachePath4)
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			success6 = download(config.CFMrsURL6, cfCachePath6)
		}()
		wg.Wait()

		// 加载成功的数据
		if success4 {
			if err := cfNetSet4.LoadFromFile(cfCachePath4); err != nil {
				log.Printf("[ERROR] 加载IPv4列表失败: %v", err)
			} else {
				log.Printf("[INFO] 成功加载 %d 个IPv4前缀", len(cfNetSet4.list))
			}
		}

		if success6 {
			if err := cfNetSet6.LoadFromFile(cfCachePath6); err != nil {
				log.Printf("[ERROR] 加载IPv6列表失败: %v", err)
			} else {
				log.Printf("[INFO] 成功加载 %d 个IPv6前缀", len(cfNetSet6.list))
			}
		}

		cfLastLoaded = time.Now()
	}

	// 立即执行首次加载
	loadFiles()

	// 定时更新
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		loadFiles()
	}
}

// DNS处理相关
func resolveReplaceCNAME(cname string, upstream []string) []netip.Addr {
	if val, ok := replaceCache.Load(cname); ok {
		if item, ok := val.(cacheItem); ok && time.Since(item.time) < replaceExpire {
			log.Printf("[CACHE] Hit: %s", cname)
			return item.addr
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var mu sync.Mutex
	var addrs []netip.Addr
	var wg sync.WaitGroup

	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA}
	for _, qtype := range queryTypes {
		for _, server := range upstream {
			wg.Add(1)
			go func(server string, qtype uint16) {
				defer wg.Done()
				m := new(dns.Msg)
				m.SetQuestion(dns.Fqdn(cname), qtype)
				c := new(dns.Client)
				resp, _, err := c.ExchangeContext(ctx, m, server)
				if err != nil {
					log.Printf("[WARN] Query failed for %s (type %d): %v", cname, qtype, err)
					return
				}
				if resp == nil {
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

	addrs = uniqueAddrs(addrs)
	if len(addrs) > 0 {
		replaceCache.Store(cname, cacheItem{addr: addrs, time: time.Now()})
		log.Printf("[CACHE] Stored: %s -> %v (TTL: %v)", cname, addrs, replaceExpire)
	} else {
		log.Printf("[WARN] No addresses found for %s", cname)
	}

	return addrs
}

func uniqueAddrs(addrs []netip.Addr) []netip.Addr {
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

func isCloudflareResponse(msg *dns.Msg) bool {
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			if ip, err := netip.ParseAddr(v.A.String()); err == nil && cfNetSet4.Contains(ip) {
				return true
			}
		case *dns.AAAA:
			if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && cfNetSet6.Contains(ip) {
				return true
			}
		}
	}
	return false
}

func buildReplacedResponse(req *dns.Msg, original *dns.Msg, addrs []netip.Addr, qtype uint16) *dns.Msg {
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

func getUpstreamResponse(req *dns.Msg, upstream []string) *dns.Msg {
	for _, server := range upstream {
		c := &dns.Client{
			Timeout: 2 * time.Second,
			Net:     "udp", // 显式指定协议
		}
		resp, _, err := c.Exchange(req, server)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			return resp
		}
	}
	return nil
}

func shouldReplace(resp *dns.Msg) bool {
	// 可根据实际需求添加更复杂的判断逻辑
	return len(resp.Answer) > 0
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	start := time.Now()
	defer func() {
		log.Printf("[STAT] Request processed in %v", time.Since(start))
	}()

	for _, q := range r.Question {
		qtype := q.Qtype
		if qtype != dns.TypeA && qtype != dns.TypeAAAA {
			continue
		}

		domain := q.Name
		//log.Printf(LOG_UPSTREAM_QUERY, domain, qtype)
		queriesTotal.WithLabelValues(dns.TypeToString[qtype], "received").Inc()

		// 检查是否命中定向域名
		if rule, matched := matchDesignatedDomain(domain); matched {
			designatedHits.Inc()
			resp, err := resolveViaDesignatedDNS(r, rule.DNS) // 传入整个req消息
			if err != nil {
				log.Printf("[ERROR] 定向查询失败 %s via %s: %v", domain, rule.DNS, err)
				// 这里可以fallback，或者返回SERVFAIL
			} else {
				_ = w.WriteMsg(resp)
				log.Printf("[DESIGNATED] %s -> %s", domain, rule.DNS)
				return
			}
		}

		// 白名单检查
		if isWhitelisted(domain) {
			log.Printf("[DEBUG] 域名 %s 匹配白名单模式: %v", domain, whitelistPatterns)
			//log.Printf(LOG_HIT_WHITELIST, domain)
			whitelistHits.Inc()
			proxyQuery(w, r, config.Upstream)
			return // 确保这里执行了return
		}

		// 上游查询
		upstreamResp := getUpstreamResponse(r, config.Upstream)
		if upstreamResp == nil {
			log.Printf("[ERROR] Upstream query failed for %s", domain)
			queriesTotal.WithLabelValues(dns.TypeToString[qtype], "failed").Inc()
			_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
			return
		}

		// Cloudflare检测
		if isCloudflareResponse(upstreamResp) {
			for _, rr := range upstreamResp.Answer {
				switch v := rr.(type) {
				case *dns.A:
					if ip, err := netip.ParseAddr(v.A.String()); err == nil && cfNetSet4.Contains(ip) {
						// 替换逻辑
						if shouldReplace(upstreamResp) {
							replaceAddrs := resolveReplaceCNAME(config.REplaceDomain, config.Upstream)
							if len(replaceAddrs) > 0 {
								resp := buildReplacedResponse(r, upstreamResp, replaceAddrs, qtype)
								//log.Printf(LOG_REPLACE_CNAME, domain, replaceAddrs)
								replacedCount.Inc()
								_ = w.WriteMsg(resp)
								queriesTotal.WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
								//log.Printf(LOG_HIT_CFNET, domain, ip)
								return
							}
						}
					}
				case *dns.AAAA:
					if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && cfNetSet6.Contains(ip) {
						// 替换逻辑
						if shouldReplace(upstreamResp) {
							replaceAddrs := resolveReplaceCNAME(config.REplaceDomain, config.Upstream)
							if len(replaceAddrs) > 0 {
								resp := buildReplacedResponse(r, upstreamResp, replaceAddrs, qtype)
								//log.Printf(LOG_REPLACE_CNAME, domain, replaceAddrs)
								replacedCount.Inc()
								_ = w.WriteMsg(resp)
								queriesTotal.WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
								//log.Printf(LOG_HIT_CFNET, domain, ip)
								return
							}
						}
					}
				}
			}
		}
		// 默认返回
		_ = w.WriteMsg(upstreamResp)
		queriesTotal.WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
	}
}

func proxyQuery(w dns.ResponseWriter, r *dns.Msg, upstream []string) {
	for _, server := range upstream {
		c := new(dns.Client)
		resp, _, err := c.Exchange(r, server)
		if err == nil && resp != nil {
			_ = w.WriteMsg(resp)
			return
		}
	}
	_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeServerFailure))
}

// 分流部分域名走特别的解析
func resolveViaDesignatedDNS(req *dns.Msg, dnsServer string) (*dns.Msg, error) {
	c := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
	}

	resp, _, err := c.Exchange(req, dnsServer)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func main() {
	configPath := flag.String("c", "config.yaml", "Path to config file")
	flag.Parse()

	// 加载配置
	cfgData, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to read config: %v", err)
	}

	if err := yaml.Unmarshal(cfgData, &config); err != nil {
		log.Fatalf("[FATAL] Failed to parse config: %v", err)
	}

	// 初始化设置
	cfExpire, err = time.ParseDuration(config.CFCacheTime)
	if err != nil {
		log.Fatalf("[FATAL] Invalid CF cache time: %v", err)
	}

	replaceExpire, err = time.ParseDuration(config.ReplaceCacheTime)
	if err != nil {
		log.Fatalf("[FATAL] Invalid replace cache time: %v", err)
	}

	// 启动后台任务
	go updateCloudflareNetworks(&config)
	go func() {
		for {
			loadWhitelist(config.WhitelistFile)
			loadDesignatedDomains(config.DesignatedDomain)
			time.Sleep(1 * time.Minute)
		}
	}()

	// 启动指标服务器
	if config.MetricsPort > 0 {
		go func() {
			http.Handle("/metrics", promhttp.Handler())
			addr := fmt.Sprintf(":%d", config.MetricsPort)
			log.Printf("[INFO] Starting metrics server on %s", addr)
			if err := http.ListenAndServe(addr, nil); err != nil {
				log.Printf("[ERROR] Metrics server failed: %v", err)
			}
		}()
	}

	// 启动DNS服务器
	dns.HandleFunc(".", handleDNSRequest)
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", config.ListenPort),
		Net:     "udp",
		UDPSize: 65535,
	}

	log.Printf("[INFO] Starting DNS server on :%d", config.ListenPort)
	log.Printf("[INFO] Using upstreams: %v", config.Upstream)
	log.Printf("[INFO] Whitelist file: %s", config.WhitelistFile)
	log.Printf("[INFO] DesignatedDomain file: %s", config.DesignatedDomain)
	log.Printf("[INFO] Replace CNAME: %s", config.REplaceDomain)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("[FATAL] Server failed: %v", err)
	}
}
