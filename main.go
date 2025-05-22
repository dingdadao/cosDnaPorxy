package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenPort  int      `yaml:"listen_port"`
	Upstream    []string `yaml:"upstream"`
	CFMrsURL4   string   `yaml:"cf_mrs_url4"`
	CFMrsURL6   string   `yaml:"cf_mrs_url6"`
	CFMrsCache  string   `yaml:"cf_mrs_cache"`
	ReplaceCame string   `yaml:"replace_cname"`
	CFCacheTime string   `yaml:"cf_cache_time"`
}

var (
	cfIPNets = struct {
		nets []*net.IPNet
		mu   sync.RWMutex
	}{}
)

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}

// 从文件加载并解析缓存文件到内存
func loadCFMrsCache(cachePath string) error {
	log.Printf("尝试从缓存文件加载 Cloudflare IP 列表: %s", cachePath)
	f, err := os.Open(cachePath)
	if err != nil {
		return err
	}
	defer f.Close()

	ipnets, err := parseCIDRListFromReader(f)
	if err != nil {
		return err
	}

	cfIPNets.mu.Lock()
	cfIPNets.nets = ipnets
	cfIPNets.mu.Unlock()
	log.Printf("成功从缓存加载 %d 个 Cloudflare IP 网段", len(ipnets))
	return nil
}

// 修改downloadAndUpdateCFMrs函数，支持两个URL合并请求
func downloadAndUpdateCFMrs(cfg *Config) error {
	log.Printf("开始下载 Cloudflare IP 列表: %s 和 %s", cfg.CFMrsURL4, cfg.CFMrsURL6)

	var allData []string

	urls := []string{cfg.CFMrsURL4, cfg.CFMrsURL6}
	for _, url := range urls {
		resp, err := http.Get(url)
		if url == "" {
			continue
		}
		if err != nil {
			return fmt.Errorf("请求 %s 失败: %v", url, err)
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("读取 %s 响应失败: %v", url, err)
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		allData = append(allData, lines...)
	}

	// 写入缓存文件
	err := os.WriteFile(cfg.CFMrsCache, []byte(strings.Join(allData, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("写入缓存文件失败: %v", err)
	}
	log.Printf("缓存文件写入成功: %s，共 %d 条IP", cfg.CFMrsCache, len(allData))

	// 解析内容更新内存缓存
	ipnets, err := parseMrsFromBytes([]byte(strings.Join(allData, "\n")))
	if err != nil {
		return err
	}

	cfIPNets.mu.Lock()
	cfIPNets.nets = ipnets
	cfIPNets.mu.Unlock()
	log.Printf("成功更新内存 Cloudflare IP 网段缓存，数量: %d", len(ipnets))

	return nil
}

// 解析 .mrs 格式内容（字节数组）
func parseMrsFromBytes(data []byte) ([]*net.IPNet, error) {
	return parseCIDRListFromReader(strings.NewReader(string(data)))
}

// 通用解析器，从 io.Reader 读取并解析 .mrs 文件，提取 Cloudflare IP网段
func parseCIDRListFromReader(r io.Reader) ([]*net.IPNet, error) {
	scanner := bufio.NewScanner(r)
	var ipnets []*net.IPNet
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("[WARN] 第 %d 行 CIDR 解析失败，跳过: %s", lineNum, line)
			continue
		}
		ipnets = append(ipnets, ipnet)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ipnets, nil
}

func isCFIP(ip net.IP) bool {
	cfIPNets.mu.RLock()
	defer cfIPNets.mu.RUnlock()
	for _, ipnet := range cfIPNets.nets {
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

func handleDNSRequest(cfg *Config, w dns.ResponseWriter, req *dns.Msg) {
	c := new(dns.Client)
	c.Net = "udp"

	for _, upstream := range cfg.Upstream {
		r, _, err := c.Exchange(req, strings.TrimPrefix(upstream, "udp://"))
		if err != nil || r == nil {
			continue
		}

		var hasCFIP bool
		var domainName string

		// 先检测是否有 Cloudflare IP
		for _, ans := range r.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if isCFIP(rr.A) {
					hasCFIP = true
					domainName = rr.Header().Name
					break
				}
			case *dns.AAAA:
				if isCFIP(rr.AAAA) {
					hasCFIP = true
					domainName = rr.Header().Name
					break
				}
			}
			if hasCFIP {
				break
			}
		}

		if hasCFIP {
			// 清空所有答案，返回单条CNAME
			cnameRR, err := dns.NewRR(fmt.Sprintf("%s 300 IN CNAME %s.", domainName, cfg.ReplaceCame))
			if err != nil {
				log.Printf("生成CNAME失败: %v", err)
				_ = w.WriteMsg(r)
				return
			}
			r.Answer = []dns.RR{cnameRR}
			_ = w.WriteMsg(r)
			return
		}

		// 没有Cloudflare IP，原样返回所有记录（包括A/AAAA及其它类型）
		_ = w.WriteMsg(r)
		return
	}

	// 所有上游失败，返回SERVFAIL
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

func main() {
	cfg, err := loadConfig("config.yaml")
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	// 启动时先尝试加载缓存文件
	err = loadCFMrsCache(cfg.CFMrsCache)
	if err != nil {
		log.Printf("加载缓存失败: %v，尝试下载最新列表", err)
		if err = downloadAndUpdateCFMrs(cfg); err != nil {
			log.Fatalf("首次下载Cloudflare列表失败: %v", err)
		}
	}

	// 后台定时刷新Cloudflare IP列表

	go func() {
		for {
			// 解析配置中的时间
			cacheDuration, err := time.ParseDuration(cfg.CFCacheTime)
			if err != nil {
				log.Printf("配置中的 CFCacheTime 无效（%s），使用默认值 10h", cfg.CFCacheTime)
				cacheDuration, _ = time.ParseDuration("1h") // fallback 默认值
			}
			time.Sleep(cacheDuration)
			if err := downloadAndUpdateCFMrs(cfg); err != nil {
				log.Printf("定时刷新 Cloudflare IP 列表失败: %v", err)
			}
		}
	}()

	// DNS 服务器启动
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDNSRequest(cfg, w, r)
	})
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", cfg.ListenPort),
		Net:     "udp",
		UDPSize: 65535,
	}
	log.Printf("DNS代理服务启动，监听端口 :%d", cfg.ListenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("服务器启动失败: %v", err)
	}
}
