package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
)

type Config struct {
	ListenPort       string   `json:"ListenPort"`
	Upstreams        []string `json:"Upstreams"`
	CFMrsURL4        string   `json:"CFMrsURL4"`
	CFMrsURL6        string   `json:"CFMrsURL6"`
	ReplaceCNAME     string   `json:"ReplaceCNAME"`
	CFMrsCacheTime   string   `json:"CFMrsCacheTime"`
	ReplaceCacheTime string   `json:"ReplaceCacheTime"`
	WhitelistFile    string   `json:"WhitelistFile"`

	cfmrsCacheDuration   time.Duration
	replaceCacheDuration time.Duration
}

var (
	cfCIDRs4     []netip.Prefix
	cfCIDRs6     []netip.Prefix
	cfLock       sync.RWMutex
	cfExpire     time.Time
	replaceCache sync.Map

	whitelist struct {
		exact    map[string]struct{}
		wildcard []string
		lock     sync.RWMutex
	}
)

func loadConfig(filename string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(filename)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}

	durationCF, err := time.ParseDuration(cfg.CFMrsCacheTime)
	if err != nil {
		return cfg, fmt.Errorf("invalid CFMrsCacheTime: %w", err)
	}

	durationReplace, err := time.ParseDuration(cfg.ReplaceCacheTime)
	if err != nil {
		return cfg, fmt.Errorf("invalid ReplaceCacheTime: %w", err)
	}

	cfg.cfmrsCacheDuration = durationCF
	cfg.replaceCacheDuration = durationReplace
	return cfg, nil
}

func loadWhitelist(filename string) {
	newExact := make(map[string]struct{})
	newWildcard := make([]string, 0)

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Printf("Error reading whitelist: %v", err)
		return
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "*.") {
			domain := strings.ToLower(line[1:]) + "."
			newWildcard = append(newWildcard, domain)
		} else {
			domain := dns.Fqdn(strings.ToLower(line))
			newExact[domain] = struct{}{}
		}
	}

	whitelist.lock.Lock()
	defer whitelist.lock.Unlock()
	whitelist.exact = newExact
	whitelist.wildcard = newWildcard
	log.Printf("Whitelist updated: %d exact, %d wildcard", len(newExact), len(newWildcard))
}

func isWhitelisted(domain string) bool {
	domain = dns.Fqdn(strings.ToLower(domain))

	whitelist.lock.RLock()
	defer whitelist.lock.RUnlock()

	if _, ok := whitelist.exact[domain]; ok {
		return true
	}

	for _, suffix := range whitelist.wildcard {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

func watchWhitelist(filename string) {
	watcher, _ := fsnotify.NewWatcher()
	defer watcher.Close()

	if err := watcher.Add(filename); err != nil {
		log.Printf("File watch error: %v", err)
		return
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op.Has(fsnotify.Write) {
				loadWhitelist(filename)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func refreshCFList(cfg Config) {
	for {
		func() {
			cfLock.Lock()
			defer cfLock.Unlock()

			cfCIDRs4 = downloadPrefixes(cfg.CFMrsURL4)
			cfCIDRs6 = downloadPrefixes(cfg.CFMrsURL6)
			cfExpire = time.Now().Add(cfg.cfmrsCacheDuration)
		}()
		time.Sleep(cfg.cfmrsCacheDuration)
	}
}

func downloadPrefixes(url string) []netip.Prefix {
	data, err := download(url)
	if err != nil {
		log.Printf("Download error: %v", err)
		return nil
	}

	var prefixes []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if prefix, err := netip.ParsePrefix(line); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func download(url string) ([]byte, error) {
	if strings.HasPrefix(url, "http") {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
			Timeout: 10 * time.Second,
		}
		resp, err := client.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		return io.ReadAll(resp.Body)
	}
	return os.ReadFile(url)
}

func handleDNS(w dns.ResponseWriter, r *dns.Msg, cfg Config) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	for _, q := range r.Question {
		if isWhitelisted(q.Name) {
			resp := fetchDoH(r, cfg.Upstreams[0])
			if resp != nil {
				msg.Answer = append(msg.Answer, resp.Answer...)
			}
			continue
		}

		resp := fetchDoH(r, cfg.Upstreams[0])
		if resp == nil {
			continue
		}

		for i, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				if isCloudflareIP(rr.A) {
					if newIP := resolveReplaceIP(cfg.ReplaceCNAME, dns.TypeA, cfg); newIP != nil {
						rr.A = newIP
						resp.Answer[i] = rr
					}
				}
			case *dns.AAAA:
				if isCloudflareIP(rr.AAAA) {
					if newIP := resolveReplaceIP(cfg.ReplaceCNAME, dns.TypeAAAA, cfg); newIP != nil {
						rr.AAAA = newIP
						resp.Answer[i] = rr
					}
				}
			}
		}
		msg.Answer = append(msg.Answer, resp.Answer...)
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("Write error: %v", err)
	}
}

func fetchDoH(m *dns.Msg, dohURL string) *dns.Msg {
	packed, _ := m.Pack()
	req, _ := http.NewRequest("POST", dohURL, bytes.NewReader(packed))
	req.Header.Set("Content-Type", "application/dns-message")

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	response := new(dns.Msg)
	if err := response.Unpack(data); err != nil {
		return nil
	}
	return response
}

func resolveReplaceIP(domain string, qtype uint16, cfg Config) net.IP {
	key := fmt.Sprintf("%s-%d", domain, qtype)
	if cached, ok := replaceCache.Load(key); ok {
		if entry := cached.(replaceCacheEntry); time.Now().Before(entry.expire) {
			return entry.ip
		}
	}

	m := new(dns.Msg).SetQuestion(dns.Fqdn(domain), qtype)
	resp := fetchDoH(m, cfg.Upstreams[0])
	if resp == nil || len(resp.Answer) == 0 {
		return nil
	}

	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			entry := replaceCacheEntry{
				ip:     rr.A,
				expire: time.Now().Add(cfg.replaceCacheDuration),
			}
			replaceCache.Store(key, entry)
			return rr.A
		case *dns.AAAA:
			entry := replaceCacheEntry{
				ip:     rr.AAAA,
				expire: time.Now().Add(cfg.replaceCacheDuration),
			}
			replaceCache.Store(key, entry)
			return rr.AAAA
		}
	}
	return nil
}

func isCloudflareIP(ip net.IP) bool {
	cfLock.RLock()
	defer cfLock.RUnlock()

	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}

	check := func(prefixes []netip.Prefix) bool {
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}

	return check(cfCIDRs4) || check(cfCIDRs6)
}

type replaceCacheEntry struct {
	ip     net.IP
	expire time.Time
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config file")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Config error: %v", err)
	}

	loadWhitelist(cfg.WhitelistFile)
	go watchWhitelist(cfg.WhitelistFile)
	go refreshCFList(cfg)

	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDNS(w, r, cfg)
	})

	server := &dns.Server{Addr: cfg.ListenPort, Net: "udp"}
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.ShutdownContext(ctx)
	log.Println("Server stopped")
}
