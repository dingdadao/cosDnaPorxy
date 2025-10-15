package dns

import (
	"cosDnaPorxy/internal/utils"
	"testing"
)

func TestBingDomainMatching(t *testing.T) {
	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建定向域名匹配器
	matcher := NewDesignatedMatcher(logger)

	// 设置默认DNS
	matcher.SetDefaultDNS("udp://119.29.29.29:53")

	// 模拟加载定向域名配置
	tempDomains := []*DesignatedDomain{
		{
			Domain:       "*.bing.com",
			Pattern:      "*.bing.com",
			DNS:          "default_dns",
			UpstreamType: "udp",
			MatchType:    "wildcard",
		},
	}

	// 直接设置匹配器的域名列表
	matcher.mu.Lock()
	matcher.domains = tempDomains
	matcher.trie.Insert("*.bing.com", "udp://119.29.29.29:53", "udp")
	matcher.mu.Unlock()

	// 测试匹配 www.bing.com
	dnsServer, matched := matcher.GetDesignatedDomainOrDefault("www.bing.com")

	if !matched {
		t.Errorf("Expected www.bing.com to be matched, but it wasn't")
	}

	if dnsServer != "udp://119.29.29.29:53" {
		t.Errorf("Expected DNS server to be 'udp://119.29.29.29:53', but got '%s'", dnsServer)
	}

	// 测试匹配 bing.com
	dnsServer, matched = matcher.GetDesignatedDomainOrDefault("bing.com")

	if !matched {
		t.Errorf("Expected bing.com to be matched, but it wasn't")
	}

	if dnsServer != "udp://119.29.29.29:53" {
		t.Errorf("Expected DNS server to be 'udp://119.29.29.29:53', but got '%s'", dnsServer)
	}

	t.Logf("Bing domain matching works correctly")
}
