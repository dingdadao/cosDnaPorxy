package dns

import (
	"cosDnaPorxy/internal/utils"
	"os"
	"testing"
)

func TestMatcherLoading(t *testing.T) {
	// 创建临时配置文件
	tmpFile, err := os.CreateTemp("", "designated_test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// 写入测试配置
	content := `# 测试配置
*.bing.com default_dns
bing.* default_dns
bing default_dns
`
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建定向域名匹配器
	matcher := NewDesignatedMatcher(logger)

	// 设置默认DNS
	matcher.SetDefaultDNS("udp://119.29.29.29:53")

	// 加载配置文件
	err = matcher.LoadDesignatedDomains(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load designated domains: %v", err)
	}

	// 检查加载的域名数量
	matcher.mu.RLock()
	domainCount := len(matcher.domains)
	wildcardCount := len(matcher.wildcards)
	matcher.mu.RUnlock()

	if domainCount != 3 {
		t.Errorf("Expected 3 domains, got %d", domainCount)
	}

	if wildcardCount != 2 {
		t.Errorf("Expected 2 wildcard/regex domains, got %d", wildcardCount)
	}

	// 测试匹配
	testCases := []struct {
		domain      string
		shouldMatch bool
		description string
	}{
		{"www.bing.com", true, "前缀通配符应该匹配"},
		{"bing.com", true, "后缀通配符应该匹配"},
		{"cn.bing.com", true, "前缀通配符应该匹配"},
		{"bing.org", true, "后缀通配符应该匹配"},
		{"example.bing.com", true, "关键字匹配应该匹配"},
	}

	for _, tc := range testCases {
		dnsServer, matched := matcher.GetDesignatedDomainOrDefault(tc.domain)
		if matched != tc.shouldMatch {
			t.Errorf("Expected %s %s %s, but it didn't", tc.domain, tc.description, map[bool]string{true: "to match", false: "NOT to match"}[tc.shouldMatch])
		} else if matched && dnsServer != "udp://119.29.29.29:53" {
			t.Errorf("Expected DNS server udp://119.29.29.29:53 for %s, got %s", tc.domain, dnsServer)
		} else {
			if matched {
				t.Logf("✓ %s correctly matched -> %s", tc.domain, dnsServer)
			} else {
				t.Logf("✓ %s correctly did not match", tc.domain)
			}
		}
	}

	t.Logf("Matcher loading test completed")
}
