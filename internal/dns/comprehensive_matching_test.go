package dns

import (
	"cosDnaPorxy/internal/utils"
	"regexp"
	"testing"
)

func TestParseDesignatedLine(t *testing.T) {
	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建定向域名匹配器
	matcher := NewDesignatedMatcher(logger)
	matcher.SetDefaultDNS("udp://119.29.29.29:53")

	// 测试精确匹配
	dd, err := matcher.parseDesignatedLine("example.com udp://8.8.8.8:53")
	if err != nil {
		t.Errorf("Failed to parse exact match: %v", err)
	}
	if dd.MatchType != "exact" {
		t.Errorf("Expected exact match, got %s", dd.MatchType)
	}

	// 测试前缀通配符
	dd, err = matcher.parseDesignatedLine("*.example.com udp://8.8.8.8:53")
	if err != nil {
		t.Errorf("Failed to parse prefix wildcard: %v", err)
	}
	if dd.MatchType != "wildcard" {
		t.Errorf("Expected wildcard match, got %s", dd.MatchType)
	}

	// 测试后缀通配符
	dd, err = matcher.parseDesignatedLine("example.* default_dns")
	if err != nil {
		t.Errorf("Failed to parse suffix wildcard: %v", err)
	}
	if dd.MatchType != "suffix_wildcard" {
		t.Errorf("Expected suffix wildcard match, got %s", dd.MatchType)
	}
	if dd.Regex == nil {
		t.Errorf("Expected regex for suffix wildcard")
	}

	// 测试关键字匹配
	dd, err = matcher.parseDesignatedLine("example default_dns")
	if err != nil {
		t.Errorf("Failed to parse keyword match: %v", err)
	}
	if dd.MatchType != "keyword" {
		t.Errorf("Expected keyword match, got %s", dd.MatchType)
	}
	if dd.Regex == nil {
		t.Errorf("Expected regex for keyword match")
	}

	// 测试复杂通配符
	dd, err = matcher.parseDesignatedLine("*example* default_dns")
	if err != nil {
		t.Errorf("Failed to parse complex wildcard: %v", err)
	}
	if dd.MatchType != "regex" {
		t.Errorf("Expected regex match, got %s", dd.MatchType)
	}
	if dd.Regex == nil {
		t.Errorf("Expected regex for complex wildcard")
	}

	t.Logf("Parse designated line test completed")
}

func TestRegexPatterns(t *testing.T) {
	// 测试后缀通配符正则表达式
	pattern := "^" + regexp.QuoteMeta("example") + `\..*$`
	regex, err := regexp.Compile(pattern)
	if err != nil {
		t.Errorf("Failed to compile suffix wildcard regex: %v", err)
	}

	testCases := []struct {
		domain      string
		shouldMatch bool
		description string
	}{
		{"example.com", true, "后缀通配符应该匹配example.com"},
		{"example.org", true, "后缀通配符应该匹配example.org"},
		{"sub.example.com", false, "后缀通配符不应该匹配子域名"},
		{"example", false, "后缀通配符不应该匹配根域名"},
	}

	for _, tc := range testCases {
		matched := regex.MatchString(tc.domain)
		if matched != tc.shouldMatch {
			t.Errorf("Expected %s %s %s, but it didn't", tc.domain, tc.description, map[bool]string{true: "to match", false: "NOT to match"}[tc.shouldMatch])
		} else {
			if matched {
				t.Logf("✓ %s correctly matched suffix wildcard pattern", tc.domain)
			} else {
				t.Logf("✓ %s correctly did not match suffix wildcard pattern", tc.domain)
			}
		}
	}

	// 测试关键字匹配正则表达式
	pattern = `.*` + regexp.QuoteMeta("bing") + `.*`
	regex, err = regexp.Compile(pattern)
	if err != nil {
		t.Errorf("Failed to compile keyword regex: %v", err)
	}

	testCases = []struct {
		domain      string
		shouldMatch bool
		description string
	}{
		{"www.bing.com", true, "关键字应该匹配包含bing的域名"},
		{"bing.com", true, "关键字应该匹配包含bing的域名"},
		{"google.com", false, "关键字不应该匹配不包含bing的域名"},
		{"sub.bing.example.com", true, "关键字应该匹配包含bing的域名"},
	}

	for _, tc := range testCases {
		matched := regex.MatchString(tc.domain)
		if matched != tc.shouldMatch {
			t.Errorf("Expected %s %s %s, but it didn't", tc.domain, tc.description, map[bool]string{true: "to match", false: "NOT to match"}[tc.shouldMatch])
		} else {
			if matched {
				t.Logf("✓ %s correctly matched keyword pattern", tc.domain)
			} else {
				t.Logf("✓ %s correctly did not match keyword pattern", tc.domain)
			}
		}
	}

	t.Logf("Regex patterns test completed")
}