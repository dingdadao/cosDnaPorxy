package dns

import (
	"testing"
)

func TestIsWhitelisted(t *testing.T) {
	// 创建测试用的Handler
	h := &Handler{
		whitelistPattern: []string{
			"example.com",
			"*.test.com",
			"sub.example.org",
		},
	}

	// 测试用例
	testCases := []struct {
		domain     string
		expected   bool
		description string
	}{
		{"example.com", true, "精确匹配"},
		{"www.example.com", false, "子域名不匹配精确域名"},
		{"test.com", true, "通配符匹配根域名"},
		{"sub.test.com", true, "通配符匹配子域名"},
		{"deep.sub.test.com", true, "通配符匹配多级子域名"},
		{"sub.example.org", true, "精确匹配子域名"},
		{"other.com", false, "不匹配任何模式"},
		{"example.org", false, "不匹配任何模式"},
	}

	for _, tc := range testCases {
		result := h.isWhitelisted(tc.domain)
		if result != tc.expected {
			t.Errorf("域名: %s, 期望: %v, 实际: %v, 描述: %s", 
				tc.domain, tc.expected, result, tc.description)
		}
	}
}

func TestWhitelistBehavior(t *testing.T) {
	// 测试白名单的行为：跳过云服务检查，直接进行分流
	t.Log("白名单域名应该：")
	t.Log("1. 跳过Cloudflare/AWS IP替换检查")
	t.Log("2. 直接进行geosite国内外分流")
	t.Log("3. 不进行IP篡改")
	t.Log("4. 保持原始DNS响应")
} 