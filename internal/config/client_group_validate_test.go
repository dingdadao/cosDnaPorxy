package config

import (
	"strings"
	"testing"
)

func baseValidConfig() *Config {
	return &Config{
		ListenPort: 15353,
		Upstream:   []string{"udp://223.5.5.5:53"},
		Cache:      CacheConfig{MaxItems: 100, TTL: 60, MaxAsyncWorkers: 1},
	}
}

func TestValidIPOrCIDR(t *testing.T) {
	valid := []string{
		"127.0.0.1", "10.0.0.0/8", "192.168.1.0/24", "::1", "2001:db8::/32", "2001:db8::1",
	}
	for _, v := range valid {
		if !ValidIPOrCIDR(v) {
			t.Errorf("ValidIPOrCIDR(%q) = false，期望 true", v)
		}
	}
	invalid := []string{
		"not-a-cidr", "999.1.1.1", "10.0.0.0/33", "1.2.3.4/", "1.2.3.4/8/8", "", "example.com",
	}
	for _, v := range invalid {
		if ValidIPOrCIDR(v) {
			t.Errorf("ValidIPOrCIDR(%q) = true，期望 false", v)
		}
	}
}

func TestValidateCustomGroupsMatch(t *testing.T) {
	cases := []struct {
		name    string
		match   []string
		wantErr string // 期望错误包含的子串，空表示应通过
	}{
		{"裸IPv4", []string{"203.0.113.7"}, ""},
		{"IPv4网段", []string{"192.168.1.0/24"}, ""},
		{"IPv6网段", []string{"2001:db8::/32"}, ""},
		{"多条件", []string{"10.0.0.0/8", "::1"}, ""},
		{"空项忽略", []string{"10.0.0.0/8", "  "}, ""},
		{"非法CIDR", []string{"not-a-cidr"}, "非法 IP/CIDR"},
		{"前缀越界", []string{"10.0.0.0/33"}, "非法 IP/CIDR"},
		{"域名不是合法匹配项", []string{"example.com"}, "非法 IP/CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := baseValidConfig()
			cfg.CustomGroups = []CustomGroup{{
				Name: "g", Enabled: true, Match: tc.match,
				FallbackDNS: []string{"udp://223.5.5.5:53"},
			}}
			err := ValidateConfig(cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("期望通过，实际报错: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("期望报错含 %q，实际通过", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误信息 %q 未包含 %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateISPGroups(t *testing.T) {
	newCfg := func(g ISPGroup) *Config {
		cfg := baseValidConfig()
		cfg.ISPGroups = []ISPGroup{g}
		return cfg
	}

	// 合法：启用 + 配置兜底 DNS
	if err := ValidateConfig(newCfg(ISPGroup{
		ISP: ISPGroupTelecom, Enabled: true, FallbackDNS: []string{"udp://223.5.5.5:53"},
	})); err != nil {
		t.Fatalf("合法运营商分组被拒绝: %v", err)
	}

	// 非法 ISP 标识
	if err := ValidateConfig(newCfg(ISPGroup{ISP: "ctcc", Enabled: false})); err == nil ||
		!strings.Contains(err.Error(), "非法分组标识") {
		t.Fatalf("非法 isp 未被拒绝: %v", err)
	}

	// 未启用：允许空 DNS
	if err := ValidateConfig(newCfg(ISPGroup{ISP: ISPGroupOther, Enabled: false})); err != nil {
		t.Fatalf("未启用的分组不应校验 DNS: %v", err)
	}

	// 启用但既无引用分流也无兜底 DNS → 拒绝
	if err := ValidateConfig(newCfg(ISPGroup{ISP: ISPGroupOther, Enabled: true})); err == nil ||
		!strings.Contains(err.Error(), "至少引用一条分流规则或配置一条兜底") {
		t.Fatalf("启用但无兜底 DNS 未被拒绝: %v", err)
	}

	// 重复分组 → 拒绝
	cfg := baseValidConfig()
	cfg.ISPGroups = []ISPGroup{
		{ISP: ISPGroupTelecom, Enabled: true, FallbackDNS: []string{"udp://1.1.1.1:53"}},
		{ISP: ISPGroupTelecom, Enabled: true, FallbackDNS: []string{"udp://1.1.1.1:53"}},
	}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复运营商分组未被拒绝: %v", err)
	}

	// 非法 dns_mode（未启用也要拦，避免脏配置被静默接受）
	if err := ValidateConfig(newCfg(ISPGroup{ISP: ISPGroupOther, Enabled: false, DNSMode: "bogus"})); err == nil ||
		!strings.Contains(err.Error(), "dns_mode") {
		t.Fatalf("非法 dns_mode 未被拒绝: %v", err)
	}

	// 引用了不存在的分流列表 → 拒绝
	cfg = newCfg(ISPGroup{
		ISP: ISPGroupTelecom, Enabled: true, SplitRefs: []string{"不存在的列表"},
	})
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "引用的分流列表") {
		t.Fatalf("悬空 split_refs 未被拒绝: %v", err)
	}

	// DNS 缺端口应被归一化补全
	cfg = newCfg(ISPGroup{
		ISP: ISPGroupTelecom, Enabled: true, FallbackDNS: []string{"udp://1.1.1.1"},
	})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("DNS 应被归一化: %v", err)
	}
	if got := cfg.ISPGroups[0].FallbackDNS[0]; got != "udp://1.1.1.1:53" {
		t.Fatalf("DNS 未补默认端口: %q", got)
	}
}

func TestValidateCustomGroupsName(t *testing.T) {
	newCfg := func(g CustomGroup) *Config {
		cfg := baseValidConfig()
		cfg.CustomGroups = []CustomGroup{g}
		return cfg
	}

	// 空名称 → 拒绝（无论是否启用）
	if err := ValidateConfig(newCfg(CustomGroup{Name: "  ", Enabled: false})); err == nil ||
		!strings.Contains(err.Error(), "name 不能为空") {
		t.Fatalf("空名称未被拒绝: %v", err)
	}

	// 启用但无 Match → 拒绝
	if err := ValidateConfig(newCfg(CustomGroup{
		Name: "机房", Enabled: true, FallbackDNS: []string{"udp://1.1.1.1:53"},
	})); err == nil || !strings.Contains(err.Error(), "至少一条匹配条件") {
		t.Fatalf("启用但无 Match 未被拒绝: %v", err)
	}

	// 启用但既无引用分流也无兜底 DNS → 拒绝
	if err := ValidateConfig(newCfg(CustomGroup{
		Name: "机房", Enabled: true, Match: []string{"10.0.0.0/8"},
	})); err == nil || !strings.Contains(err.Error(), "至少引用一条分流规则或配置一条兜底") {
		t.Fatalf("启用但无兜底 DNS 未被拒绝: %v", err)
	}

	// 重复名称 → 拒绝
	cfg := baseValidConfig()
	cfg.CustomGroups = []CustomGroup{
		{Name: "机房", Enabled: false},
		{Name: "机房", Enabled: false},
	}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("重复自定义组名未被拒绝: %v", err)
	}
}

func TestNormalizeRefs(t *testing.T) {
	got := normalizeRefs([]string{" a ", "", "  ", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("normalizeRefs 结果异常: %#v", got)
	}
	if len(normalizeRefs(nil)) != 0 {
		t.Fatalf("nil 应归一化为空切片")
	}
}

func TestValidateClientIPSourcesAndTrustedProxies(t *testing.T) {
	cfg := baseValidConfig()
	cfg.ClientIPSources = []string{"static", "header", "socket", "bogus"}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "client_ip_sources") {
		t.Fatalf("非法 client_ip_sources 未被拒绝: %v", err)
	}

	cfg = baseValidConfig()
	cfg.TrustedProxies = []string{"127.0.0.1/32", "oops"}
	if err := ValidateConfig(cfg); err == nil || !strings.Contains(err.Error(), "trusted_proxies") {
		t.Fatalf("非法 trusted_proxies 未被拒绝: %v", err)
	}

	cfg = baseValidConfig()
	cfg.TrustedProxies = []string{"127.0.0.1/32", "::1/128", ""}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("空项应被忽略，实际报错: %v", err)
	}
}
