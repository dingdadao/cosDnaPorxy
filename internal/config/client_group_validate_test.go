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

func TestValidateClientGroupsMatch(t *testing.T) {
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
			cfg.ClientGroups = []ClientGroup{{Name: "g", Enabled: true, Match: tc.match, DNS: []string{"udp://223.5.5.5:53"}}}
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
