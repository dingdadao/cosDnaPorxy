package config

import (
	"strings"
	"testing"
)

// 上游地址归一化：缺端口按协议补默认端口，IPv6 字面量补成 [::1]:53
func TestNormalizeUpstream(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"udp 缺端口补 53", "udp://1.1.1.1", "udp://1.1.1.1:53"},
		{"udp 已有端口保持", "udp://1.1.1.1:5353", "udp://1.1.1.1:5353"},
		{"tcp 缺端口补 53", "tcp://8.8.8.8", "tcp://8.8.8.8:53"},
		{"tls(DoT) 缺端口补 853", "tls://dns.google", "tls://dns.google:853"},
		{"tls(DoT) 已有端口保持", "tls://dns.google:853", "tls://dns.google:853"},
		{"udp IPv6 缺端口补 [v6]:53", "udp://2001:4860:4860::8888", "udp://[2001:4860:4860::8888]:53"},
		{"udp IPv6 带方括号缺端口", "udp://[2001:4860:4860::8888]", "udp://[2001:4860:4860::8888]:53"},
		{"udp IPv6 已有端口保持", "udp://[2001:4860:4860::8888]:5353", "udp://[2001:4860:4860::8888]:5353"},
		{"DoH 完整 URL 原样保留", "https://223.5.5.5/dns-query", "https://223.5.5.5/dns-query"},
		{"DoH URL 带端口原样保留", "https://dns.google:8443/dns-query", "https://dns.google:8443/dns-query"},
		{"DoH3 原样保留", "h3://dns.adguard.com", "h3://dns.adguard.com"},
		{"旧格式裸 IP 补 53", "1.1.1.1", "1.1.1.1:53"},
		{"旧格式 host:port 保持", "1.1.1.1:5353", "1.1.1.1:5353"},
		{"旧格式裸 IPv6 补 53", "::1", "[::1]:53"},
		{"首尾空白被裁剪", "  udp://1.1.1.1  ", "udp://1.1.1.1:53"},
		{"scheme 统一小写", "UDP://1.1.1.1", "udp://1.1.1.1:53"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeUpstream(tc.in)
			if err != nil {
				t.Fatalf("NormalizeUpstream(%q) 报错: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("NormalizeUpstream(%q) = %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// 非法上游必须被拒绝，而不是被当成域名静默放行
func TestNormalizeUpstreamRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string // 错误信息中应出现的关键片段
	}{
		{"空地址", "", "为空"},
		{"缺少主机", "udp://", "缺少主机"},
		{"不支持的协议前缀", "ftp://1.1.1.1", "不支持的上游协议前缀"},
		{"端口非数字", "udp://1.1.1.1:abc", "非法的端口"},
		{"端口越界", "udp://1.1.1.1:70000", "越界"},
		{"端口为 0", "udp://1.1.1.1:0", "越界"},
		{"DoH 缺少主机", "https:///dns-query", "非法"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeUpstream(tc.in)
			if err == nil {
				t.Fatalf("NormalizeUpstream(%q) 应报错，实际返回 %q", tc.in, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息应包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// 运行时兜底：把上游地址转成可直接 dial 的 host:port
func TestUpstreamDialAddr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"udp://1.1.1.1", "1.1.1.1:53"},
		{"tcp://1.1.1.1", "1.1.1.1:53"},
		{"tls://dns.google", "dns.google:853"},
		{"udp://1.1.1.1:5353", "1.1.1.1:5353"},
		{"1.1.1.1", "1.1.1.1:53"},
		{"1.1.1.1:5353", "1.1.1.1:5353"},
		// 关键回归：裸 IPv6 不能被当成「已含端口」
		{"::1", "[::1]:53"},
		{"[::1]", "[::1]:53"},
		{"[::1]:5353", "[::1]:5353"},
		{"udp://[::1]", "[::1]:53"},
		{"udp://2001:db8::1", "[2001:db8::1]:53"},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := UpstreamDialAddr(tc.in); got != tc.want {
				t.Errorf("UpstreamDialAddr(%q) = %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestUpstreamDefaultPort(t *testing.T) {
	cases := map[string]string{
		"":       "53",
		"udp":    "53",
		"tcp":    "53",
		"tls":    "853",
		"tls://": "853",
		"https":  "443",
		"h3":     "443",
		"TLS":    "853",
	}
	for scheme, want := range cases {
		if got := UpstreamDefaultPort(scheme); got != want {
			t.Errorf("UpstreamDefaultPort(%q) = %q，期望 %q", scheme, got, want)
		}
	}
}

func TestValidUpstreamScheme(t *testing.T) {
	for _, ok := range []string{"", "udp", "tcp", "tls", "https", "h3", "UDP"} {
		if !ValidUpstreamScheme(ok) {
			t.Errorf("ValidUpstreamScheme(%q) 应为合法", ok)
		}
	}
	for _, bad := range []string{"ftp", "http", "quic", "doh"} {
		if ValidUpstreamScheme(bad) {
			t.Errorf("ValidUpstreamScheme(%q) 应为非法", bad)
		}
	}
}

// ValidateConfig 应就地补全各上游字段的缺省端口（存量配置 udp://1.1.1.1 才会恢复正常）
func TestValidateConfigNormalizesUpstreams(t *testing.T) {
	cfg := &Config{
		ListenPort: 53,
		Upstream:   []string{"udp://1.1.1.1", "https://223.5.5.5/dns-query"},
		BackupDNS:  "udp://9.9.9.9",
		SplitLists: []SplitList{{
			Name:    "国外",
			Enabled: true,
			DNS:     []string{"udp://1.1.1.1", "tls://dns.google"},
		}},
		ClientGroups: []ClientGroup{{
			Name:    "办公网",
			Enabled: true,
			Match:   []string{"10.0.0.0/8"},
			DNS:     []string{"tls://dns.google"},
		}},
	}

	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("校验失败: %v", err)
	}

	checks := []struct {
		field string
		got   string
		want  string
	}{
		{"upstream[0]", cfg.Upstream[0], "udp://1.1.1.1:53"},
		{"upstream[1]", cfg.Upstream[1], "https://223.5.5.5/dns-query"},
		{"backup_dns", cfg.BackupDNS, "udp://9.9.9.9:53"},
		{"split_lists[0].dns[0]", cfg.SplitLists[0].DNS[0], "udp://1.1.1.1:53"},
		{"split_lists[0].dns[1]", cfg.SplitLists[0].DNS[1], "tls://dns.google:853"},
		{"client_groups[0].dns[0]", cfg.ClientGroups[0].DNS[0], "tls://dns.google:853"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s 归一化结果 = %q，期望 %q", c.field, c.got, c.want)
		}
	}
}

// 非法上游要带上具体字段名报错，便于管理端定位
func TestValidateConfigRejectsBadUpstreamFields(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"全局上游端口非法", func(c *Config) { c.Upstream = []string{"udp://1.1.1.1:abc"} }, "upstream[0]"},
		{"分流列表协议不支持", func(c *Config) {
			c.SplitLists = []SplitList{{Name: "x", Enabled: true, DNS: []string{"ftp://1.1.1.1"}}}
		}, "split_lists[0].dns[0]"},
		{"客户端分组协议不支持", func(c *Config) {
			c.ClientGroups = []ClientGroup{{Name: "g", Enabled: true, Match: []string{"10.0.0.0/8"}, DNS: []string{"htps://1.1.1.1"}}}
		}, "client_groups[0].dns[0]"},
		{"备份 DNS 非法", func(c *Config) { c.BackupDNS = "udp://" }, "backup_dns"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mut(cfg)
			err := ValidateConfig(cfg)
			if err == nil {
				t.Fatal("应报错")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("错误信息应包含字段名 %q，实际: %v", tc.want, err)
			}
		})
	}
}
