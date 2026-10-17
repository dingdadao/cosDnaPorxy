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

// 权重后缀解析：#<非负整数> 拆出权重，其余（含非法后缀）视为未指定
func TestSplitUpstreamWeight(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantAddr string
		wantW    int
		wantHas  bool
	}{
		{"显式权重", "udp://1.1.1.1:53#70", "udp://1.1.1.1:53", 70, true},
		{"无权重后缀", "udp://1.1.1.1:53", "udp://1.1.1.1:53", 0, false},
		{"权重为 0（禁用）", "udp://1.1.1.1:53#0", "udp://1.1.1.1:53", 0, true},
		{"带空白裁剪", "  udp://1.1.1.1:53#30  ", "udp://1.1.1.1:53", 30, true},
		{"非数字后缀视为未指定", "udp://1.1.1.1:53#abc", "udp://1.1.1.1:53#abc", 0, false},
		{"负权重视为未指定", "udp://1.1.1.1:53#-5", "udp://1.1.1.1:53#-5", 0, false},
		{"DoH 带权重", "https://223.5.5.5/dns-query#20", "https://223.5.5.5/dns-query", 20, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, w, has := SplitUpstreamWeight(tc.in)
			if addr != tc.wantAddr || w != tc.wantW || has != tc.wantHas {
				t.Errorf("SplitUpstreamWeight(%q) = (%q, %d, %v)，期望 (%q, %d, %v)",
					tc.in, addr, w, has, tc.wantAddr, tc.wantW, tc.wantHas)
			}
		})
	}
}

// 归一化保留权重后缀（地址部分按协议补默认端口）
func TestNormalizeUpstreamWithWeight(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"udp://1.1.1.1#70", "udp://1.1.1.1:53#70"},
		{"udp://1.1.1.1:5353#20", "udp://1.1.1.1:5353#20"},
		{"tls://dns.google#50", "tls://dns.google:853#50"},
		{"https://223.5.5.5/dns-query#30", "https://223.5.5.5/dns-query#30"},
		{"udp://1.1.1.1#0", "udp://1.1.1.1:53#0"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
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

// 非法权重后缀必须被拒绝，而不是静默当地址的一部分
func TestNormalizeUpstreamRejectsBadWeight(t *testing.T) {
	for _, in := range []string{"udp://1.1.1.1:53#abc", "udp://1.1.1.1:53#-5", "udp://1.1.1.1#x"} {
		if _, err := NormalizeUpstream(in); err == nil {
			t.Errorf("NormalizeUpstream(%q) 应报错", in)
		}
	}
}

// 运行时 dial 地址必须剥离权重后缀，否则 dial 会因 "#70" 失败
func TestUpstreamDialAddrStripsWeight(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"udp://1.1.1.1:53#70", "1.1.1.1:53"},
		{"udp://1.1.1.1#70", "1.1.1.1:53"},
		{"tls://dns.google#50", "dns.google:853"},
		{"1.1.1.1:5353#10", "1.1.1.1:5353"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := UpstreamDialAddr(tc.in); got != tc.want {
				t.Errorf("UpstreamDialAddr(%q) = %q，期望 %q", tc.in, got, tc.want)
			}
		})
	}
}

// 全局与分组的 dns_mode 校验：wrandom 合法，未知取值拒绝
func TestValidDNSMode(t *testing.T) {
	for _, ok := range []string{"", DNSModeRace, DNSModeFailover, DNSModeWRandom} {
		if !ValidDNSMode(ok) {
			t.Errorf("ValidDNSMode(%q) 应为合法", ok)
		}
	}
	for _, bad := range []string{"random", "WRANDOM", "weighted", "parallel"} {
		if ValidDNSMode(bad) {
			t.Errorf("ValidDNSMode(%q) 应为非法", bad)
		}
	}
}

// ValidateConfig 应接受 wrandom 与带权重的上游，并拒绝非法 dns_mode
func TestValidateConfigWeightedMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DNSMode = DNSModeWRandom
	cfg.Upstream = []string{"udp://1.1.1.1:53#70", "udp://8.8.8.8:53#30"}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("wrandom 全局模式校验不应失败: %v", err)
	}
	if cfg.Upstream[0] != "udp://1.1.1.1:53#70" || cfg.Upstream[1] != "udp://8.8.8.8:53#30" {
		t.Errorf("权重后缀应保留: %v", cfg.Upstream)
	}

	cfg = DefaultConfig()
	cfg.DNSMode = "random"
	if err := ValidateConfig(cfg); err == nil {
		t.Error("非法全局 dns_mode 应报错")
	}

	cfg = DefaultConfig()
	cfg.ISPGroups = []ISPGroup{{ISP: ISPGroupTelecom, Enabled: true, FallbackDNS: []string{"udp://1.1.1.1:53#70"}, DNSMode: DNSModeWRandom}}
	if err := ValidateConfig(cfg); err != nil {
		t.Errorf("分组 wrandom 模式校验不应失败: %v", err)
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
		CustomGroups: []CustomGroup{{
			Name:        "办公网",
			Enabled:     true,
			Match:       []string{"10.0.0.0/8"},
			FallbackDNS: []string{"tls://dns.google"},
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
		{"custom_groups[0].fallback_dns[0]", cfg.CustomGroups[0].FallbackDNS[0], "tls://dns.google:853"},
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
		{"运营商分组默认上游协议不支持", func(c *Config) {
			c.ISPGroups = []ISPGroup{{ISP: ISPGroupTelecom, FallbackDNS: []string{"htps://1.1.1.1"}}}
		}, "isp_groups[0].fallback_dns[0]"},
		{"自定义分组默认上游协议不支持", func(c *Config) {
			c.CustomGroups = []CustomGroup{{Name: "g", FallbackDNS: []string{"htps://1.1.1.1"}}}
		}, "custom_groups[0].fallback_dns[0]"},
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
