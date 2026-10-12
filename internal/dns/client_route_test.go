package dns

import (
	"testing"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"
)

// newRouteFixture 构造只含路由所需依赖的 handler（配置 + 分流匹配器），
// 不启动任何网络监听，因此可直接断言 resolveRoute 的决策结果。
func newRouteFixture(t *testing.T, cfg *config.Config) *RefactoredHandler {
	t.Helper()
	logger := utils.NewEnhancedLogger("error", "test", false)
	mh := NewMatcherHandler(cfg, logger, &RefactoredHandler{})
	if err := mh.InitializeConfig(); err != nil {
		t.Fatalf("加载分流规则失败: %v", err)
	}
	return &RefactoredHandler{config: cfg, Logger: logger, matcherHandler: mh}
}

// routeCfg 构造「国内 + 国外」两条全局分流列表与全局上游的基础配置。
func routeCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.Upstream = []string{"udp://9.9.9.9:53"}
	cfg.SplitLists = []config.SplitList{
		{
			Name: "国内", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,cn.example.com"),
			DNS: []string{"udp://223.5.5.5:53"}, Refresh: time.Hour,
		},
		{
			Name: "国外", Enabled: true, DomainFile: writeRuleFile(t, "DOMAIN-SUFFIX,en.example.com"),
			DNS: []string{"udp://8.8.8.8:53"}, Refresh: time.Hour,
		},
	}
	return cfg
}

// 未命中客户端分组 → 沿用原有全局域名分流行为
func TestResolveRouteNoClientGroup(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	d, up := h.resolveRoute("www.cn.example.com", ClientDecision{})
	if !d.Matched || d.ListName != "国内" || up[0] != "udp://223.5.5.5:53" {
		t.Fatalf("未命中分组时应走全局分流：%+v / %v", d, up)
	}

	_, up = h.resolveRoute("www.unknown.com", ClientDecision{})
	if up[0] != "udp://9.9.9.9:53" {
		t.Fatalf("全局分流未命中时应回退全局上游，得到 %v", up)
	}
}

// 命中分组 → 引用分流命中时复用该分流列表的 DNS；引用未命中时走兜底 DNS
func TestResolveRouteMatchedGroupReuseSplitThenFallback(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	cd := ClientDecision{
		Matched:     true,
		Scope:       "c:机房",
		Label:       "机房",
		SplitRefs:   []string{"国内", "国外"},
		FallbackDNS: []string{"udp://10.0.0.1:53"},
		DNSMode:     "failover",
		IPPrefer:    config.IPPreferA,
	}

	// 命中引用的「国内」分流列表 → 复用该列表的 DNS，不展开组兜底
	d, up := h.resolveRoute("www.cn.example.com", cd)
	if !d.Matched || d.ListName != "国内" || up[0] != "udp://223.5.5.5:53" {
		t.Fatalf("命中引用分流应复用其 DNS：%+v / %v", d, up)
	}

	d, up = h.resolveRoute("www.en.example.com", cd)
	if !d.Matched || d.ListName != "国外" || up[0] != "udp://8.8.8.8:53" {
		t.Fatalf("命中引用分流应复用其 DNS：%+v / %v", d, up)
	}

	// 引用分流全部未命中 → 走兜底 DNS，并携带分组配置的偏好与 ECS 语义
	d, up = h.resolveRoute("www.other.org", cd)
	if len(up) != 1 || up[0] != "udp://10.0.0.1:53" {
		t.Fatalf("引用未命中应走兜底 DNS，得到 %v", up)
	}
	if !d.Matched || d.ListName != "机房" || d.DNSMode != "failover" || d.IPPrefer != config.IPPreferA {
		t.Fatalf("兜底决策应携带分组配置：%+v", d)
	}
}

// 命中分组但引用分流为空且兜底 DNS 为空 → 回退全局 upstream
func TestResolveRouteMatchedGroupEmptyFallbackFallsBack(t *testing.T) {
	h := newRouteFixture(t, routeCfg(t))

	cd := ClientDecision{Matched: true, Scope: "c:专线", Label: "专线", DNSMode: "failover"}
	_, up := h.resolveRoute("www.anything.example.org", cd)
	if len(up) != 1 || up[0] != "udp://9.9.9.9:53" {
		t.Fatalf("兜底 DNS 为空时应回退全局上游，得到 %v", up)
	}
}