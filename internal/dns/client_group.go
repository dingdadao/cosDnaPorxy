package dns

import (
	"net/netip"
	"sort"
	"strings"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/source"
)

// ISPLookup 客户端运营商识别抽象（注入到匹配器，便于替换实现与测试）
type ISPLookup interface {
	Lookup(addr netip.Addr) (source.ISP, bool)
}

// ClientDecision 客户端分组匹配决策
type ClientDecision struct {
	Matched          bool
	GroupName        string
	DNS              []string
	DNSMode          string
	EnableCloudCheck bool
	ECS              config.ECSPolicy
	IPPrefer         string
	AllowDomainSplit bool
}

// ClientGroupMatcher 客户端分组匹配器
type ClientGroupMatcher struct {
	groups []config.ClientGroup
	isp    ISPLookup // 可空的运营商识别器；为空时 isp: 匹配项视为不命中
}

// NewClientGroupMatcher 创建客户端分组匹配器
func NewClientGroupMatcher(groups []config.ClientGroup) *ClientGroupMatcher {
	return &ClientGroupMatcher{groups: normalizeGroups(groups)}
}

// NewClientGroupMatcherWithISPLookup 创建客户端分组匹配器并注入运营商识别器
func NewClientGroupMatcherWithISPLookup(groups []config.ClientGroup, sp ISPLookup) *ClientGroupMatcher {
	return &ClientGroupMatcher{groups: normalizeGroups(groups), isp: sp}
}

// SetISPLookup 覆盖或清除运营商识别器
func (m *ClientGroupMatcher) SetISPLookup(sp ISPLookup) { m.isp = sp }

// UpdateGroups 更新分组
func (m *ClientGroupMatcher) UpdateGroups(groups []config.ClientGroup) {
	m.groups = normalizeGroups(groups)
}

// Match 按客户端 IP 匹配分组（每个查询解析一次运营商，供多个分组复用）
func (m *ClientGroupMatcher) Match(clientIP netip.Addr) ClientDecision {
	var ipISP source.ISP
	haveISP := false
	if m.isp != nil && clientIP.IsValid() {
		if isp, ok := m.isp.Lookup(clientIP); ok {
			ipISP, haveISP = isp, true
		}
	}
	for _, g := range m.groups {
		if !g.Enabled {
			continue
		}
		hit := matchGroup(g, clientIP, ipISP, haveISP)
		if hit {
			return ClientDecision{
				Matched:          true,
				GroupName:        g.Name,
				DNS:              g.DNS,
				DNSMode:          normDNSMode(g.DNSMode),
				EnableCloudCheck: g.EnableCloudCheck,
				ECS:              g.ECS,
				IPPrefer:         g.IPPrefer,
				AllowDomainSplit: g.AllowDomainSplit,
			}
		}
	}
	return ClientDecision{Matched: false, AllowDomainSplit: true}
}

// normalizeGroups 按优先级排序：Priority 大者在前，同 Priority 按原顺序（稳定排序）
func normalizeGroups(groups []config.ClientGroup) []config.ClientGroup {
	out := make([]config.ClientGroup, len(groups))
	copy(out, groups)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Priority > out[j].Priority
	})
	return out
}

// matchGroup 判断单个分组是否命中。ipISP/haveISP 为本查询预解析的运营商结果。
func matchGroup(g config.ClientGroup, clientIP netip.Addr, ipISP source.ISP, haveISP bool) bool {
	if !clientIP.IsValid() {
		return false
	}

	matched := false
	for _, item := range g.Match {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		// 运营商匹配：isp:<name>
		if strings.HasPrefix(item, "isp:") {
			if !haveISP {
				continue // 未装库/未命中段，isp 项不算命中（不短路，继续看其它 IP 项）
			}
			if want, ok := source.ParseISP(strings.TrimPrefix(item, "isp:")); ok && want == ipISP {
				matched = true
				break
			}
			continue
		}
		// CIDR 匹配
		if strings.Contains(item, "/") {
			prefix, err := netip.ParsePrefix(item)
			if err != nil {
				continue
			}
			if prefix.Contains(clientIP) {
				matched = true
				break
			}
		} else {
			// 精确 IP 匹配
			ip, err := netip.ParseAddr(item)
			if err != nil {
				continue
			}
			if ip == clientIP {
				matched = true
				break
			}
		}
	}

	if g.Invert {
		return !matched
	}
	return matched
}
