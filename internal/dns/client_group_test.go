package dns

import (
	"net/netip"
	"testing"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/source"
)

// FakeSpondev 测试用运营商识别器：固定按需要返回
type fakeSpon struct{}

func (fakeSpon) Lookup(addr netip.Addr) (source.ISP, bool) {
	switch addr.String() {
	case "1.1.1.1":
		return source.ISPTelecom, true
	case "2.2.2.2":
		return source.ISPUnicom, true
	}
	return source.ISPOther, false
}

func TestMatcherISPMatch(t *testing.T) {
	groups := []config.ClientGroup{
		{Name: "tel", Enabled: true, Priority: 1, Match: []string{"isp:telecom"}, DNS: []string{"udp://223.5.5.5:53"}},
		{Name: "uni", Enabled: true, Priority: 2, Match: []string{"isp:unicom"}, DNS: []string{"udp://100.10.10.10:53"}},
		{Name: "cidr", Enabled: true, Priority: 0, Match: []string{"10.0.0.0/8"}, DNS: []string{"udp://1.1.1.1:53"}},
	}
	m := NewClientGroupMatcherWithISPLookup(groups, fakeSpon{})

	if d := m.Match(netip.MustParseAddr("1.1.1.1")); !d.Matched || d.GroupName != "tel" {
		t.Errorf("1.1.1.1 应命中 tel，得到 %+v", d)
	}
	if d := m.Match(netip.MustParseAddr("2.2.2.2")); !d.Matched || d.GroupName != "uni" {
		t.Errorf("2.2.2.2 应命中 uni，得到 %+v", d)
	}
	if d := m.Match(netip.MustParseAddr("10.1.1.1")); !d.Matched || d.GroupName != "cidr" {
		t.Errorf("10.1.1.1 应命中 cidr，得到 %+v", d)
	}
	// 未知 ISP 且无 CIDR 命中 → 未匹配，AllowDomainSplit 兜底 true
	if d := m.Match(netip.MustParseAddr("8.8.8.8")); d.Matched {
		t.Errorf("8.8.8.8 不应命中任何分组，得到 %+v", d)
	}
}

func TestMatcherISPWithoutLookup(t *testing.T) {
	groups := []config.ClientGroup{
		{Name: "tel", Enabled: true, Priority: 1, Match: []string{"isp:telecom"}, DNS: []string{"udp://223.5.5.5:53"}},
	}
	// 未注入识别器：isp: 项视为不命中，避免误匹配
	m := NewClientGroupMatcher(groups)
	if d := m.Match(netip.MustParseAddr("1.1.1.1")); d.Matched {
		t.Errorf("未注入识别器时 isp: 不应命中，得到 %+v", d)
	}
}
