package dns

import (
	"net/netip"

	"github.com/miekg/dns"
)

// ecsDefaultUDPSize 客户端未带 OPT 而又需注入 ECS 时，新建 OPT 使用的 UDP payload size
// （RFC 6891 推荐的 1232，避免响应在常见 MTU 下发生分片）
const ecsDefaultUDPSize = 1232

// applySplitECS 准备发往上游的请求：命中分流列表时按该列表的 ECS 策略处理，
// 未命中列表时不干预（沿用既有转发行为）。
// 需要改动时在 req 的副本上操作——req 会被 single-flight 与缓存复用，原地修改会并发污染。
func applySplitECS(req *dns.Msg, d SplitDecision) *dns.Msg {
	if !d.Matched {
		return req
	}
	var inject *netip.Prefix
	if p, ok := d.ECS.Resolve(); ok {
		inject = &p
	}
	out := req.Copy()
	applyECS(out, inject)
	return out
}

// applyECS 装卸请求中的 EDNS Client Subnet：
// inject == nil 时只剥离客户端自带的 ECS（开关未打开＝不传，且避免上游按客户端网段返回而污染共享缓存）；
// inject != nil 时先剥离客户端的、再注入本地的。
// 只增删 EDNS0_SUBNET 这一个 option，保留 OPT 本身：客户端通告的 UDP payload size 与 DO 位
// 直接影响上游的响应截断与 DNSSEC 处理，不能丢。
func applyECS(msg *dns.Msg, inject *netip.Prefix) {
	if msg == nil {
		return
	}

	opt := msg.IsEdns0()
	if opt == nil {
		if inject == nil {
			return // 客户端本就没带 OPT，也无需注入
		}
		msg.SetEdns0(ecsDefaultUDPSize, false)
		if opt = msg.IsEdns0(); opt == nil {
			return
		}
	}

	// 剥离已有 ECS，其余 option 原样保留
	kept := opt.Option[:0]
	for _, o := range opt.Option {
		if _, isSubnet := o.(*dns.EDNS0_SUBNET); !isSubnet {
			kept = append(kept, o)
		}
	}
	opt.Option = kept

	if inject == nil {
		return
	}

	family := uint16(1) // RFC 7871：1=IPv4，2=IPv6
	if inject.Addr().Is6() {
		family = 2
	}
	opt.Option = append(opt.Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(inject.Bits()),
		Address:       inject.Addr().AsSlice(),
	})
}
