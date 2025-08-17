package dns

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"net/netip"
)

// isCloudResponse 检查是否为云服务响应
func (h *Handler) isCloudResponse(msg *dns.Msg, iptype int) bool {
	var ipd *NetIPX
	for _, rr := range msg.Answer {
		switch v := rr.(type) {
		case *dns.A:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet4
			case AWSType:
				ipd = h.aWSNetSet4
			}
			if ipd != nil {
				if ip, err := netip.ParseAddr(v.A.String()); err == nil && ipd.Contains(ip) {
					h.logger.Debug("IPv4 %s is in known IP range", ip)
					return true
				}
			}
		case *dns.AAAA:
			switch iptype {
			case CFType:
				ipd = h.cfNetSet6
			case AWSType:
				ipd = h.aWSNetSet6
			}
			if ipd != nil {
				if ip, err := netip.ParseAddr(v.AAAA.String()); err == nil && ipd.Contains(ip) {
					h.logger.Debug("IPv6 %s is in known IP range", ip)
					return true
				}
			}
		}
	}
	return false
}

// resolveReplaceCNAME 解析替换CNAME
func (h *Handler) resolveReplaceCNAME(cname string) []netip.Addr {
	// 生成缓存键
	cacheKey := fmt.Sprintf("replace_cname:%s", cname)

	// 尝试从缓存获取
	if cached, found := h.hotCache.Get(cacheKey); found {
		if cachedAddrs, ok := cached.([]netip.Addr); ok {
			h.logger.Debug("替换域名缓存命中: %s", cname)
			h.metrics.GetCacheHits().WithLabelValues("replace_cname").Inc()
			return cachedAddrs
		}
	}

	// 缓存未命中，执行解析
	h.logger.Debug("替换域名缓存未命中，执行解析: %s", cname)

	var addrs []netip.Addr

	// 使用所有上游解析
	allUpstreams := append(h.config.CNUpstream, h.config.NotCNUpstream...)

	// 创建A记录查询
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(cname), dns.TypeA)

	resp, err := h.proxyQuery(req, allUpstreams)
	if err == nil && resp != nil {
		for _, rr := range resp.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, err := netip.ParseAddr(a.A.String()); err == nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}

	// 创建AAAA记录查询
	reqAAAA := &dns.Msg{}
	reqAAAA.SetQuestion(dns.Fqdn(cname), dns.TypeAAAA)

	respAAAA, err := h.proxyQuery(reqAAAA, allUpstreams)
	if err == nil && respAAAA != nil {
		for _, rr := range respAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				if ip, err := netip.ParseAddr(aaaa.AAAA.String()); err == nil {
					addrs = append(addrs, ip)
				}
			}
		}
	}

	// 去重
	addrs = h.uniqueAddrs(addrs)

	// 缓存结果（使用较长的TTL，因为替换域名相对稳定）
	if len(addrs) > 0 {
		h.hotCache.Set(cacheKey, addrs, h.replaceExpire)
		h.logger.Debug("替换域名解析结果已缓存: %s -> %v", cname, addrs)
	}

	return addrs
}

// uniqueAddrs 去重IP地址
func (h *Handler) uniqueAddrs(addrs []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{})
	result := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if _, exists := seen[a]; !exists {
			seen[a] = struct{}{}
			result = append(result, a)
		}
	}
	return result
}

// buildReplacedResponse 构建替换后的响应
func (h *Handler) buildReplacedResponse(req *dns.Msg, original *dns.Msg, addrs []netip.Addr, qtype uint16) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Authoritative = original.Authoritative
	resp.RecursionAvailable = original.RecursionAvailable
	resp.Rcode = original.Rcode

	// 保留非A/AAAA记录
	for _, ans := range original.Answer {
		if ans.Header().Rrtype != dns.TypeA && ans.Header().Rrtype != dns.TypeAAAA {
			resp.Answer = append(resp.Answer, ans)
		}
	}

	// 添加替换记录
	for _, ip := range addrs {
		if (qtype == dns.TypeA && ip.Is4()) || (qtype == dns.TypeAAAA && ip.Is6()) {
			hdr := dns.RR_Header{
				Name:   req.Question[0].Name,
				Rrtype: qtype,
				Class:  dns.ClassINET,
				Ttl:    300,
			}
			if ip.Is4() {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: hdr,
					A:   net.ParseIP(ip.String()),
				})
			} else {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  hdr,
					AAAA: net.ParseIP(ip.String()),
				})
			}
		}
	}
	return resp
}

// handleReplacement 处理命中IP替换
func (h *Handler) handleReplacement(w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg, qtype uint16, domain string, ip netip.Addr, iptype int) {
	var replaceDomain string

	switch iptype {
	case CFType:
		replaceDomain = h.config.ReplaceCFDomain
	case AWSType:
		replaceDomain = h.config.ReplaceAWSDomain
	}

	replaceAddrs := h.resolveReplaceCNAME(replaceDomain)

	// 新增：收集原始IP
	var originalIPs []string
	if resp != nil {
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				originalIPs = append(originalIPs, v.A.String())
			case *dns.AAAA:
				originalIPs = append(originalIPs, v.AAAA.String())
			}
		}
	}

	if len(replaceAddrs) > 0 {
		newResp := h.buildReplacedResponse(req, resp, replaceAddrs, qtype)
		h.logger.Info("【Cloudflare命中】%s，原IP: %v，替换为: %v", domain, originalIPs, replaceAddrs)
		h.metrics.GetReplacedCount().Inc()
		// 设置缓存 - 缓存替换后的响应
		h.setCachedResponse(req, newResp)
		if err := w.WriteMsg(newResp); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "replaced").Inc()
		h.logger.Debug("handleReplacement matched: %s -> %v", domain, originalIPs)
	} else {
		// 设置缓存 - 缓存原始响应
		h.setCachedResponse(req, resp)
		if err := w.WriteMsg(resp); err != nil {
			h.logger.Error("WriteMsg失败: %v", err)
		}
		h.metrics.GetQueriesTotal().WithLabelValues(dns.TypeToString[qtype], "passed").Inc()
	}
} 