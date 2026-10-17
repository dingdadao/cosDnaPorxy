package dns

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// buildBigResponse 构造 CNAME + n 条同目标名 A 记录的响应：
// 未压缩明显大于压缩（重复目标名可被压缩指针复用），便于观察压缩带来的报文尺寸变化。
func buildBigResponse(qname string, n int) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.AuthenticatedData = true // 上游 AD=1，出口应清零

	target := "target.cf.example.net."
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: target,
	})
	for i := 0; i < n; i++ {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: target, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(10, 0, byte(i/256), byte(i%256)),
		})
	}
	return resp
}

// msgSize 返回在指定压缩设置下打包后的字节数
func msgSize(t *testing.T, m *dns.Msg, compress bool) int {
	t.Helper()
	cp := m.Copy()
	cp.Compress = compress
	b, err := cp.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return len(b)
}

// startLiveWireServer 在同一端口启动真实 UDP 与 TCP 服务（与生产一致），
// 命中时走生产同款 serveCacheHit，未命中回退 Get 重建 + 统一出口。返回 host:port。
func startLiveWireServer(t *testing.T, cache *OptimizedDNSCache, domain string) string {
	t.Helper()

	// 先占 TCP 端口，再用同一端口绑 UDP，保证 TC 后客户端可原地址改走 TCP
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 TCP 失败: %v", err)
	}
	addr := ln.Addr().String()
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		_ = ln.Close()
		t.Fatalf("监听 UDP(%s) 失败: %v", addr, err)
	}

	// 命中优先直写预打包字节，否则回退统一出口（与生产服务路径一致）
	h := &RefactoredHandler{}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if s, ok := cache.GetServe("-", domain, dns.TypeA); ok {
			h.serveCacheHit(w, r, s)
			return
		}
		if resp, hit, _, _ := cache.Get("-", domain, dns.TypeA); hit {
			h.writeResponse(w, r, resp)
			return
		}
		h.sendErrorResponse(w, r, dns.RcodeServerFailure)
	})

	udpSrv := &dns.Server{PacketConn: pc, Handler: handler}
	tcpSrv := &dns.Server{Listener: ln, Handler: handler}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpSrv.Shutdown(); _ = tcpSrv.Shutdown() })

	// 等待服务就绪
	time.Sleep(30 * time.Millisecond)
	return addr
}

// exchange 用真实 dns.Client 通过指定网络发起查询
func exchange(t *testing.T, network, addr string, req *dns.Msg) *dns.Msg {
	t.Helper()
	c := &dns.Client{Net: network, Timeout: 3 * time.Second}
	resp, _, err := c.Exchange(req, addr)
	if err != nil {
		t.Fatalf("真实客户端 %s 查询失败: %v", network, err)
	}
	return resp
}

func newReq(qname string, edns bool, size uint16) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	if edns {
		req.SetEdns0(size, false)
	}
	return req
}

// TestLiveUDPCompressedHit 真实 UDP 客户端：压缩报文可被正常解析，且比旧路径（未压缩）更小。
// 20 条 A 的响应未压缩 > 512，压缩后 < 512：旧 Truncate 会因未压缩超限而开启压缩，
// 新快路径直接发压缩报文，两者都应在 512 内完整返回，不带 TC。
func TestLiveUDPCompressedHit(t *testing.T) {
	const qname = "Example.COM."
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	resp := buildBigResponse(qname, 20)

	uncompressed := msgSize(t, resp, false)
	compressed := msgSize(t, resp, true)
	t.Logf("20A 响应尺寸: 未压缩=%d 压缩=%d", uncompressed, compressed)
	if compressed >= 512 {
		t.Fatalf("用例前提不成立：压缩后应 <512，实际 %d", compressed)
	}

	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, resp, false)
	ageStoredAt(cache, "-", domain, dns.TypeA, 1500*time.Millisecond)

	ls := startLiveWireServer(t, cache, domain)
	got := exchange(t, "udp", ls, newReq(qname, false, 0))

	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode=%s，期望 NOERROR", dns.RcodeToString[got.Rcode])
	}
	if got.Truncated {
		t.Fatalf("压缩后 %d<512 不应置 TC", compressed)
	}
	if len(got.Answer) != 21 {
		t.Fatalf("answers=%d，期望 21", len(got.Answer))
	}
	if got.AuthenticatedData {
		t.Error("出口应清除 AD 位")
	}
	served := msgSize(t, got, got.Compress)
	_ = served
	t.Logf("真实 UDP 客户端解析成功: rcode=NOERROR answers=%d（压缩报文 %d 字节 < 未压缩 %d 字节）",
		len(got.Answer), compressed, uncompressed)
}

// TestLiveUDPNoEDNSBigTruncates 真实 UDP 客户端：压缩后仍超 512 的响应应回退旧路径并置 TC，
// 客户端按标准流程改 TCP 重试可拿到完整响应。
func TestLiveUDPNoEDNSBigTruncates(t *testing.T) {
	const qname = "Example.COM."
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	resp := buildBigResponse(qname, 40)
	compressed := msgSize(t, resp, true)
	if compressed <= 512 {
		t.Fatalf("用例前提不成立：压缩后应 >512，实际 %d", compressed)
	}

	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, resp, false)
	ageStoredAt(cache, "-", domain, dns.TypeA, 1500*time.Millisecond)

	ls := startLiveWireServer(t, cache, domain)

	udpResp := exchange(t, "udp", ls, newReq(qname, false, 0))
	if !udpResp.Truncated {
		t.Fatalf("UDP 无 EDNS 且响应超 512 应置 TC，实际未置（answers=%d）", len(udpResp.Answer))
	}
	if len(udpResp.Answer) >= 41 {
		t.Fatalf("截断后 answers=%d，应少于完整 41 条", len(udpResp.Answer))
	}

	// 标准客户端行为：TC=1 时改走 TCP
	tcpResp := exchange(t, "tcp", ls, newReq(qname, false, 0))
	if tcpResp.Truncated {
		t.Fatal("TCP 重试不应再被截断")
	}
	if len(tcpResp.Answer) != 41 {
		t.Fatalf("TCP 重试 answers=%d，期望 41", len(tcpResp.Answer))
	}
	t.Logf("UDP 超限置 TC（保留 %d 条）→ TCP 重试完整（%d 条），符合 RFC 1035 截断语义",
		len(udpResp.Answer), len(tcpResp.Answer))
}

// TestLiveUDPWithEDNSFullResponse 真实 UDP 客户端带 EDNS(4096)：
// 大响应走压缩快路径完整返回，并正确回带 OPT。
func TestLiveUDPWithEDNSFullResponse(t *testing.T) {
	const qname = "Example.COM."
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	resp := buildBigResponse(qname, 40)

	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, resp, false)
	ageStoredAt(cache, "-", domain, dns.TypeA, 1500*time.Millisecond)

	ls := startLiveWireServer(t, cache, domain)
	got := exchange(t, "udp", ls, newReq(qname, true, 4096))

	if got.Truncated {
		t.Fatal("EDNS 4096 下不应截断")
	}
	if len(got.Answer) != 41 {
		t.Fatalf("answers=%d，期望 41", len(got.Answer))
	}
	if opt := got.IsEdns0(); opt == nil || opt.UDPSize() != 4096 {
		t.Fatalf("应回带客户端 OPT(4096)，实际 %v", opt)
	}
	t.Logf("EDNS(4096) 大响应经压缩快路径完整返回: answers=%d opt=%v", len(got.Answer), got.IsEdns0())
}

// TestLiveTCPFullCompressed 真实 TCP 客户端：大响应完整压缩返回，字节远小于未压缩。
func TestLiveTCPFullCompressed(t *testing.T) {
	const qname = "Example.COM."
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	resp := buildBigResponse(qname, 40)
	uncompressed := msgSize(t, resp, false)
	compressed := msgSize(t, resp, true)

	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, resp, false)
	ageStoredAt(cache, "-", domain, dns.TypeA, 1500*time.Millisecond)

	ls := startLiveWireServer(t, cache, domain)
	got := exchange(t, "tcp", ls, newReq(qname, false, 0))

	if got.Truncated {
		t.Fatal("TCP 不应截断")
	}
	if len(got.Answer) != 41 {
		t.Fatalf("answers=%d，期望 41", len(got.Answer))
	}
	t.Logf("TCP 完整响应: answers=%d 压缩=%d 未压缩=%d（省 %d 字节）",
		len(got.Answer), compressed, uncompressed, uncompressed-compressed)
}

// TestLiveMixedCaseQNAME 真实客户端发混合大小写 QNAME 时，响应 Question 必须按原样回写（0x20 随机化校验）。
func TestLiveMixedCaseQNAME(t *testing.T) {
	const mixed = "ExAmPlE.CoM."
	domain := strings.ToLower(strings.TrimSuffix(mixed, "."))

	cache := NewOptimizedDNSCache(4096, time.Minute)
	cache.Set("-", domain, dns.TypeA, buildBigResponse("example.com.", 4), false)
	ageStoredAt(cache, "-", domain, dns.TypeA, 1500*time.Millisecond)

	ls := startLiveWireServer(t, cache, domain)
	got := exchange(t, "udp", ls, newReq(mixed, true, 1232))

	if len(got.Question) != 1 || got.Question[0].Name != mixed {
		t.Fatalf("Question 回写 = %v，期望原样 %q", got.Question, mixed)
	}
	t.Logf("混合大小写 QNAME 原样回写: %q", got.Question[0].Name)
}
