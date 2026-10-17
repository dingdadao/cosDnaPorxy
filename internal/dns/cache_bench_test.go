package dns

import (
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// benchResponse 构造贴近真实流量的响应：CNAME + 2×A + 1×AAAA
func benchResponse(domain string) *dns.Msg {
	fq := dns.Fqdn(domain)
	cdn := "cdn." + fq
	m := new(dns.Msg)
	m.SetQuestion(fq, dns.TypeA)
	m.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: fq, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: cdn,
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: cdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.1").To4(),
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: cdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.2").To4(),
		},
		&dns.AAAA{
			Hdr:  dns.RR_Header{Name: cdn, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2001:db8::1"),
		},
	}
	return m
}

const benchDomainCount = 1024

func newBenchCache(b *testing.B) (*OptimizedDNSCache, []string) {
	b.Helper()
	c := NewOptimizedDNSCache(200000, 5*time.Minute)
	domains := make([]string, benchDomainCount)
	for i := range domains {
		d := "b" + strconv.Itoa(i) + ".example.com."
		domains[i] = d
		c.Set("-", d, dns.TypeA, benchResponse(d), false)
	}
	return c, domains
}

// benchKeySink 阻止编译器把被测表达式优化掉
var benchKeySink string

// BenchmarkCacheKeyOnly 只测缓存键构造的分配开销
func BenchmarkCacheKeyOnly(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchKeySink = c.key("-", domains[i&(benchDomainCount-1)], dns.TypeA)
	}
}

// BenchmarkCacheLookupNoCopy 只测分片锁 + map 查找（不含拷贝）
func BenchmarkCacheLookupNoCopy(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		k := c.key("-", domains[i&(benchDomainCount-1)], dns.TypeA)
		sh := c.getShard(k)
		sh.mu.RLock()
		_, _ = sh.store[k]
		sh.mu.RUnlock()
	}
}

// BenchmarkCacheMsgCopyOnly 只测命中时的 Msg 深拷贝
func BenchmarkCacheMsgCopyOnly(b *testing.B) {
	m := benchResponse("x.example.com.")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Copy()
	}
}

// BenchmarkCacheGetHit 完整命中路径（当前实现）
func BenchmarkCacheGetHit(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, hit, _, _ := c.Get("-", domains[i&(benchDomainCount-1)], dns.TypeA)
		if !hit {
			b.Fatal("cache miss")
		}
	}
}

// BenchmarkCacheGetHitParallel 并发命中路径，用于观察分片锁竞争
func BenchmarkCacheGetHitParallel(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			_, hit, _, _ := c.Get("-", domains[i&(benchDomainCount-1)], dns.TypeA)
			if !hit {
				b.Fatal("cache miss")
			}
			i++
		}
	})
}

// BenchmarkCacheGetWithFlightHit 命中路径（单飞行入口）
func BenchmarkCacheGetWithFlightHit(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, hit, _, _ := c.GetWithFlight("-", domains[i&(benchDomainCount-1)], dns.TypeA)
		if !hit {
			b.Fatal("cache miss")
		}
	}
}

// BenchmarkCacheGetServeHit 快路径查询（共享响应 + 预打包字节，不含写出）
func BenchmarkCacheGetServeHit(b *testing.B) {
	c, domains := newBenchCache(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := c.GetServe("-", domains[i&(benchDomainCount-1)], dns.TypeA); !ok {
			b.Fatal("cache miss")
		}
	}
}

// BenchmarkBuildWire Set 时新增的预打包成本（Pack + 扫描 TTL 偏移）
func BenchmarkBuildWire(b *testing.B) {
	base := benchResponse("x.example.com.")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, meta := buildWire(base.Copy()); !meta.ok {
			b.Fatal("buildWire failed")
		}
	}
}

// BenchmarkCacheSet 写入路径总成本（含深拷贝 + 预打包 + 分片锁）
func BenchmarkCacheSet(b *testing.B) {
	c := NewOptimizedDNSCache(200000, 5*time.Minute)
	base := benchResponse("x.example.com.")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Set("-", "b"+strconv.Itoa(i&(benchDomainCount-1))+".example.com.", dns.TypeA, base, false)
	}
}

// benchReqs 为每个缓存域名构造同名请求（快路径要求请求 QNAME 与缓存一致）
func benchReqs(domains []string) []*dns.Msg {
	reqs := make([]*dns.Msg, len(domains))
	for i, d := range domains {
		reqs[i] = new(dns.Msg)
		reqs[i].SetQuestion(d, dns.TypeA)
		reqs[i].Id = uint16(i)
	}
	return reqs
}

// benchWriter 响应出口：WriteMsg 按 miekg 真实行为打包后丢弃，Write 直接丢弃
type benchWriter struct{ network string }

func (w benchWriter) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53} }
func (w benchWriter) RemoteAddr() net.Addr {
	if w.network == "tcp" {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
	}
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}
func (w benchWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w benchWriter) WriteMsg(m *dns.Msg) error   { _, err := m.Pack(); return err }
func (w benchWriter) Close() error                { return nil }
func (w benchWriter) TsigStatus() error           { return nil }
func (w benchWriter) TsigTimersOnly(bool)         {}
func (w benchWriter) Hijack()                     {}

// BenchmarkWireWriteOnlyLegacy 仅测旧出口（深拷贝已完成，只测 Truncate+打包写出）
func BenchmarkWireWriteOnlyLegacy(b *testing.B) {
	c, domains := newBenchCache(b)
	req := new(dns.Msg)
	req.SetQuestion("b0.example.com.", dns.TypeA)
	req.Id = 1
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	resp, _, _, _ := c.Get("-", domains[0], dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.writeResponse(w, req, resp.Copy())
	}
}

// BenchmarkWireWriteOnlyNew 仅测新出口（GetServe 已完成，只测打补丁直写）
func BenchmarkWireWriteOnlyNew(b *testing.B) {
	c, domains := newBenchCache(b)
	req := new(dns.Msg)
	req.SetQuestion("b0.example.com.", dns.TypeA)
	req.Id = 1
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	s, _ := c.GetServe("-", domains[0], dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.serveCacheHit(w, req, s)
	}
}

// BenchmarkCacheHitLegacyFull 旧完整命中路径：Get 深拷贝（含TTL递减）+ 统一出口打包写出
func BenchmarkCacheHitLegacyFull(b *testing.B) {
	c, domains := newBenchCache(b)
	reqs := benchReqs(domains)
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i & (benchDomainCount - 1)
		resp, hit, _, _ := c.Get("-", domains[j], dns.TypeA)
		if !hit {
			b.Fatal("cache miss")
		}
		h.writeResponse(w, reqs[j], resp)
	}
}

// BenchmarkCacheHitWireFull 新完整命中路径：GetServe + 直写预打包字节
func BenchmarkCacheHitWireFull(b *testing.B) {
	c, domains := newBenchCache(b)
	reqs := benchReqs(domains)
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j := i & (benchDomainCount - 1)
		s, ok := c.GetServe("-", domains[j], dns.TypeA)
		if !ok {
			b.Fatal("cache miss")
		}
		h.serveCacheHit(w, reqs[j], s)
	}
}

// BenchmarkCacheHitLegacyFullParallel 旧完整命中路径（并发）
func BenchmarkCacheHitLegacyFullParallel(b *testing.B) {
	c, domains := newBenchCache(b)
	reqs := benchReqs(domains)
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			j := i & (benchDomainCount - 1)
			resp, hit, _, _ := c.Get("-", domains[j], dns.TypeA)
			if !hit {
				b.Fatal("cache miss")
			}
			h.writeResponse(w, reqs[j], resp)
			i++
		}
	})
}

// BenchmarkCacheHitWireFullParallel 新完整命中路径（并发）
func BenchmarkCacheHitWireFullParallel(b *testing.B) {
	c, domains := newBenchCache(b)
	reqs := benchReqs(domains)
	h := &RefactoredHandler{}
	w := dns.ResponseWriter(benchWriter{network: "udp"})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			j := i & (benchDomainCount - 1)
			s, ok := c.GetServe("-", domains[j], dns.TypeA)
			if !ok {
				b.Fatal("cache miss")
			}
			h.serveCacheHit(w, reqs[j], s)
			i++
		}
	})
}
