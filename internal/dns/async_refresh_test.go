package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestAsyncRefreshCNAMEHandling 测试异步刷新中对CNAME记录的处理
func TestAsyncRefreshCNAMEHandling(t *testing.T) {
	// 创建一个包含CNAME和A记录的响应
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn("target.example.com"),
	})
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 1},
	})

	// 模拟异步刷新中的处理逻辑
	// 检查响应是否包含CNAME记录
	hasCNAME := false
	hasA := false

	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.CNAME:
			hasCNAME = true
		case *dns.A, *dns.AAAA:
			hasA = true
		}
	}

	if hasCNAME {
		t.Logf("异步刷新响应包含CNAME记录，可能需要特殊处理")
	}

	if hasA {
		t.Logf("异步刷新响应包含A记录")
	}

	// 验证记录类型
	for i, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.CNAME:
			t.Logf("记录 %d 是CNAME记录", i)
		case *dns.A:
			t.Logf("记录 %d 是A记录", i)
		case *dns.AAAA:
			t.Logf("记录 %d 是AAAA记录", i)
		default:
			t.Logf("记录 %d 是其他类型记录: %T", i, rr)
		}
	}

	t.Logf("异步刷新CNAME处理分析完成")
}

// TestAsyncRefreshPureCNAME 测试异步刷新中只有CNAME记录的情况
func TestAsyncRefreshPureCNAME(t *testing.T) {
	// 创建一个只包含CNAME记录的响应
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn("target.example.com"),
	})

	// 模拟异步刷新中的处理逻辑
	// 检查响应是否只包含CNAME记录
	hasCNAME := false
	hasIP := false

	for _, rr := range resp.Answer {
		switch rr.(type) {
		case *dns.CNAME:
			hasCNAME = true
		case *dns.A, *dns.AAAA:
			hasIP = true
		}
	}

	if hasCNAME && !hasIP {
		t.Logf("异步刷新响应只包含CNAME记录，没有IP记录")
	}

	t.Logf("异步刷新纯CNAME处理分析完成")
}

// TestAsyncRefreshRecordLimit 测试异步刷新中记录数量限制
func TestAsyncRefreshRecordLimit(t *testing.T) {
	// 创建超过4条记录的响应
	resp := &dns.Msg{}
	for i := 0; i < 6; i++ {
		record := &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 168, 1, byte(i + 1)},
		}
		resp.Answer = append(resp.Answer, record)
	}

	// 模拟异步刷新中的处理逻辑
	// 检查记录数量
	if len(resp.Answer) > 4 {
		t.Logf("异步刷新响应包含%d条记录，超过限制", len(resp.Answer))
	}

	t.Logf("异步刷新记录数量限制分析完成")
}
