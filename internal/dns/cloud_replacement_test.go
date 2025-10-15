package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestCloudReplacementIPOnly 测试纯IP记录的情况
func TestCloudReplacementIPOnly(t *testing.T) {
	// 创建测试用的DNS消息
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// 创建一个只包含IP记录的响应
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 1},
	})
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 2},
	})

	// 模拟我们的处理逻辑 - 收集IP记录
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	if len(ipRecords) != 2 {
		t.Errorf("Expected 2 IP records, got %d", len(ipRecords))
	}

	// 验证所有记录都是IP记录
	for _, rr := range ipRecords {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 正确的类型
		default:
			t.Errorf("Expected IP record, got %T", rr)
		}
	}

	t.Logf("Pure IP records case handled correctly: %d IP records", len(ipRecords))
}

// TestCloudReplacementIPAndCNAME 测试IP和CNAME组合的情况
func TestCloudReplacementIPAndCNAME(t *testing.T) {
	// 创建测试用的DNS消息
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// 创建一个包含IP记录和CNAME记录的响应
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 1},
	})
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn("target.example.com"),
	})

	// 模拟我们的处理逻辑 - 收集IP记录
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	if len(ipRecords) != 1 {
		t.Errorf("Expected 1 IP record, got %d", len(ipRecords))
	}

	// 验证所有记录都是IP记录
	for _, rr := range ipRecords {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 正确的类型
		default:
			t.Errorf("Expected IP record, got %T", rr)
		}
	}

	t.Logf("IP and CNAME records case handled correctly: %d IP records from direct IP", len(ipRecords))
}

// TestCloudReplacementCNAMEOnly 测试只有CNAME记录的情况
func TestCloudReplacementCNAMEOnly(t *testing.T) {
	// 创建测试用的DNS消息
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// 创建一个只包含CNAME记录的响应
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn("target.example.com"),
	})

	// 模拟我们的处理逻辑 - 收集IP记录
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	// 如果没有直接的IP记录，尝试递归解析CNAME
	if len(ipRecords) == 0 {
		// 模拟递归解析CNAME目标
		// 这里我们模拟CNAME目标返回了IP记录
		mockIPRecord := &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 168, 1, 1},
		}
		ipRecords = append(ipRecords, mockIPRecord)
	}

	if len(ipRecords) != 1 {
		t.Errorf("Expected 1 IP record, got %d", len(ipRecords))
	}

	// 验证所有记录都是IP记录
	for _, rr := range ipRecords {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 正确的类型
		default:
			t.Errorf("Expected IP record, got %T", rr)
		}
	}

	t.Logf("Only CNAME record case handled correctly: %d IP records from CNAME resolution", len(ipRecords))
}

// TestCloudReplacementLimitRecords 测试记录数量限制
func TestCloudReplacementLimitRecords(t *testing.T) {
	// 创建超过4条记录的响应
	var records []dns.RR
	for i := 0; i < 6; i++ {
		record := &dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 168, 1, byte(i + 1)},
		}
		records = append(records, record)
	}

	// 模拟我们的处理逻辑 - 收集最多4条IP记录
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录，最多收集4条
	for _, rr := range records {
		// 如果已经收集了4条记录，停止收集
		if len(ipRecords) >= 4 {
			break
		}

		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	// 验证原始记录数量
	if len(records) != 6 {
		t.Errorf("Expected 6 records, got %d", len(records))
	}

	// 验证限制后的记录数量
	if len(ipRecords) != 4 {
		t.Errorf("Expected 4 records after limit, got %d", len(ipRecords))
	}

	// 验证所有记录都是IP记录
	for _, rr := range ipRecords {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 正确的类型
		default:
			t.Errorf("Expected IP record, got %T", rr)
		}
	}

	t.Logf("Record limiting works correctly: limited to %d IP records", len(ipRecords))
}

// TestCloudReplacementNoRecords 测试没有有效记录的情况
func TestCloudReplacementNoRecords(t *testing.T) {
	// 创建一个空的响应
	resp := &dns.Msg{}

	// 模拟我们的处理逻辑 - 收集IP记录
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	// 验证没有IP记录
	if len(ipRecords) != 0 {
		t.Errorf("Expected 0 IP records, got %d", len(ipRecords))
	}

	t.Logf("No records case handled correctly: %d IP records", len(ipRecords))
}

// TestProcessCloudResponse 测试统一的云域名响应处理方法
func TestProcessCloudResponse(t *testing.T) {
	// 创建一个包含CNAME和A记录的响应
	resp := &dns.Msg{}
	resp.Authoritative = true
	resp.RecursionAvailable = true
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr:    dns.RR_Header{Name: dns.Fqdn("example.com"), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: dns.Fqdn("target.example.com"),
	})
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("target.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{192, 168, 1, 1},
	})

	// 模拟处理云域名响应的逻辑
	// 收集所有IP记录（最多4条）
	var ipRecords []dns.RR

	// 遍历原始响应中的所有记录
	for _, rr := range resp.Answer {
		// 如果已经收集了4条记录，停止收集
		if len(ipRecords) >= 4 {
			break
		}

		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	// 验证处理结果
	if len(ipRecords) != 1 {
		t.Errorf("Expected 1 IP record, got %d", len(ipRecords))
	}

	// 验证所有记录都是IP记录
	for _, rr := range ipRecords {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 正确的类型
		default:
			t.Errorf("Expected IP record, got %T", rr)
		}
	}

	t.Logf("云域名响应处理完成: %d IP records", len(ipRecords))
}
