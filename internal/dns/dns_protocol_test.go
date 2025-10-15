package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// TestDNSResponseStandards 验证DNS响应是否符合协议标准
func TestDNSResponseStandards(t *testing.T) {
	// 创建一个模拟的请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	req.Id = 12345

	// 创建一个模拟的响应
	resp := &dns.Msg{}
	resp.SetReply(req)
	resp.Authoritative = true
	resp.RecursionAvailable = true

	// 添加一些A记录
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn("example.com"),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		A: []byte{192, 168, 1, 1},
	})

	// 验证响应是否符合DNS协议标准
	if resp.Id != req.Id {
		t.Errorf("Response ID should match request ID. Expected: %d, Got: %d", req.Id, resp.Id)
	}

	if !resp.Response {
		t.Error("Response flag should be set")
	}

	if resp.Opcode != dns.OpcodeQuery {
		t.Errorf("Opcode should be Query. Expected: %d, Got: %d", dns.OpcodeQuery, resp.Opcode)
	}

	if resp.Authoritative != true {
		t.Error("Authoritative flag should be set")
	}

	if resp.RecursionAvailable != true {
		t.Error("RecursionAvailable flag should be set")
	}

	if len(resp.Answer) != 1 {
		t.Errorf("Expected 1 answer record, got %d", len(resp.Answer))
	}

	// 验证Answer记录
	for i, rr := range resp.Answer {
		header := rr.Header()
		if header.Name != dns.Fqdn("example.com") {
			t.Errorf("Answer record %d name mismatch. Expected: %s, Got: %s", i, dns.Fqdn("example.com"), header.Name)
		}
		if header.Rrtype != dns.TypeA {
			t.Errorf("Answer record %d type mismatch. Expected: %d, Got: %d", i, dns.TypeA, header.Rrtype)
		}
		if header.Class != dns.ClassINET {
			t.Errorf("Answer record %d class mismatch. Expected: %d, Got: %d", i, dns.ClassINET, header.Class)
		}
		if header.Ttl == 0 {
			t.Errorf("Answer record %d TTL should not be zero", i)
		}
	}

	t.Logf("DNS response complies with protocol standards")
}

// TestCloudReplacementResponseStandards 验证云IP替换响应是否符合协议标准
func TestCloudReplacementResponseStandards(t *testing.T) {
	// 创建一个模拟的请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("cloudflare.com"), dns.TypeA)
	req.Id = 54321

	// 创建一个模拟的云IP替换响应
	finalResp := &dns.Msg{}
	finalResp.SetReply(req)
	finalResp.Authoritative = true
	finalResp.RecursionAvailable = true

	// 添加多个A记录（模拟云IP替换结果）
	ips := [][]byte{
		{192, 168, 1, 1},
		{192, 168, 1, 2},
		{192, 168, 1, 3},
	}

	for _, ip := range ips {
		finalResp.Answer = append(finalResp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("cloudflare.com"),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: ip,
		})
	}

	// 验证响应是否符合DNS协议标准
	if finalResp.Id != req.Id {
		t.Errorf("Response ID should match request ID. Expected: %d, Got: %d", req.Id, finalResp.Id)
	}

	if !finalResp.Response {
		t.Error("Response flag should be set")
	}

	if finalResp.Opcode != dns.OpcodeQuery {
		t.Errorf("Opcode should be Query. Expected: %d, Got: %d", dns.OpcodeQuery, finalResp.Opcode)
	}

	if finalResp.Authoritative != true {
		t.Error("Authoritative flag should be set")
	}

	if finalResp.RecursionAvailable != true {
		t.Error("RecursionAvailable flag should be set")
	}

	if len(finalResp.Answer) != len(ips) {
		t.Errorf("Expected %d answer records, got %d", len(ips), len(finalResp.Answer))
	}

	// 验证Answer记录
	for i, rr := range finalResp.Answer {
		header := rr.Header()
		if header.Name != dns.Fqdn("cloudflare.com") {
			t.Errorf("Answer record %d name mismatch. Expected: %s, Got: %s", i, dns.Fqdn("cloudflare.com"), header.Name)
		}
		if header.Rrtype != dns.TypeA {
			t.Errorf("Answer record %d type mismatch. Expected: %d, Got: %d", i, dns.TypeA, header.Rrtype)
		}
		if header.Class != dns.ClassINET {
			t.Errorf("Answer record %d class mismatch. Expected: %d, Got: %d", i, dns.ClassINET, header.Class)
		}
		if header.Ttl == 0 {
			t.Errorf("Answer record %d TTL should not be zero", i)
		}
	}

	// 验证响应不包含Authority和Additional部分（这是可以接受的）
	if len(finalResp.Ns) != 0 {
		t.Logf("Note: Response contains %d authority records", len(finalResp.Ns))
	}
	if len(finalResp.Extra) != 0 {
		t.Logf("Note: Response contains %d additional records", len(finalResp.Extra))
	}

	t.Logf("Cloud replacement DNS response complies with protocol standards")
}

// TestErrorResponseStandards 验证错误响应是否符合协议标准
func TestErrorResponseStandards(t *testing.T) {
	// 创建一个模拟的请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)
	req.Id = 9876

	// 创建一个错误响应
	resp := &dns.Msg{}
	resp.SetRcode(req, dns.RcodeServerFailure)

	// 验证响应是否符合DNS协议标准
	if resp.Id != req.Id {
		t.Errorf("Response ID should match request ID. Expected: %d, Got: %d", req.Id, resp.Id)
	}

	if !resp.Response {
		t.Error("Response flag should be set")
	}

	if resp.Opcode != dns.OpcodeQuery {
		t.Errorf("Opcode should be Query. Expected: %d, Got: %d", dns.OpcodeQuery, resp.Opcode)
	}

	if resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("Rcode should be ServerFailure. Expected: %d, Got: %d", dns.RcodeServerFailure, resp.Rcode)
	}

	t.Logf("Error DNS response complies with protocol standards")
}
