package dns

import (
	"cosDnaPorxy/internal/utils"
	"testing"

	"github.com/miekg/dns"
)

func TestReplaceDomainDetection(t *testing.T) {
	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建云服务检测器
	detector := NewCloudDetector(logger, nil)

	// 设置替换域名
	detector.cfReplaceDomain = "cf-cname.xingpingcn.top"
	detector.awsReplaceDomain = "cc.cloudfront.182682.xyz"

	// 测试Cloudflare替换域名
	result := detector.IsReplaceDomain("cf-cname.xingpingcn.top")
	if !result {
		t.Errorf("Expected cf-cname.xingpingcn.top to be recognized as replace domain")
	}

	// 测试AWS替换域名
	result = detector.IsReplaceDomain("cc.cloudfront.182682.xyz")
	if !result {
		t.Errorf("Expected cc.cloudfront.182682.xyz to be recognized as replace domain")
	}

	// 测试普通域名
	result = detector.IsReplaceDomain("www.example.com")
	if result {
		t.Errorf("Expected www.example.com not to be recognized as replace domain")
	}

	// 测试带点的替换域名
	result = detector.IsReplaceDomain("cf-cname.xingpingcn.top.")
	if !result {
		t.Errorf("Expected cf-cname.xingpingcn.top. to be recognized as replace domain")
	}

	t.Logf("Replace domain detection test completed")
}

func TestSkipCloudDetectionForReplaceDomains(t *testing.T) {
	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建云服务检测器
	detector := NewCloudDetector(logger, nil)

	// 设置替换域名
	detector.cfReplaceDomain = "cf-cname.xingpingcn.top"
	detector.awsReplaceDomain = "cc.cloudfront.182682.xyz"

	// 加载网络范围以便进行云检测
	detector.LoadNetworkRanges("./data/cf_mrs_file4.txt", "./data/cf_mrs_file6.txt", "./data/aws.txt")

	// 测试替换域名应该跳过云检测
	resp := &dns.Msg{}
	result := detector.DetectCloudService(resp, "cf-cname.xingpingcn.top")
	if result.Type != CloudTypeNone {
		t.Errorf("Expected no cloud detection for replace domain, got %v", result.Type)
	}

	// 测试普通域名应该进行云检测（使用一个已知的Cloudflare IP）
	resp = &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("www.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{104, 16, 0, 1}, // 这是一个已知的Cloudflare IP范围内的IP
	})

	result = detector.DetectCloudService(resp, "www.example.com")
	if result.Type == CloudTypeNone {
		t.Errorf("Expected cloudflare detection for regular domain")
	}

	t.Logf("Skip cloud detection for replace domains test completed")
}

func TestSkipCloudDetectionInAsyncRefresh(t *testing.T) {
	// 创建日志记录器
	logger := utils.NewEnhancedLogger("info", "test", false)

	// 创建云服务检测器
	detector := NewCloudDetector(logger, nil)

	// 设置替换域名
	detector.cfReplaceDomain = "cf-cname.xingpingcn.top"
	detector.awsReplaceDomain = "cc.cloudfront.182682.xyz"

	// 加载网络范围以便进行云检测
	detector.LoadNetworkRanges("./data/cf_mrs_file4.txt", "./data/cf_mrs_file6.txt", "./data/aws.txt")

	// 测试在异步刷新中，替换域名应该跳过云检测
	resp := &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("cf-cname.xingpingcn.top"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{104, 16, 0, 1}, // 这是一个Cloudflare IP，但在替换域名的情况下应该被忽略
	})

	result := detector.DetectCloudService(resp, "cf-cname.xingpingcn.top")
	if result.Type != CloudTypeNone {
		t.Errorf("Expected no cloud detection for replace domain in async refresh, got %v", result.Type)
	}

	// 测试在异步刷新中，普通域名应该进行云检测
	resp = &dns.Msg{}
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: dns.Fqdn("www.example.com"), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   []byte{104, 16, 0, 1}, // 这是一个Cloudflare IP
	})

	result = detector.DetectCloudService(resp, "www.example.com")
	if result.Type == CloudTypeNone {
		t.Errorf("Expected cloudflare detection for regular domain in async refresh")
	}

	t.Logf("Skip cloud detection in async refresh test completed")
}
