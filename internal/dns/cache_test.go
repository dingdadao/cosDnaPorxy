package dns

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestCalculateCacheTTL(t *testing.T) {
	// 创建模拟配置
	config := &Config{
		Cache: CacheConfig{
			DNSTTLMin: 60 * time.Second,  // 1分钟
			DNSTTLMax: 3600 * time.Second, // 1小时
		},
	}

	handler := &Handler{
		config: config,
	}

	tests := []struct {
		name           string
		dnsResponse    *dns.Msg
		expectedTTL    time.Duration
		expectedLogMsg string
	}{
		{
			name: "DNS TTL在配置范围内，使用DNS TTL",
			dnsResponse: createDNSResponse(600), // 10分钟
			expectedTTL: 600 * time.Second,      // 10分钟
		},
		{
			name: "DNS TTL小于最小限制，使用最小限制",
			dnsResponse: createDNSResponse(30), // 30秒
			expectedTTL: 60 * time.Second,      // 1分钟（最小限制）
		},
		{
			name: "DNS TTL大于最大限制，使用最大限制",
			dnsResponse: createDNSResponse(7200), // 2小时
			expectedTTL: 3600 * time.Second,     // 1小时（最大限制）
		},
		{
			name: "无DNS响应，使用最小限制",
			dnsResponse: nil,
			expectedTTL: 60 * time.Second, // 1分钟（最小限制）
		},
		{
			name: "空响应，使用最小限制",
			dnsResponse: &dns.Msg{},
			expectedTTL: 60 * time.Second, // 1分钟（最小限制）
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := handler.calculateCacheTTL(tt.dnsResponse)
			assert.Equal(t, tt.expectedTTL, ttl)
		})
	}
}

func TestCalculateCacheTTLWithDefaultConfig(t *testing.T) {
	// 测试默认配置（未设置DNSTTLMin和DNSTTLMax）
	config := &Config{
		Cache: CacheConfig{},
	}

	handler := &Handler{
		config: config,
	}

	tests := []struct {
		name        string
		dnsResponse *dns.Msg
		expectedTTL time.Duration
	}{
		{
			name:        "默认配置，无响应",
			dnsResponse: nil,
			expectedTTL: 30 * time.Second, // 默认30秒
		},
		{
			name:        "默认配置，DNS TTL 600秒",
			dnsResponse: createDNSResponse(600),
			expectedTTL: 600 * time.Second, // 使用DNS TTL
		},
		{
			name:        "默认配置，DNS TTL 20秒（小于默认最小30秒）",
			dnsResponse: createDNSResponse(20),
			expectedTTL: 30 * time.Second, // 使用默认最小30秒
		},
		{
			name:        "默认配置，DNS TTL 5000秒（大于默认最大3600秒）",
			dnsResponse: createDNSResponse(5000),
			expectedTTL: 3600 * time.Second, // 使用默认最大3600秒
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ttl := handler.calculateCacheTTL(tt.dnsResponse)
			assert.Equal(t, tt.expectedTTL, ttl)
		})
	}
}

// createDNSResponse 创建模拟DNS响应
func createDNSResponse(ttl uint32) *dns.Msg {
	msg := &dns.Msg{}
	msg.Answer = append(msg.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP("192.168.1.1"),
	})
	return msg
} 