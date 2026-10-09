package dns

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// TestLiveDoH3 对**已运行**的实例做真实 HTTP/3 往返校验。
// 仅当设置 LIVE_DOH3_ADDR（如 127.0.0.1:8443）时执行，不设则跳过。
func TestLiveDoH3(t *testing.T) {
	addr := os.Getenv("LIVE_DOH3_ADDR")
	if addr == "" {
		t.Skip("未设置 LIVE_DOH3_ADDR，跳过实活实例 DoH3 校验")
	}
	path := os.Getenv("LIVE_DOH3_PATH")
	if path == "" {
		path = "/dns-query"
	}

	rt := &http3.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		QUICConfig:      &quic.Config{},
	}
	defer rt.Close()
	client := &http.Client{Timeout: 8 * time.Second, Transport: rt}

	m := new(dns.Msg)
	m.SetQuestion("www.qq.com.", dns.TypeA)
	wire, err := m.Pack()
	if err != nil {
		t.Fatalf("打包查询失败: %v", err)
	}

	resp, err := client.Post("https://"+addr+path, dohMediaType, bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("DoH3 请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DoH3 状态码 %d，期望 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)

	out := new(dns.Msg)
	if err := out.Unpack(body); err != nil {
		t.Fatalf("解包响应失败: %v", err)
	}
	if out.Rcode != dns.RcodeSuccess {
		t.Fatalf("响应码 %s，期望 NOERROR", dns.RcodeToString[out.Rcode])
	}
	if len(out.Answer) == 0 {
		t.Fatalf("响应无记录: %v", out)
	}
	t.Logf("DoH3 实网校验通过: HTTP/%s rcode=NOERROR answers=%d", resp.Proto, len(out.Answer))
}
