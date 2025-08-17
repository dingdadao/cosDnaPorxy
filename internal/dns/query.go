package dns

import (
	"bytes"
	"compress/gzip"
	"context"
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
)

// queryDoH 通过DoH协议查询DNS
// 增加参数: isCN，true表示国内分流，false表示国外分流
func (h *Handler) queryDoH(req *dns.Msg, dohURL string, isCN bool) (*dns.Msg, error) {
	var dohConf config.DoHConfig
	if isCN {
		dohConf = h.config.DoH.CN
	} else {
		dohConf = h.config.DoH.NotCN
	}
	if !dohConf.Enabled {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "DoH not enabled", nil)
	}

	parsedURL, err := url.Parse(dohURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}
	host := parsedURL.Hostname()
	if host == "" {
		return nil, fmt.Errorf("invalid DoH URL hostname")
	}

	resolverIP, err := h.resolveDoHHostname(host, isCN)
	if err != nil {
		h.logger.Warn("无法解析DoH域名", "host", host, "err", err)
		return nil, err
	}

	// IPv6 地址加中括号处理
	if ip := net.ParseIP(resolverIP); ip != nil && ip.To4() == nil {
		resolverIP = "[" + resolverIP + "]"
	}

	// 提取端口或使用默认 443
	port := parsedURL.Port()
	if port == "" {
		port = "443"
	}
	dialAddr := net.JoinHostPort(resolverIP, port)

	// 打包 DNS 查询
	dnsQuery, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	httpReq, err := http.NewRequest("POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "cosDnaProxy/1.0")
	httpReq.Header.Set("Accept-Encoding", "gzip")

	// 设置超时
	timeout, err := time.ParseDuration(dohConf.Timeout)
	if err != nil {
		h.logger.Warn("DoH 超时时间格式无效，使用默认值", "raw", dohConf.Timeout, "default", "5s")
		timeout = 5 * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// 所有 DoH 请求都定向到解析出的 IP 和端口
				return net.Dial(network, dialAddr)
			},
			TLSClientConfig: &tls.Config{
				ServerName: host, // 保证 TLS 证书校验通过
			},
		},
	}

	start := time.Now()
	resp, err := client.Do(httpReq)
	duration := time.Since(start)

	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w (耗时: %v)", err, duration)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d (耗时: %v)", resp.StatusCode, duration)
	}

	// 是否是 gzip 响应
	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return dnsResp, nil
}

// resolveDoHHostname 解析DoH域名，isCN区分国内/国外
func (h *Handler) resolveDoHHostname(hostname string, isCN bool) (string, error) {
	var dohConf config.DoHConfig
	if isCN {
		dohConf = h.config.DoH.CN
	} else {
		dohConf = h.config.DoH.NotCN
	}
	// 创建DNS查询
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	c := &dns.Client{
		Timeout: 3 * time.Second,
		Net:     "udp",
	}

	resp, _, err := c.Exchange(req, dohConf.Resolver)
	if err != nil {
		return "", fmt.Errorf("failed to resolve DoH hostname: %w", err)
	}

	if resp == nil || len(resp.Answer) == 0 {
		return "", fmt.Errorf("no answer for DoH hostname")
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("no A record found for DoH hostname")
}

// queryDoHWithPool 使用连接池的DoH查询
func (h *Handler) queryDoHWithPool(req *dns.Msg, dohURL string, isCN bool) (*dns.Msg, error) {
	return h.queryDoHWithContext(context.Background(), req, dohURL, isCN)
}

// queryDoHWithContext 支持上下文取消的DoH查询
func (h *Handler) queryDoHWithContext(ctx context.Context, req *dns.Msg, dohURL string, isCN bool) (*dns.Msg, error) {
	var dohConf config.DoHConfig
	if isCN {
		dohConf = h.config.DoH.CN
	} else {
		dohConf = h.config.DoH.NotCN
	}

	if !dohConf.Enabled {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "DoH not enabled", nil)
	}

	// 从连接池获取HTTP客户端
	client := h.dohPool.GetClient(dohURL)

	// 构建DNS查询数据
	dnsQuery, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, "POST", dohURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// 设置请求头
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("User-Agent", "cosDnaProxy/1.0")

	// 发送请求
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 检查HTTP状态码
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %s", httpResp.Status)
	}

	// 读取响应体
	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// 再次检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 解析DNS响应
	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return resp, nil
}







// querySingleServer 查询单个DNS服务器
func (h *Handler) querySingleServer(req *dns.Msg, server string) (*dns.Msg, error) {
	return h.querySingleServerWithContext(context.Background(), req, server)
}

// querySingleServerWithContext 支持上下文取消的DNS查询
func (h *Handler) querySingleServerWithContext(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	var resp *dns.Msg
	var err error

	start := time.Now()

	// 检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if strings.HasPrefix(server, "https://") {
		// DoH 查询 - 使用连接池
		isCN := h.isCNUpstream(server)
		resp, err = h.queryDoHWithContext(ctx, req, server, isCN)
	} else if strings.HasPrefix(server, "tls://") {
		// DoT 查询 - 使用标准库，简化逻辑
		network, timeout := h.getNetworkAndTimeout(server)
		c := &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		serverAddr := h.getServerAddress(server)
		resp, _, err = c.ExchangeContext(ctx, req, serverAddr)
	} else {
		// UDP/TCP 查询 - 保持原有逻辑
		network, timeout := h.getNetworkAndTimeout(server)
		c := &dns.Client{
			Timeout: timeout,
			Net:     network,
		}
		serverAddr := h.getServerAddress(server)
		resp, _, err = c.ExchangeContext(ctx, req, serverAddr)
	}

	latency := time.Since(start)
	h.metrics.GetUpstreamLatency().Observe(latency.Seconds())

	// 再次检查上下文是否已取消
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if err != nil {
		h.logger.Debug("DNS查询失败 %s: %v (耗时: %v)", server, err, latency)
		return nil, err
	}

	if resp == nil {
		h.logger.Debug("DNS服务器 %s 返回空响应 (耗时: %v)", server, latency)
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "empty response from server", nil)
	}

	if resp.Rcode != dns.RcodeSuccess {
		h.logger.Debug("DNS服务器 %s 返回错误码: %s (耗时: %v)",
			server, dns.RcodeToString[resp.Rcode], latency)
	}

	h.logger.Debug("DNS查询成功 %s: %s (耗时: %v)",
		server, dns.RcodeToString[resp.Rcode], latency)
	return resp, nil
}

// getNetworkAndTimeout 根据服务器地址获取网络协议和超时时间
func (h *Handler) getNetworkAndTimeout(server string) (network string, timeout time.Duration) {
	switch {
	case strings.HasPrefix(server, "https://"):
		return "https", 5 * time.Second
	case strings.HasPrefix(server, "tls://"):
		return "tcp-tls", 8 * time.Second  // 增加DoT超时时间
	case strings.HasPrefix(server, "tcp://"):
		return "tcp", 3 * time.Second
	case strings.HasPrefix(server, "udp://"):
		return "udp", 3 * time.Second
	default:
		return "udp", 3 * time.Second
	}
}

// getServerAddress 获取服务器地址（去除协议前缀）
func (h *Handler) getServerAddress(server string) string {
	switch {
	case strings.HasPrefix(server, "https://"):
		return server // DoH 保持原样
	case strings.HasPrefix(server, "tls://"):
		return strings.TrimPrefix(server, "tls://")
	case strings.HasPrefix(server, "tcp://"):
		return strings.TrimPrefix(server, "tcp://")
	case strings.HasPrefix(server, "udp://"):
		return strings.TrimPrefix(server, "udp://")
	default:
		return server
	}
}

// queryMultipleServers 并发查询多个DNS服务器，选择最快的有效响应
// 高性能版本：无健康检查阻塞，直接并发查询所有服务器
func (h *Handler) queryMultipleServers(req *dns.Msg, servers []string) (*dns.Msg, error) {
	// 首先检查缓存
	if cachedResp, found := h.getCachedResponse(req); found {
		h.logger.Debug("缓存命中，直接返回")
		return cachedResp, nil
	}

	// 直接使用原始服务器列表，并发查询所有

	type result struct {
		resp    *dns.Msg
		err     error
		server  string
		latency time.Duration
	}

	// 创建结果通道和取消上下文
	resultChan := make(chan result, len(servers))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // 确保所有goroutine都能被取消

	// 记录活跃的查询数量
	activeQueries := int32(len(servers))

	// 并发查询所有服务器，不再进行健康检查
	h.logger.Debug("并发查询 %d 个上游服务器", len(servers))

	for _, server := range servers {
		go func(srv string) {
			defer func() {
				// 减少活跃查询计数
				if atomic.AddInt32(&activeQueries, -1) == 0 {
					// 最后一个查询完成，关闭结果通道
					close(resultChan)
				}
			}()

			start := time.Now()
			resp, err := h.querySingleServerWithContext(ctx, req, srv)
			latency := time.Since(start)

			// 检查上下文是否已取消
			select {
			case <-ctx.Done():
				// 查询被取消，不发送结果
				h.logger.Debug("查询被取消: %s", srv)
				return
			default:
				// 查询完成，发送结果
				select {
				case resultChan <- result{
					resp:    resp,
					err:     err,
					server:  srv,
					latency: latency,
				}:
					h.logger.Debug("查询完成: %s (耗时: %v)", srv, latency)
				default:
					// 通道已满，忽略结果
				}
			}
		}(server)
	}

	// 等待第一个成功响应或所有服务器都失败
	var lastError error
	timeout := time.After(10 * time.Second) // 增加超时时间，给DoT服务器更多机会
	successCount := 0

	for {
		select {
		case res, ok := <-resultChan:
			if !ok {
				// 所有查询都完成了
				if lastError != nil {
					return nil, lastError
				}
				return nil, utils.NewDNSError(dns.RcodeServerFailure, "all upstream servers failed", nil)
			}

			if res.err == nil && res.resp != nil && res.resp.Rcode == dns.RcodeSuccess {
				// 获取到成功响应，取消其他查询
				h.logger.Debug("选择最快的DNS响应: %s (耗时: %v)", res.server, res.latency)

				// 缓存结果（使用配置的TTL时间）
				h.setCachedResponse(req, res.resp)

				// 取消其他查询，释放资源
				cancel()

				return res.resp, nil
			}

			lastError = res.err
			successCount++

		case <-timeout:
			h.logger.Warn("DNS查询超时，已查询 %d 个服务器", successCount)
			cancel() // 取消所有查询
			return nil, utils.NewDNSError(dns.RcodeServerFailure, "query timeout", nil)
		}

		// 如果所有查询都完成了，退出循环
		if successCount >= len(servers) {
			break
		}
	}

	// 所有服务器都失败了
	if lastError != nil {
		return nil, lastError
	}

	return nil, utils.NewDNSError(dns.RcodeServerFailure, "all upstream servers failed", nil)
}

// proxyQuery 代理查询 - 优化版本：直接并发查询所有服务器
func (h *Handler) proxyQuery(req *dns.Msg, upstream []string) (*dns.Msg, error) {
	if len(upstream) == 0 {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "no upstream servers configured", nil)
	}

	// 直接并发查询所有上游服务器，不再进行健康检查
	// 健康检查改为异步后台进行，不影响查询性能
	resp, err := h.queryMultipleServers(req, upstream)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// resolveViaDesignatedDNS 通过指定DNS解析
func (h *Handler) resolveViaDesignatedDNS(req *dns.Msg, dnsServer string) (*dns.Msg, error) {
	// 根据服务器地址判断协议类型
	network, timeout := h.getNetworkAndTimeout(dnsServer)
	c := &dns.Client{
		Net:     network,
		Timeout: timeout,
	}

	resp, _, err := c.Exchange(req, dnsServer)
	if err != nil {
		return nil, utils.NewDNSError(dns.RcodeServerFailure, "designated DNS query failed", err)
	}
	return resp, nil
}

// recordServerPerformance 简单记录服务器性能（用于日志）
func (h *Handler) recordServerPerformance(server string, latency time.Duration) {
	// 简单记录到日志，不进行复杂统计
	h.logger.Debug("服务器 %s 查询完成，耗时: %v", server, latency)
} 