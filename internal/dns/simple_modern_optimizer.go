package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// SimpleModernOptimizer 简化的现代DNS查询优化器
type SimpleModernOptimizer struct {
	logger *utils.EnhancedLogger

	// 配置
	timeout        time.Duration // 传统协议超时时间
	modernTimeout  time.Duration // 现代协议超时时间
	retryCount     int
	enableFallback bool

	// HTTP客户端池
	httpClient *http.Client
	tlsConfig  *tls.Config

	// 连接缓存
	connCache map[string]interface{}
	cacheMu   sync.RWMutex
}

// NewSimpleModernOptimizer 创建简化的现代DNS查询优化器
func NewSimpleModernOptimizer(logger *utils.EnhancedLogger, timeout time.Duration, modernTimeout ...time.Duration) *SimpleModernOptimizer {
	// 现代协议超时，默认比传统协议更短
	modTimeout := timeout
	if len(modernTimeout) > 0 {
		modTimeout = modernTimeout[0]
	} else {
		// 默认现代协议是传统协议的3/4时间
		modTimeout = time.Duration(float64(timeout) * 0.75)
	}

	optimizer := &SimpleModernOptimizer{
		logger:         logger,
		timeout:        timeout,
		modernTimeout:  modTimeout,
		retryCount:     2,
		enableFallback: true,
		connCache:      make(map[string]interface{}),
	}

	// 初始化HTTP客户端
	optimizer.initHTTPClient()

	logger.Info("🚀 [简化现代DNS查询优化器初始化] ", map[string]interface{}{
		"rule":           "SIMPLE_MODERN_OPTIMIZER_INIT",
		"protocols":      []string{"udp", "tcp", "https", "tls", "h3"},
		"timeout":        timeout.String(),
		"modern_timeout": modTimeout.String(),
	})

	return optimizer
}

// initHTTPClient 初始化HTTP客户端
func (qo *SimpleModernOptimizer) initHTTPClient() {
	// 配置TLS
	qo.tlsConfig = &tls.Config{
		InsecureSkipVerify: false,
	}

	// HTTP客户端（支持HTTP/1.1, HTTP/2, 和部分HTTP/3）
	// 使用更短的超时时间给现代协议
	qo.httpClient = &http.Client{
		Timeout: qo.modernTimeout, // 使用现代协议超时
		Transport: &http.Transport{
			MaxIdleConns:          50,               // 减少空闲连接
			MaxIdleConnsPerHost:   5,                // 减少每个主机的空闲连接
			IdleConnTimeout:       30 * time.Second, // 更短的空闲超时
			TLSHandshakeTimeout:   qo.modernTimeout, // 使用现代协议超时
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       qo.tlsConfig,
			DisableKeepAlives:     true, // 禁用keep-alive，强制关闭连接
			DialContext: (&net.Dialer{
				Timeout:   qo.modernTimeout, // 连接超时
				KeepAlive: 0,                // 禁用TCP keep-alive
			}).DialContext,
		},
	}
}

// Query 执行并发DNS查询（简化版本）
func (qo *SimpleModernOptimizer) Query(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	if len(upstreams) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no upstream servers available"),
			},
			HasSuccess: false,
		}
	}

	return qo.concurrentQuery(req, upstreams)
}

// concurrentQuery 并发查询多个上游服务器
func (qo *SimpleModernOptimizer) concurrentQuery(req *dns.Msg, upstreams []string) *ConcurrentQueryResult {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), qo.timeout)
	defer cancel()

	// 过滤有效的上游服务器
	validUpstreams := qo.filterValidUpstreams(upstreams)
	if len(validUpstreams) == 0 {
		return &ConcurrentQueryResult{
			FastestResult: &QueryResult{
				Error: fmt.Errorf("no valid upstream servers after filtering"),
			},
			HasSuccess: false,
		}
	}

	// 创建结果通道
	resultChan := make(chan *QueryResult, len(validUpstreams))
	var wg sync.WaitGroup

	qo.logger.Debug("🚀 开始简化并发DNS查询", map[string]interface{}{
		"total_upstreams": len(upstreams),
		"valid_upstreams": len(validUpstreams),
		"domain":          req.Question[0].Name,
	})

	// 并发查询所有有效的上游服务器
	for _, upstream := range validUpstreams {
		wg.Add(1)
		go func(server string) {
			// panic恢复机制
			defer func() {
				if r := recover(); r != nil {
					qo.logger.Error("💥 [简化DNS查询panic] ", map[string]interface{}{
						"rule":        "SIMPLE_DNS_QUERY_PANIC",
						"server":      server,
						"panic_msg":   fmt.Sprintf("%v", r),
						"stack_trace": string(debug.Stack()),
					})
					// 创建错误结果
					result := &QueryResult{
						Server:       server,
						Error:        fmt.Errorf("query panic: %v", r),
						ResponseTime: time.Since(start),
					}
					select {
					case resultChan <- result:
					case <-ctx.Done():
					}
				}
				wg.Done()
			}()

			result := qo.queryServer(req, server)
			select {
			case resultChan <- result:
			case <-ctx.Done():
				// 超时或取消
			}
		}(upstream)
	}

	// 启动一个 goroutine 等待所有查询完成后关闭通道
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果，优先处理有效结果
	var allResults []*QueryResult
	var fastestResult *QueryResult
	var successResult *QueryResult
	var fastestValidResult *QueryResult // 最快的有效结果
	var fastestTime time.Duration
	hasSuccess := false
	hasValidResponse := false

	// 从通道中收集结果，优先返回有效结果
	for result := range resultChan {
		allResults = append(allResults, result)

		// 记录最快的结果（无论成功失败）
		if fastestResult == nil {
			fastestResult = result
			fastestTime = result.ResponseTime
		}

		// 检查是否为有效响应
		if result.Error == nil && result.Response != nil {
			if result.Response.Rcode == dns.RcodeSuccess {
				result.IsSuccess = true

				// 记录第一个成功结果
				if !hasSuccess {
					successResult = result
					hasSuccess = true
				}

				// 检查是否有答案（更优先的结果）
				if len(result.Response.Answer) > 0 {
					if !hasValidResponse {
						fastestValidResult = result
						hasValidResponse = true
						qo.logger.Debug("🏆 发现第一个有效结果", map[string]interface{}{
							"server":  result.Server,
							"time":    result.ResponseTime.String(),
							"answers": len(result.Response.Answer),
							"rcode":   dns.RcodeToString[result.Response.Rcode],
						})
					}
				}
			}
		}
	}

	totalTime := time.Since(start)

	// 选择最优结果：有效结果 > 成功结果 > 最快结果
	var bestResult *QueryResult
	if hasValidResponse && fastestValidResult != nil {
		bestResult = fastestValidResult
		qo.logger.Debug("🏅 使用最优有效结果", map[string]interface{}{
			"server":  bestResult.Server,
			"answers": len(bestResult.Response.Answer),
		})
	} else if hasSuccess && successResult != nil {
		bestResult = successResult
		qo.logger.Debug("🥈 使用成功结果（无答案）", map[string]interface{}{
			"server": bestResult.Server,
			"rcode":  dns.RcodeToString[bestResult.Response.Rcode],
		})
	} else {
		bestResult = fastestResult
		serverName := "none"
		if bestResult != nil {
			serverName = bestResult.Server
		}
		qo.logger.Debug("🚔 使用最快结果（可能失败）", map[string]interface{}{
			"server": serverName,
		})
	}

	// 确保始终有 FastestResult，即使所有查询都失败
	if fastestResult == nil {
		fastestResult = &QueryResult{
			Error:        fmt.Errorf("all %d upstream queries failed", len(validUpstreams)),
			Server:       "none",
			ResponseTime: totalTime,
		}
	}

	// 记录统计信息
	if hasValidResponse && fastestValidResult != nil {
		qo.logger.Info("✅ 简化并发查询成功（有效结果）", map[string]interface{}{
			"fastest_server":      fastestResult.Server,
			"fastest_time":        fastestTime.String(),
			"valid_result_server": fastestValidResult.Server,
			"valid_result_time":   fastestValidResult.ResponseTime.String(),
			"valid_answers":       len(fastestValidResult.Response.Answer),
			"total_results":       len(allResults),
			"total_time":          totalTime.String(),
		})
	} else if hasSuccess && successResult != nil {
		qo.logger.Info("🥈 简化并发查询成功（无答案）", map[string]interface{}{
			"fastest_server": fastestResult.Server,
			"fastest_time":   fastestTime.String(),
			"success_server": successResult.Server,
			"success_time":   successResult.ResponseTime.String(),
			"total_results":  len(allResults),
			"total_time":     totalTime.String(),
		})
	} else {
		qo.logger.Warn("⚠️ 简化并发查询全部失败", map[string]interface{}{
			"fastest_server": fastestResult.Server,
			"fastest_time":   fastestTime.String(),
			"total_results":  len(allResults),
			"total_time":     totalTime.String(),
		})
	}

	// 返回结果：优先使用有效结果作为 SuccessResult
	var finalSuccessResult *QueryResult
	if hasValidResponse && fastestValidResult != nil {
		finalSuccessResult = fastestValidResult
	} else if hasSuccess && successResult != nil {
		finalSuccessResult = successResult
	}

	return &ConcurrentQueryResult{
		FastestResult:  fastestResult,      // 最快结果（可能是错误）
		SuccessResult:  finalSuccessResult, // 最优有效结果
		AllResults:     allResults,
		HasSuccess:     hasValidResponse || hasSuccess, // 有效结果或成功结果
		FastestTime:    fastestTime,
		TotalQueryTime: totalTime,
	}
}

// filterValidUpstreams 过滤有效的上游服务器
func (qo *SimpleModernOptimizer) filterValidUpstreams(upstreams []string) []string {
	var validUpstreams []string

	for _, upstream := range upstreams {
		if qo.isValidUpstream(upstream) {
			validUpstreams = append(validUpstreams, upstream)
		} else {
			qo.logger.Warn("⚠️ 跳过不支持的上游服务器", map[string]interface{}{
				"server": upstream,
				"reason": "unsupported_protocol_or_format",
			})
		}
	}

	return validUpstreams
}

// isValidUpstream 检查上游服务器是否有效
func (qo *SimpleModernOptimizer) isValidUpstream(upstream string) bool {
	// 支持的协议前缀
	supportedSchemes := []string{"udp://", "tcp://", "https://", "tls://", "h3://"}

	// 检查是否是URL格式
	for _, scheme := range supportedSchemes {
		if strings.HasPrefix(upstream, scheme) {
			return true
		}
	}

	// 兼容旧格式：IP:PORT 格式（自动识别为UDP）
	if strings.Contains(upstream, ":") && !strings.Contains(upstream, "://") {
		// 尝试解析为 host:port 格式
		if host, port, err := net.SplitHostPort(upstream); err == nil {
			// 简单验证
			if host != "" && port != "" {
				qo.logger.Debug("🔄 兼容旧格式，自动识别为UDP", map[string]interface{}{
					"server": upstream,
				})
				return true
			}
		}
	}

	return false
}

// queryServer 查询特定服务器（根据URL scheme自动选择协议）
func (qo *SimpleModernOptimizer) queryServer(req *dns.Msg, server string) *QueryResult {
	start := time.Now()

	var resp *dns.Msg
	var err error
	var protocol string
	var timeout time.Duration

	// 根据URL scheme选择协议和超时时间
	if strings.HasPrefix(server, "udp://") {
		protocol = "UDP"
		timeout = qo.timeout // 传统协议使用普通超时
		resp, err = qo.queryUDP(req, server)
	} else if strings.HasPrefix(server, "tcp://") {
		protocol = "TCP"
		timeout = qo.timeout // 传统协议使用普通超时
		resp, err = qo.queryTCP(req, server)
	} else if strings.HasPrefix(server, "https://") {
		protocol = "DoH"
		timeout = qo.modernTimeout // 现代协议使用更短超时
		resp, err = qo.queryDoH(req, server)
	} else if strings.HasPrefix(server, "tls://") {
		protocol = "DoT"
		timeout = qo.modernTimeout // 现代协议使用更短超时
		resp, err = qo.queryDoT(req, server)
	} else if strings.HasPrefix(server, "h3://") {
		protocol = "DoH3"
		timeout = qo.modernTimeout // 现代协议使用更短超时
		resp, err = qo.queryDoH3(req, server)
	} else {
		// 兼容旧格式：传统UDP/TCP
		protocol = "UDP/TCP"
		timeout = qo.timeout
		resp, err = qo.queryTraditional(req, server)
	}

	result := &QueryResult{
		Response:     resp,
		Server:       server,
		ResponseTime: time.Since(start),
		Error:        err,
	}

	if err == nil && resp != nil {
		qo.logger.Debug("✅ DNS查询成功", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"time":           result.ResponseTime.String(),
			"timeout_config": timeout.String(),
			"answers":        len(resp.Answer),
			"rcode":          dns.RcodeToString[resp.Rcode],
		})
	} else if err != nil {
		qo.logger.Debug("❌ DNS查询失败", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"timeout_config": timeout.String(),
			"error":          err.Error(),
		})
	}

	return result
}

// queryUDP 纯UDP查询
func (qo *SimpleModernOptimizer) queryUDP(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 解析URL (udp://1.1.1.1:53)
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP URL: %w", err)
	}

	// 构建地址
	address := u.Host
	if !strings.Contains(address, ":") {
		address += ":53" // 默认DNS端口
	}

	ctx, cancel := context.WithTimeout(context.Background(), qo.timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: qo.timeout,
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)
	return resp, err
}

// queryTCP 纯TCP查询
func (qo *SimpleModernOptimizer) queryTCP(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 解析URL (tcp://1.1.1.1:53)
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP URL: %w", err)
	}

	// 构建地址
	address := u.Host
	if !strings.Contains(address, ":") {
		address += ":53" // 默认DNS端口
	}

	ctx, cancel := context.WithTimeout(context.Background(), qo.timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "tcp",
		Timeout: qo.timeout,
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)
	return resp, err
}

// queryTraditional 传统UDP/TCP查询（兼容旧格式）
func (qo *SimpleModernOptimizer) queryTraditional(req *dns.Msg, server string) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), qo.timeout)
	defer cancel()

	// 优先尝试UDP
	client := &dns.Client{
		Net:     "udp",
		Timeout: qo.timeout,
	}

	resp, _, err := client.ExchangeContext(ctx, req, server)

	// UDP失败时尝试TCP（可能是响应太大）
	if err != nil && qo.enableFallback {
		client.Net = "tcp"
		resp, _, err = client.ExchangeContext(ctx, req, server)
	}

	return resp, err
}

// queryDoH DNS over HTTPS查询
func (qo *SimpleModernOptimizer) queryDoH(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 解析URL
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoH URL: %w", err)
	}

	// 如果没有路径，使用默认的/dns-query
	if u.Path == "" || u.Path == "/" {
		u.Path = "/dns-query"
	}

	// 将DNS消息编码为wireformat
	wireData, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// 创建带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), qo.modernTimeout)
	defer cancel()

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// 设置DoH头部
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")
	httpReq.Header.Set("Connection", "close") // 强制关闭连接

	// 发送请求
	httpResp, err := qo.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// 检查HTTP状态码
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request failed with status: %d", httpResp.StatusCode)
	}

	// 读取响应数据
	respData, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// 解析DNS响应
	resp := new(dns.Msg)
	if err := resp.Unpack(respData); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return resp, nil
}

// queryDoT DNS over TLS查询
func (qo *SimpleModernOptimizer) queryDoT(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 解析URL (tls://example.com:853)
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid DoT URL: %w", err)
	}

	// 构建地址
	address := u.Host
	if !strings.Contains(address, ":") {
		address += ":853" // 默认DoT端口
	}

	// 使用现代协议超时
	ctx, cancel := context.WithTimeout(context.Background(), qo.modernTimeout)
	defer cancel()

	// 配置TLS
	tlsConfig := &tls.Config{
		ServerName:         u.Hostname(),
		InsecureSkipVerify: false,
	}

	client := &dns.Client{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Timeout:   qo.modernTimeout, // 使用现代协议超时
	}

	resp, _, err := client.ExchangeContext(ctx, req, address)
	return resp, err
}

// queryDoH3 DNS over HTTP/3查询（简化版本，如果不支持HTTP/3则降级到HTTPS）
func (qo *SimpleModernOptimizer) queryDoH3(req *dns.Msg, serverURL string) (*dns.Msg, error) {
	// 将h3://转换为https://，因为大多数Go HTTP客户端会自动协商HTTP/3
	httpsURL := strings.Replace(serverURL, "h3://", "https://", 1)

	qo.logger.Debug("🔄 DoH3降级为DoH", map[string]interface{}{
		"original": serverURL,
		"fallback": httpsURL,
	})

	// 使用DoH查询（HTTP客户端会自动尝试HTTP/3如果支持的话）
	return qo.queryDoH(req, httpsURL)
}

// Close 关闭查询优化器
func (qo *SimpleModernOptimizer) Close() {
	qo.cacheMu.Lock()
	defer qo.cacheMu.Unlock()

	// 清理连接缓存
	for key, conn := range qo.connCache {
		if closer, ok := conn.(io.Closer); ok {
			closer.Close()
		}
		delete(qo.connCache, key)
	}

	qo.logger.Info("📪 [简化现代DNS查询优化器已关闭] ", map[string]interface{}{
		"rule": "SIMPLE_MODERN_OPTIMIZER_CLOSE",
	})
}
