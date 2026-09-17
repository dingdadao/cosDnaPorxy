package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// proxyQuery 使用查询优化器执行并发DNS查询（支持多种优化器）
func (h *RefactoredHandler) proxyQuery(req *dns.Msg, upstreams []string) (*dns.Msg, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream servers available")
	}

	// 根据优化器类型选择查询方法
	var result *ConcurrentQueryResult

	if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(req, upstreams)
	} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(req, upstreams)
	} else {
		return nil, errors.New("unknown query optimizer type")
	}

	// 优先返回有效结果给客户端，如果没有有效结果才返回最快结果
	if result.HasSuccess && result.SuccessResult != nil && result.SuccessResult.Response != nil {
		// 有有效结果，优先返回成功结果
		return result.SuccessResult.Response, nil
	}

	// 没有有效结果，尝试使用备份DNS服务器
	if h.config.BackupDNS != "" {
		h.Logger.Debug("🔄 所有上游服务器查询失败，尝试使用备份DNS", map[string]interface{}{
			"backup_dns": h.config.BackupDNS,
		})
		// 使用备份DNS进行单个服务器查询
		backupResult := h.querySingleServer(req, h.config.BackupDNS)
		if backupResult != nil && backupResult.Response != nil && backupResult.Error == nil {
			h.Logger.Debug("✅ 备份DNS查询成功", map[string]interface{}{
				"backup_dns": h.config.BackupDNS,
			})
			return backupResult.Response, nil
		}
		h.Logger.Debug("❌ 备份DNS查询也失败", map[string]interface{}{
			"backup_dns": h.config.BackupDNS,
			"error":      backupResult.Error,
		})
	}

	// 没有有效结果，返回最快结果（可能是错误）
	if result.FastestResult == nil || result.FastestResult.Error != nil {
		if result.FastestResult != nil {
			return nil, result.FastestResult.Error
		}
		return nil, errors.New("all upstream queries failed")
	}

	return result.FastestResult.Response, nil
}

// proxyQueryWithCaching 代理查询并缓存原始上游响应
// 云检测统一在processQuery中执行（仅一次），此处只做查询+缓存，不再处理CNAME或检测云
func (h *RefactoredHandler) proxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16) (*dns.Msg, error) {
	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query_detailed")

	if len(upstreams) == 0 {
		upstreamTimer.End() // 确保计时器关闭
		return nil, errors.New("no upstream servers available")
	}

	// 根据优化器类型选择查询方法
	var result *ConcurrentQueryResult

	if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(req, upstreams)
	} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(req, upstreams)
	} else {
		upstreamTimer.End() // 确保计时器关闭
		return nil, errors.New("unknown query optimizer type")
	}

	// 获取上游查询时间
	upstreamTime := upstreamTimer.End()

	// 有成功结果：缓存原始响应（负缓存TTL由cacheManager.Set按RFC 2308处理）并返回
	if result.HasSuccess && result.SuccessResult != nil && result.SuccessResult.Response != nil {
		resp := result.SuccessResult.Response
		h.cacheManager.Set(domain, qtype, resp, false)
		h.Logger.Debug("✅ 上游查询成功并缓存原始响应", map[string]interface{}{
			"domain":         domain,
			"qtype":          dns.TypeToString[qtype],
			"success_server": result.SuccessResult.Server,
			"rcode":          dns.RcodeToString[resp.Rcode],
			"answers":        len(resp.Answer),
			"upstream_time":  upstreamTime,
		})
		return resp, nil
	}

	// 没有有效结果，返回最快结果（可能是错误）
	if result.FastestResult != nil {
		if result.FastestResult.Error != nil {
			return nil, result.FastestResult.Error
		}
		if result.FastestResult.Response != nil {
			return result.FastestResult.Response, nil
		}
	}

	return nil, errors.New("all upstream queries failed")
}

// ValidateDNSResult 验证查询结果是否包含有效的 DNS 记录
func (h *RefactoredHandler) ValidateDNSResult(result *ConcurrentQueryResult) (bool, string) {
	if result == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "result == nil"})
		return false, "result == nil"
	}
	if result.SuccessResult == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "SuccessResult == nil"})
		return false, "SuccessResult == nil"
	}
	r := result.SuccessResult
	if r.Error != nil {
		h.Logger.Debug("DNS 响应错误", map[string]interface{}{"error": r.Error.Error()})
		return false, r.Error.Error()
	}
	if r.Response == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "Response == nil"})
		return false, "Response == nil"
	}
	resp := r.Response
	if resp.Rcode != dns.RcodeSuccess {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "Rcode != Success", "rcode": resp.Rcode})
		return false, fmt.Sprintf("Rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		// 根据DNS NOERROR空答案处理规范，当DNS查询返回NOERROR但Answer为空时，
		// 表示域名存在但无请求的记录类型，此响应应被视为有效并进行缓存
		h.Logger.Debug("DNS NOERROR空答案响应", map[string]interface{}{"reason": "Answer 为空但rcode为success"})
		// 返回true表示这是一个有效的响应，需要缓存
		return true, "NOERROR空答案响应有效"
	}

	h.Logger.Debug("DNS 验证成功", map[string]interface{}{"answer_count": len(resp.Answer)})
	return true, "验证成功"
}

// ValidateNonIPDNSResult 验证非IP记录DNS查询结果
func (h *RefactoredHandler) ValidateNonIPDNSResult(result *ConcurrentQueryResult) (bool, string) {
	if result == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "result == nil"})
		return false, "result == nil"
	}
	if result.FastestResult == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "FastestResult == nil"})
		return false, "FastestResult == nil"
	}

	r := result.FastestResult
	if r.Error != nil {
		h.Logger.Debug("非IP记录DNS响应错误", map[string]interface{}{"error": r.Error.Error()})
		return false, r.Error.Error()
	}
	if r.Response == nil {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "Response == nil"})
		return false, "Response == nil"
	}
	resp := r.Response
	if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
		h.Logger.Debug("非IP记录DNS验证失败", map[string]interface{}{"reason": "Rcode != Success and Rcode != NameError", "rcode": resp.Rcode})
		return false, fmt.Sprintf("Rcode=%d", resp.Rcode)
	}
	// 对于非IP记录，即使Answer为空也被视为有效响应（如NOERROR响应）
	h.Logger.Debug("非IP记录DNS验证成功", map[string]interface{}{"answer_count": len(resp.Answer), "rcode": dns.RcodeToString[resp.Rcode]})
	return true, "验证成功"
}

// IsValidDNSResult 只返回 bool
func (h *RefactoredHandler) IsValidDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateDNSResult(result)
	return ok
}

// IsValidNonIPDNSResult 验证非IP记录DNS结果
func (h *RefactoredHandler) IsValidNonIPDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateNonIPDNSResult(result)
	return ok
}

// querySingleServer 查询单个DNS服务器
func (h *RefactoredHandler) querySingleServer(req *dns.Msg, server string) *QueryResult {
	start := time.Now()

	var resp *dns.Msg
	var err error
	var protocol string
	var timeout time.Duration

	// 根据URL scheme选择协议和超时时间
	if strings.HasPrefix(server, "udp://") {
		protocol = "UDP"
		timeout = h.config.Timeout // 传统协议使用普通超时
		resp, err = h.queryUDP(req, server)
	} else if strings.HasPrefix(server, "tcp://") {
		protocol = "TCP"
		timeout = h.config.Timeout // 传统协议使用普通超时
		resp, err = h.queryTCP(req, server)
	} else if strings.HasPrefix(server, "https://") {
		protocol = "DoH"
		timeout = h.config.ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoH(req, server)
	} else if strings.HasPrefix(server, "tls://") {
		protocol = "DoT"
		timeout = h.config.ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoT(req, server)
	} else if strings.HasPrefix(server, "h3://") {
		protocol = "DoH3"
		timeout = h.config.ModernTimeout // 现代协议使用更短超时
		resp, err = h.queryDoH3(req, server)
	} else {
		// 兼容旧格式：传统UDP/TCP
		protocol = "UDP/TCP"
		timeout = h.config.Timeout
		resp, err = h.queryTraditional(req, server)
	}

	result := &QueryResult{
		Response:     resp,
		Server:       server,
		ResponseTime: time.Since(start),
		Error:        err,
	}

	if err == nil && resp != nil {
		h.Logger.Debug("✅ 备份DNS查询成功", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"time":           result.ResponseTime.String(),
			"timeout_config": timeout.String(),
			"answers":        len(resp.Answer),
			"rcode":          dns.RcodeToString[resp.Rcode],
		})
	} else if err != nil {
		h.Logger.Debug("❌ 备份DNS查询失败", map[string]interface{}{
			"server":         server,
			"protocol":       protocol,
			"timeout_config": timeout.String(),
			"error":          err.Error(),
		})
	}

	return result
}

// queryUDP 执行UDP DNS查询
func (h *RefactoredHandler) queryUDP(req *dns.Msg, server string) (*dns.Msg, error) {
	// 移除udp://前缀
	addr := strings.TrimPrefix(server, "udp://")

	// 使用连接池获取客户端
	client := h.udpConnPool.GetClient(addr, h.config.Timeout)

	// 确保在函数结束时归还客户端到池中
	defer func() {
		h.udpConnPool.PutClient(addr)
	}()

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryTCP 执行TCP DNS查询
func (h *RefactoredHandler) queryTCP(req *dns.Msg, server string) (*dns.Msg, error) {
	// 移除tcp://前缀
	addr := strings.TrimPrefix(server, "tcp://")

	// 使用连接池获取客户端
	client := h.tcpConnPool.GetClient(addr, h.config.Timeout)

	// 确保在函数结束时归还客户端到池中
	defer func() {
		h.tcpConnPool.PutClient(addr)
	}()

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryDoH 执行DoH DNS查询
func (h *RefactoredHandler) queryDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用连接池获取HTTP客户端
	client := h.dohConnPool.GetClient(server)

	// 解析URL
	u, err := url.Parse(server)
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
	ctx, cancel := context.WithTimeout(context.Background(), h.config.ModernTimeout)
	defer cancel()

	// 创建HTTP请求
	httpReq, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(wireData))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// 设置DoH头部
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// 发送请求
	httpResp, err := client.Do(httpReq)
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

// queryDoT 执行DoT DNS查询
func (h *RefactoredHandler) queryDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用连接池获取DoT连接
	ctx := context.Background()
	conn, err := h.dotConnPool.GetConn(ctx, server)
	if err != nil {
		h.Logger.Error("获取DoT连接失败", map[string]interface{}{
			"server": server,
			"error":  err,
		})
		return nil, err
	}

	// 确保在函数结束时归还连接到池中
	defer func() {
		h.dotConnPool.PutConn(conn)
	}()

	// 使用TLS连接创建dns.Conn并执行查询
	dnsConn := &dns.Conn{Conn: conn.tlsConn}
	err = dnsConn.WriteMsg(req)
	if err != nil {
		h.Logger.Error("DoT写入请求失败", map[string]interface{}{
			"server": server,
			"error":  err,
		})
		return nil, err
	}

	resp, err := dnsConn.ReadMsg()
	if err != nil {
		h.Logger.Error("DoT读取响应失败", map[string]interface{}{
			"server": server,
			"error":  err,
		})
		return nil, err
	}

	return resp, nil
}

// queryDoH3 执行DoH3 DNS查询
func (h *RefactoredHandler) queryDoH3(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用SimpleModernOptimizer的方法
	optimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer)
	if !ok {
		return nil, fmt.Errorf("not a SimpleModernOptimizer")
	}
	return optimizer.queryDoH3(req, server)
}

// queryTraditional 执行传统DNS查询
func (h *RefactoredHandler) queryTraditional(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用SimpleModernOptimizer的方法
	optimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer)
	if !ok {
		return nil, fmt.Errorf("not a SimpleModernOptimizer")
	}
	return optimizer.queryTraditional(req, server)
}
