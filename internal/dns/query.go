package dns

import (
	"errors"
	"fmt"
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

// proxyQueryWithCaching 带智能缓存的查询（只缓存成功的结果）
func (h *RefactoredHandler) proxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16, skipCloudDetection ...bool) (*dns.Msg, error) {
	// 计时上游查询
	upstreamTimer := h.Logger.StartTimer("upstream_query_detailed")

	if len(upstreams) == 0 {
		upstreamTimer.End() // 确保计时器关闭
		return nil, errors.New("no upstream servers available")
	}

	// 检查是否应该跳过云服务检测
	shouldSkipCloudDetection := len(skipCloudDetection) > 0 && skipCloudDetection[0]

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

	// 初始化返回给客户端的响应
	var responseToReturn *dns.Msg
	var errorToReturn error

	// 获取上游查询时间
	upstreamTime := upstreamTimer.End()

	// 如果有成功的结果，先进行处理
	if result.HasSuccess && result.SuccessResult != nil {
		// 检查 fastest_server 是否为空
		fastestServer := "unknown"
		if result.FastestResult != nil {
			fastestServer = result.FastestResult.Server
		}

		h.Logger.Debug("💾 处理成功结果", map[string]interface{}{
			"domain":         domain,
			"qtype":          dns.TypeToString[qtype],
			"success_server": result.SuccessResult.Server,
			"fastest_server": fastestServer,
			"upstream_time":  upstreamTime,
		})

		// 设置初始响应
		responseToReturn = result.SuccessResult.Response

		// 只有在不跳过云服务检测时才进行云服务检测
		if shouldSkipCloudDetection {
			// 对于定向域名，跳过云服务检测，直接缓存结果
			// 处理CNAME记录
			processedResp := h.processDNSResponseWithCNAME(responseToReturn, domain, upstreams)
			h.cacheManager.Set(domain, qtype, processedResp, false)
			// 更新返回给客户端的响应
			responseToReturn = processedResp
		} else {
			// 检查是否为云服务
			detection := h.cloudDetector.DetectCloudService(result.SuccessResult.Response, domain)
			isCloud := detection.Type != CloudTypeNone

			if isCloud {
				// 对于云域名，使用专门的云域名处理方法
				cloudProcessedResp := h.processCloudResponse(result.SuccessResult.Response, domain)
				// 将整个域名标记为云服务域名（确保A/AAAA记录一致性）
				h.cacheManager.MarkDomainAsCloud(domain, qtype, int(detection.Type))
				// 更新返回给客户端的响应
				responseToReturn = cloudProcessedResp
				h.Logger.Debug("☁️ 云服务检测并处理完成", map[string]interface{}{
					"domain":        domain,
					"type":          detection.Type,
					"upstream_time": upstreamTime,
				})
			} else {
				// 对于普通域名，处理CNAME记录
				processedResp := h.processDNSResponseWithCNAME(responseToReturn, domain, upstreams)
				h.cacheManager.Set(domain, qtype, processedResp, isCloud)
				// 更新返回给客户端的响应
				responseToReturn = processedResp
			}
		}
	}

	// 确定最终返回给客户端的响应
	if h.IsValidDNSResult(result) {
		// 有有效结果，返回处理后的结果
		h.Logger.Debug("✅ 返回处理后的结果给客户端", map[string]interface{}{
			"domain":         domain,
			"success_server": result.SuccessResult.Server,
			"success_time":   result.SuccessResult.ResponseTime.String(),
			"rcode":          dns.RcodeToString[responseToReturn.Rcode],
			"answers":        len(responseToReturn.Answer),
			"upstream_time":  upstreamTime,
		})
	} else {
		// 没有有效结果，返回最快结果（可能是错误）
		if result.FastestResult != nil {
			if result.FastestResult.Error != nil {
				errorToReturn = result.FastestResult.Error
				h.Logger.Debug("❌ 返回最快错误结果", map[string]interface{}{
					"domain":         domain,
					"fastest_server": result.FastestResult.Server,
					"error":          result.FastestResult.Error.Error(),
					"upstream_time":  upstreamTime,
				})
			} else {
				responseToReturn = result.FastestResult.Response
				h.Logger.Debug("⚠️ 返回最快结果（无成功结果）", map[string]interface{}{
					"domain":         domain,
					"fastest_server": result.FastestResult.Server,
					"fastest_time":   result.FastestResult.ResponseTime.String(),
					"upstream_time":  upstreamTime,
				})
			}
		} else {
			errorToReturn = errors.New("all upstream queries failed")
		}
	}

	return responseToReturn, errorToReturn
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

	client := &dns.Client{
		Net:     "udp",
		Timeout: h.config.Timeout,
	}

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryTCP 执行TCP DNS查询
func (h *RefactoredHandler) queryTCP(req *dns.Msg, server string) (*dns.Msg, error) {
	// 移除tcp://前缀
	addr := strings.TrimPrefix(server, "tcp://")

	client := &dns.Client{
		Net:     "tcp",
		Timeout: h.config.Timeout,
	}

	resp, _, err := client.Exchange(req, addr)
	return resp, err
}

// queryDoH 执行DoH DNS查询
func (h *RefactoredHandler) queryDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用SimpleModernOptimizer的方法
	optimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer)
	if !ok {
		return nil, fmt.Errorf("not a SimpleModernOptimizer")
	}
	return optimizer.queryDoH(req, server)
}

// queryDoT 执行DoT DNS查询
func (h *RefactoredHandler) queryDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	// 使用SimpleModernOptimizer的方法
	optimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer)
	if !ok {
		return nil, fmt.Errorf("not a SimpleModernOptimizer")
	}
	return optimizer.queryDoT(req, server)
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
