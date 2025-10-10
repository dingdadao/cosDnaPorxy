package dns

import (
	"errors"
	"fmt"

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
func (h *RefactoredHandler) proxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16) (*dns.Msg, error) {
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

	// 如果有成功的结果，缓存它
	if result.HasSuccess && result.SuccessResult != nil {
		// 检查 fastest_server 是否为空
		fastestServer := "unknown"
		if result.FastestResult != nil {
			fastestServer = result.FastestResult.Server
		}

		h.Logger.Debug("💾 缓存成功结果", map[string]interface{}{
			"domain":         domain,
			"qtype":          dns.TypeToString[qtype],
			"success_server": result.SuccessResult.Server,
			"fastest_server": fastestServer,
		})

		// 检查是否为云服务
		detection := h.cloudDetector.DetectCloudService(result.SuccessResult.Response)
		isCloud := detection.Type != CloudTypeNone

		if isCloud {
			h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, isCloud, int(detection.Type))
		} else {
			h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, isCloud)
		}
	}

	// 优先返回有效结果给客户端，如果没有有效结果才返回最快结果
	var responseToReturn *dns.Msg
	var errorToReturn error

	if h.IsValidDNSResult(result) {
		// 有有效结果，优先返回成功结果
		responseToReturn = result.SuccessResult.Response
		h.Logger.Debug("✅ 返回成功结果给客户端", map[string]interface{}{
			"domain":         domain,
			"success_server": result.SuccessResult.Server,
			"success_time":   result.SuccessResult.ResponseTime.String(),
			"rcode":          dns.RcodeToString[result.SuccessResult.Response.Rcode],
			"answers":        len(result.SuccessResult.Response.Answer),
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
				})
			} else {
				responseToReturn = result.FastestResult.Response
				h.Logger.Debug("⚠️ 返回最快结果（无成功结果）", map[string]interface{}{
					"domain":         domain,
					"fastest_server": result.FastestResult.Server,
					"fastest_time":   result.FastestResult.ResponseTime.String(),
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
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{"reason": "Answer 为空"})
		return false, "Answer 为空"
	}

	h.Logger.Debug("DNS 验证成功", map[string]interface{}{"answer_count": len(resp.Answer)})
	return true, "验证成功"
}

// IsValidDNSResult 只返回 bool
func (h *RefactoredHandler) IsValidDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateDNSResult(result)
	return ok
}
