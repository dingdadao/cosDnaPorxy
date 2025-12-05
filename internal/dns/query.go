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
func (h *RefactoredHandler) proxyQueryWithCaching(req *dns.Msg, upstreams []string, domain string, qtype uint16, skipCloudDetection ...bool) (*dns.Msg, error) {
	if len(upstreams) == 0 {
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
		return nil, errors.New("unknown query optimizer type")
	}

	// 初始化返回给客户端的响应
	var responseToReturn *dns.Msg
	var errorToReturn error

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
			"type":           "success_result_processed",
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
			// 对于普通查询，不在此处进行任何处理，而是在processQuery中统一处理
			// 不处理CNAME记录，不缓存结果
			// 保持原始响应不变
		}
	}

	// 确定最终返回给客户端的响应
	if h.IsValidDNSResult(result) {
		// 有有效结果，记录处理后的结果
		h.Logger.Debug("✅ 处理后的查询结果", map[string]interface{}{
			"domain":         domain,
			"success_server": result.SuccessResult.Server,
			"success_time":   result.SuccessResult.ResponseTime.String(),
			"rcode":          dns.RcodeToString[responseToReturn.Rcode],
			"answers":        len(responseToReturn.Answer),
			"type":           "processed_query_result",
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
					"type":           "fastest_error_result",
				})
			} else {
				responseToReturn = result.FastestResult.Response
				h.Logger.Debug("⚠️ 返回最快结果（无成功结果）", map[string]interface{}{
					"domain":         domain,
					"fastest_server": result.FastestResult.Server,
					"fastest_time":   result.FastestResult.ResponseTime.String(),
					"type":           "fastest_result_no_success",
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
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{
			"reason": "result == nil",
			"type":   "dns_validation_failed",
		})
		return false, "result == nil"
	}
	if result.SuccessResult == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{
			"reason": "SuccessResult == nil",
			"type":   "dns_validation_failed",
		})
		return false, "SuccessResult == nil"
	}
	r := result.SuccessResult
	if r.Error != nil {
		h.Logger.Debug("DNS 响应错误", map[string]interface{}{
			"error": r.Error.Error(),
			"type":  "dns_response_error",
		})
		return false, r.Error.Error()
	}
	if r.Response == nil {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{
			"reason": "Response == nil",
			"type":   "dns_validation_failed",
		})
		return false, "Response == nil"
	}
	resp := r.Response
	if resp.Rcode != dns.RcodeSuccess {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{
			"reason": "Rcode != Success",
			"rcode":  resp.Rcode,
			"type":   "dns_validation_failed",
		})
		return false, fmt.Sprintf("Rcode=%d", resp.Rcode)
	}
	if len(resp.Answer) == 0 {
		h.Logger.Debug("DNS 验证失败", map[string]interface{}{
			"reason": "Answer 为空",
			"type":   "dns_validation_failed",
		})
		return false, "Answer 为空"
	}

	h.Logger.Debug("DNS 验证成功", map[string]interface{}{
		"answer_count": len(resp.Answer),
		"type":         "dns_validation_success",
	})
	return true, "验证成功"
}

// IsValidDNSResult 只返回 bool
func (h *RefactoredHandler) IsValidDNSResult(result *ConcurrentQueryResult) bool {
	ok, _ := h.ValidateDNSResult(result)
	return ok
}
