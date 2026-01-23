package dns

import (
	"fmt"
	"runtime/debug"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// RefreshHandler 处理异步刷新相关功能
type RefreshHandler struct {
	config         *config.Config
	logger         *utils.EnhancedLogger
	cacheManager   *CacheManager
	cloudDetector  *CloudDetector
	queryOptimizer interface{}
	matcherHandler *MatcherHandler
	proxyQuery     func(*dns.Msg, []string) (*dns.Msg, error)
}

// NewRefreshHandler 创建新的刷新处理器
func NewRefreshHandler(
	config *config.Config,
	logger *utils.EnhancedLogger,
	cacheManager *CacheManager,
	cloudDetector *CloudDetector,
	queryOptimizer interface{},
	matcherHandler *MatcherHandler,
	proxyQuery func(*dns.Msg, []string) (*dns.Msg, error),
) *RefreshHandler {
	return &RefreshHandler{
		config:         config,
		logger:         logger,
		cacheManager:   cacheManager,
		cloudDetector:  cloudDetector,
		queryOptimizer: queryOptimizer,
		matcherHandler: matcherHandler,
		proxyQuery:     proxyQuery,
	}
}

// RefreshDNSRecord 刷新DNS记录（缓存回调）
func (rh *RefreshHandler) RefreshDNSRecord(domain string, qtype uint16) error {
	// 添加顶层panic恢复机制
	defer func() {
		if r := recover(); r != nil {
			// 记录panic信息
			if rh != nil && rh.logger != nil {
				rh.logger.Error("💥 [异步刷新panic] ", map[string]interface{}{
					"rule":        "REFRESH_RECORD_PANIC",
					"domain":      domain,
					"qtype":       dns.TypeToString[qtype],
					"panic_msg":   fmt.Sprintf("%v", r),
					"stack_trace": string(debug.Stack()),
				})
			}

			// 即使发生panic，也要尝试延长缓存TTL以防止频繁刷新
			if rh != nil && rh.cacheManager != nil {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL/2)
			}
		}
	}()

	// 添加空指针检查
	if rh == nil {
		return fmt.Errorf("refresh handler is nil")
	}

	if rh.logger == nil {
		return fmt.Errorf("logger is nil")
	}

	// 检查是否为替换域名，如果是则直接返回，避免套娃
	if rh.cloudDetector.IsReplaceDomain(domain) {
		rh.logger.Debug("⏭️ 跳过异步刷新（替换域名）", map[string]interface{}{
			"domain": domain,
		})
		return nil
	}

	rh.logger.Info("🔄 [异步刷新开始] ", map[string]interface{}{
		"domain": domain,
		"qtype":  dns.TypeToString[qtype],
	})

	// 确定应该使用的上游DNS服务器（遵循相同的优先级规则）
	upstreams := rh.determineUpstreamsForDomain(domain)

	// 添加上游服务器检查
	if len(upstreams) == 0 {
		rh.logger.Warn("⚠️ [异步刷新警告] 未找到有效的上游服务器", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
				if rh.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf("no valid upstream servers found")
	}

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 添加请求检查
	if req == nil {
		rh.logger.Error("❌ [异步刷新失败] 请求对象为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 检查是否为替换域名，替换域名使用替换缓存时间，普通云域名使用普通缓存时间
				if rh.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用替换缓存时间
					replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
					if rh.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
					rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
				} else {
					// 普通云域名使用普通缓存时间
					rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
				}
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf("request object is nil")
	}

	// 使用类型断言调用不同类型的查询优化器
	var result *ConcurrentQueryResult
	if rh.queryOptimizer == nil {
		rh.logger.Error("❌ [异步刷新失败] 查询优化器未初始化", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
				if rh.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf("query optimizer is nil")
	}

	if modernOptimizer, ok := rh.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(req, upstreams)
	} else if traditionalOptimizer, ok := rh.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(req, upstreams)
	} else {
		rh.logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  "unknown query optimizer type",
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
				if rh.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf("unknown query optimizer type")
	}

	if result == nil {
		rh.logger.Error("❌ [异步刷新失败] 查询结果为空", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
		if rh.cacheManager != nil {
			// 检查域名级别的云服务状态来判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
				if rh.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf("query result is nil")
	}

	if result.FastestResult == nil || result.FastestResult.Error != nil {
		errorMsg := "all upstream queries failed"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			errorMsg = result.FastestResult.Error.Error()
		}
		rh.logger.Error("❌ [异步刷新失败] ", map[string]interface{}{
			"domain": domain,
			"error":  errorMsg,
		})
		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			// 直接从缓存中获取云域名信息，判断应该使用哪种TTL
			isDomainCloud := rh.cacheManager.IsDomainCloud(domain)
			if isDomainCloud {
				// 对于云域名，使用配置的替换缓存时间
				replaceCacheTime := rh.config.Cache.TTL // 默认使用缓存TTL
				if rh.config.ReplaceCacheTime != "" {
					if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
						replaceCacheTime = parsedTime
					}
				}
				rh.cacheManager.ExtendTTL(domain, qtype, replaceCacheTime)
			} else {
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL)
			}
		}
		return fmt.Errorf(errorMsg)
	}

	// 验证查询结果：必须有成功响应且包含实际答案记录
	if result.HasSuccess && result.SuccessResult != nil &&
		result.SuccessResult.Response != nil &&
		result.SuccessResult.Response.Rcode == dns.RcodeSuccess {

		// 添加缓存管理器检查
		if rh.cacheManager == nil {
			rh.logger.Error("❌ [异步刷新失败] 缓存管理器未初始化", map[string]interface{}{
				"domain": domain,
				"qtype":  dns.TypeToString[qtype],
			})
			return fmt.Errorf("cache manager is nil")
		}

		// 检查是否匹配定向域名
		dnsServer, isDesignated := rh.matcherHandler.GetYAMLMatcher().GetDesignatedDomainOrDefault(domain)

		if isDesignated {
			rh.logger.Info("🎯 [异步刷新-定向域名处理开始] ", map[string]interface{}{
				"domain": domain,
				"dns":    dnsServer,
			})

			// 对于定向域名，跳过云服务检测
			rh.logger.Info("⏭️ [异步刷新-跳过云服务检测] ", map[string]interface{}{
				"domain": domain,
				"reason": "designated_domain",
			})

			// 处理CNAME记录，使用定向域名指定的DNS服务器
			processedResp := processDNSResponseWithCNAME(rh.logger, result.SuccessResult.Response, domain, []string{dnsServer}, rh.proxyQuery)
			ensureMinimumTTL(processedResp, rh.config.Cache.TTL)
			rh.cacheManager.Set(domain, qtype, processedResp, false, 0)

			rh.logger.Debug("🔄 [异步刷新完成-定向域名] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"source":       "designated",
				"answer_count": len(processedResp.Answer),
				"upstreams":    []string{dnsServer},
			})
		} else {
			rh.logger.Info("🌐 [异步刷新-普通域名处理开始] ", map[string]interface{}{
				"domain": domain,
			})

			// 添加云检测器检查
			if rh.cloudDetector == nil {
				rh.logger.Error("❌ [异步刷新失败] 云检测器未初始化", map[string]interface{}{
					"domain": domain,
					"qtype":  dns.TypeToString[qtype],
				})
				rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL/2)
				return fmt.Errorf("cloud detector is nil")
			}

			// 检查是否为云服务
			rh.logger.Info("🔍 [异步刷新-云服务检测开始] ", map[string]interface{}{
				"domain": domain,
			})
			detection := rh.cloudDetector.DetectCloudService(result.SuccessResult.Response, domain)
			isCloud := detection.Type != CloudTypeNone
			cloudType := int(detection.Type)

			if isCloud {
				rh.logger.Info("☁️ [异步刷新-云服务检测结果] ", map[string]interface{}{
					"domain":     domain,
					"cloud_type": detection.Type,
				})

				// 将整个域名标记为云服务域名（确保A/AAAA记录一致性）
				rh.cacheManager.MarkDomainAsCloud(domain, qtype, cloudType)

				// 检查是否为替换域名，替换域名使用替换缓存时间，普通云域名使用普通缓存时间
				var replaceCacheTime time.Duration
				if rh.cloudDetector.IsReplaceDomain(domain) {
					// 替换域名使用替换缓存时间
					replaceCacheTime = rh.config.Cache.TTL // 默认使用缓存TTL
					if rh.config.ReplaceCacheTime != "" {
						if parsedTime, err := time.ParseDuration(rh.config.ReplaceCacheTime); err == nil {
							replaceCacheTime = parsedTime
						}
					}
				} else {
					// 普通云域名使用普通缓存时间
					replaceCacheTime = rh.config.Cache.TTL
				}

				// 使用统一的云域名响应处理方法，使用上游DNS服务器
				processedResponse := processCloudResponse(rh.logger, result.SuccessResult.Response, domain, rh.proxyQuery)

				// 确保云域名响应的TTL不小于适当的缓存时间
				ensureMinimumTTL(processedResponse, replaceCacheTime)
				// 只更新云响应缓存，不更新普通缓存
				rh.cacheManager.SetCloudResponse(domain, qtype, processedResponse, cloudType, replaceCacheTime)

				rh.logger.Debug("🔄 [异步刷新完成-云域名] ", map[string]interface{}{
					"domain":       domain,
					"qtype":        dns.TypeToString[qtype],
					"source":       "cloud",
					"cloud_type":   detection.Type,
					"answer_count": len(processedResponse.Answer),
					"upstreams":    upstreams,
				})
			} else {
				// 检查是否为中国域名（如果启用了中国域名检查）- 在云服务检测之后
				if rh.config.EnableChinaDomainCheck {
					rh.logger.Debug("🔍 [异步刷新-中国域名检测开始] ", map[string]interface{}{
						"domain":  domain,
						"enabled": rh.config.EnableChinaDomainCheck,
					})
					isChinaDomain := rh.matcherHandler.GetChinaMatcher().IsChinaDomain(domain)
					if isChinaDomain {
						rh.logger.Info("🇨🇳 [异步刷新-中国域名检测结果] ", map[string]interface{}{
							"domain": domain,
						})

						// 对于中国域名，使用中国DNS服务器进行查询
						if rh.config.ChinaDNS != "" {
							processedResp := processDNSResponseWithCNAME(rh.logger, result.SuccessResult.Response, domain, []string{rh.config.ChinaDNS}, rh.proxyQuery)
							ensureMinimumTTL(processedResp, rh.config.Cache.TTL)
							rh.cacheManager.Set(domain, qtype, processedResp, false, 0) // 中国域名不标记为云服务

							rh.logger.Debug("🔄 [异步刷新完成-中国域名] ", map[string]interface{}{
								"domain":       domain,
								"qtype":        dns.TypeToString[qtype],
								"source":       "china",
								"answer_count": len(processedResp.Answer),
								"upstreams":    []string{rh.config.ChinaDNS},
							})
						} else {
							rh.logger.Warn("⚠️ [异步刷新-中国域名但未配置ChinaDNS] ", map[string]interface{}{
								"domain": domain,
							})
							// 如果未配置ChinaDNS，按普通域名处理
							processedResp := processDNSResponseWithCNAME(rh.logger, result.SuccessResult.Response, domain, upstreams, rh.proxyQuery)
							ensureMinimumTTL(processedResp, rh.config.Cache.TTL)
							rh.cacheManager.Set(domain, qtype, processedResp, false, 0)

							rh.logger.Debug("🔄 [异步刷新完成-中国域名-普通处理] ", map[string]interface{}{
								"domain":       domain,
								"qtype":        dns.TypeToString[qtype],
								"source":       "china_fallback_normal",
								"answer_count": len(processedResp.Answer),
								"upstreams":    upstreams,
							})
						}
					} else {
						rh.logger.Debug("❌ [异步刷新-非中国域名] ", map[string]interface{}{
							"domain": domain,
						})

						rh.logger.Info("❌ [异步刷新-非云服务域名] ", map[string]interface{}{
							"domain": domain,
						})

						// 对于普通域名，处理CNAME记录
						processedResp := processDNSResponseWithCNAME(rh.logger, result.SuccessResult.Response, domain, upstreams, rh.proxyQuery)
						ensureMinimumTTL(processedResp, rh.config.Cache.TTL)
						rh.cacheManager.Set(domain, qtype, processedResp, false, 0)

						rh.logger.Debug("🔄 [异步刷新完成-普通域名] ", map[string]interface{}{
							"domain":       domain,
							"qtype":        dns.TypeToString[qtype],
							"source":       "normal",
							"answer_count": len(processedResp.Answer),
							"upstreams":    upstreams,
						})
					}
				} else {
					// 如果中国域名检查被禁用，执行原来的逻辑
					rh.logger.Debug("⏭️ [异步刷新-中国域名检查已禁用] ", map[string]interface{}{
						"domain":  domain,
						"enabled": rh.config.EnableChinaDomainCheck,
					})

					rh.logger.Info("❌ [异步刷新-非云服务域名] ", map[string]interface{}{
						"domain": domain,
					})

					// 对于普通域名，处理CNAME记录
					processedResp := processDNSResponseWithCNAME(rh.logger, result.SuccessResult.Response, domain, upstreams, rh.proxyQuery)
					ensureMinimumTTL(processedResp, rh.config.Cache.TTL)
					rh.cacheManager.Set(domain, qtype, processedResp, false, 0)

					rh.logger.Debug("🔄 [异步刷新完成-普通域名] ", map[string]interface{}{
						"domain":       domain,
						"qtype":        dns.TypeToString[qtype],
						"source":       "normal",
						"answer_count": len(processedResp.Answer),
						"upstreams":    upstreams,
					})
				}
			}
		}
	} else {
		// 记录详细的失败原因
		failureReason := "unknown_error"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			failureReason = result.FastestResult.Error.Error()
		} else if !result.HasSuccess {
			failureReason = "no_successful_response"
		} else if result.SuccessResult == nil {
			failureReason = "success_result_is_nil"
		} else if result.SuccessResult.Response == nil {
			failureReason = "response_is_nil"
		} else if result.SuccessResult.Response.Rcode != dns.RcodeSuccess {
			failureReason = fmt.Sprintf("non_success_rcode: %s", dns.RcodeToString[result.SuccessResult.Response.Rcode])
		} else if len(result.SuccessResult.Response.Answer) == 0 {
			failureReason = "no_answer_records"
		}

		rh.logger.Warn("⚠️ [异步刷新跳过] ", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
			"reason": failureReason,
		})

		// 即使刷新失败，也要延长原缓存的过期时间，防止频繁刷新
		// 这样可以避免缓存立即过期导致的查询失败
		// 延长时间为配置TTL的一半，避免过于频繁的刷新
		if rh.cacheManager != nil {
			rh.cacheManager.ExtendTTL(domain, qtype, rh.config.Cache.TTL/2)
		}
	}

	return nil
}

// determineUpstreamsForDomain 确定域名应该使用的上游DNS服务器（使用统一的定向域名匹配）
func (rh *RefreshHandler) determineUpstreamsForDomain(domain string) []string {
	// 使用统一的定向域名匹配逻辑
	if dnsServer, hasDesignated := rh.matcherHandler.GetYAMLMatcher().GetDesignatedDomainOrDefault(domain); hasDesignated {
		rh.logger.Debug("异步刷新：定向域名或默认DNS", map[string]interface{}{
			"domain":     domain,
			"dns_server": dnsServer,
		})
		return []string{dnsServer}
	}

	// 如果没有匹配到任何配置，使用上游DNS作为备用
	rh.logger.Debug("异步刷新：使用上游DNS作为备用", map[string]interface{}{
		"domain":    domain,
		"upstreams": rh.config.Upstream,
	})
	return rh.config.Upstream
}

// processDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录的辅助函数
func processDNSResponseWithCNAME(logger *utils.EnhancedLogger, resp *dns.Msg, domain string, upstreams []string, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *dns.Msg {
	// 开始计时CNAME处理
	cnameTimer := logger.StartTimer("cname_processing_async")
	defer cnameTimer.End()

	if resp == nil {
		return resp
	}

	// 创建新的响应，不复制原始响应的问题部分以避免Question section mismatch
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}

	// 设置正确的问题部分
	processedResp.Question = []dns.Question{
		{
			Name:   dns.Fqdn(domain),
			Qtype:  resp.Question[0].Qtype,
			Qclass: resp.Question[0].Qclass,
		},
	}

	processedResp.Id = resp.Id // 保持ID一致

	// 获取最大IP记录数配置，默认为2
	maxIPRecords := 2 // 默认值，可以从配置中获取
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	logger.Debug("🔍 CNAME处理开始", map[string]interface{}{
		"domain":         domain,
		"max_ip_records": maxIPRecords,
		"upstreams":      upstreams,
	})

	// 收集所有IP记录（最多maxIPRecords条）
	var ipRecords []dns.RR

	// 第一遍：收集直接的IP记录
	for _, rr := range resp.Answer {
		// 如果已经收集了足够数量的记录，停止收集
		if len(ipRecords) >= maxIPRecords {
			break
		}

		// 直接处理IP记录
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, rr)
		}
	}

	logger.Debug("📝 直接IP记录收集完成", map[string]interface{}{
		"domain":      domain,
		"collected":   len(ipRecords),
		"max_allowed": maxIPRecords,
	})

	// 如果已经收集到足够数量的IP记录，直接返回，不需要继续解析CNAME
	if len(ipRecords) >= maxIPRecords {
		logger.Debug("✅ 已收集到足够IP记录，跳过CNAME解析", map[string]interface{}{
			"domain":    domain,
			"count":     len(ipRecords),
			"requested": maxIPRecords,
		})
	} else {
		// 如果没有足够的IP记录，尝试递归解析CNAME记录
		logger.Debug("🔍 开始CNAME递归解析", map[string]interface{}{
			"domain":    domain,
			"current":   len(ipRecords),
			"need_more": maxIPRecords - len(ipRecords),
		})

		// 串行解析CNAME记录（先简化实现确保正确性）
		for _, rr := range resp.Answer {
			// 检查是否已经收集了足够数量的记录
			if len(ipRecords) >= maxIPRecords {
				break
			}

			if cname, ok := rr.(*dns.CNAME); ok {
				logger.Debug("🔄 解析CNAME记录", map[string]interface{}{
					"domain": domain,
					"target": cname.Target,
				})

				// 递归解析CNAME目标，使用传入的上游DNS服务器
				cnameTargetReq := &dns.Msg{}
				cnameTargetReq.SetQuestion(cname.Target, resp.Question[0].Qtype) // 使用与原始请求相同的查询类型

				cnameTargetResp, err := proxyQuery(cnameTargetReq, upstreams)
				if err == nil && cnameTargetResp != nil {
					// 递归处理CNAME目标的响应
					// 注意：这里不应该再次应用IP数量限制，而是获取所有可能的IP，
					// 然后由外层逻辑统一控制最终数量
					processedCnameResp := processDNSResponseWithCNAME(logger, cnameTargetResp, domain, upstreams, proxyQuery)
					if processedCnameResp != nil {
						// 从处理后的响应中提取IP记录
						for _, targetRR := range processedCnameResp.Answer {
							// 检查是否已经收集了足够数量的记录
							if len(ipRecords) >= maxIPRecords {
								break
							}

							// 只处理IP记录
							switch targetRR.(type) {
							case *dns.A, *dns.AAAA:
								// 检查是否已存在相同的IP记录，避免重复
								isDuplicate := false
								for _, existing := range ipRecords {
									if existing.String() == targetRR.String() {
										isDuplicate = true
										break
									}
								}
								if !isDuplicate {
									ipRecords = append(ipRecords, targetRR)
								}
							}
						}
					}
				} else {
					logger.Debug("❌ CNAME解析失败", map[string]interface{}{
						"domain": domain,
						"target": cname.Target,
						"error":  err,
					})
				}
			}
		}

		logger.Debug("✅ CNAME递归解析完成", map[string]interface{}{
			"domain":    domain,
			"total":     len(ipRecords),
			"max_limit": maxIPRecords,
		})
	}

	// 按IPv4和IPv6分别限制数量
	var ipv4Records []dns.RR
	var ipv6Records []dns.RR

	for _, record := range ipRecords {
		switch record.(type) {
		case *dns.A:
			ipv4Records = append(ipv4Records, record)
		case *dns.AAAA:
			ipv6Records = append(ipv6Records, record)
		}
	}

	// 限制IPv4和IPv6记录数，各自不超过maxIPRecords
	if len(ipv4Records) > maxIPRecords {
		ipv4Records = ipv4Records[:maxIPRecords]
		logger.Debug("✂️ IPv4记录超限裁剪", map[string]interface{}{
			"domain": domain,
			"before": len(ipv4Records),
			"after":  maxIPRecords,
		})
	}

	if len(ipv6Records) > maxIPRecords {
		ipv6Records = ipv6Records[:maxIPRecords]
		logger.Debug("✂️ IPv6记录超限裁剪", map[string]interface{}{
			"domain": domain,
			"before": len(ipv6Records),
			"after":  maxIPRecords,
		})
	}

	// 合并IPv4和IPv6记录
	ipRecords = append(ipv4Records, ipv6Records...)

	// 总体记录数也不应超过maxIPRecords * 2（如果需要全局限制的话）
	// 但根据需求，我们允许IPv4和IPv6各自独立达到maxIPRecords
	logger.Debug("📊 IP记录统计", map[string]interface{}{
		"domain":      domain,
		"ipv4_count":  len(ipv4Records),
		"ipv6_count":  len(ipv6Records),
		"total_count": len(ipRecords),
		"max_ipv4":    maxIPRecords,
		"max_ipv6":    maxIPRecords,
	})

	// 复制IP记录到处理后的响应，修改域名
	for _, rr := range ipRecords {
		newRR := dns.Copy(rr)
		newRR.Header().Name = dns.Fqdn(domain)
		processedResp.Answer = append(processedResp.Answer, newRR)
	}

	cnameProcessingTime := cnameTimer.End()
	logger.Debug("✅ CNAME处理完成", map[string]interface{}{
		"domain":          domain,
		"final_count":     len(processedResp.Answer),
		"max_allowed":     maxIPRecords,
		"processing_time": cnameProcessingTime,
	})

	return processedResp
}

// processCloudResponse 处理云域名响应，确保符合DNS协议标准的辅助函数
func processCloudResponse(logger *utils.EnhancedLogger, resp *dns.Msg, domain string, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 使用通用的CNAME处理方法，传入上游DNS服务器为默认上游
	return processDNSResponseWithCNAME(logger, resp, domain, nil, proxyQuery)
}

// ensureMinimumTTL 确保响应中的 TTL 不小于指定的最小值的辅助函数
func ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
	if resp == nil {
		return
	}

	minTTLSeconds := uint32(minTTL.Seconds())

	// 更新 Answer 部分的 TTL
	for _, rr := range resp.Answer {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Authority 部分的 TTL
	for _, rr := range resp.Ns {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}

	// 更新 Additional 部分的 TTL
	for _, rr := range resp.Extra {
		if rr.Header().Ttl < minTTLSeconds {
			rr.Header().Ttl = minTTLSeconds
		}
	}
}
