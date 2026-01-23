package dns

import (
	"strings"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// CNAMEProcessor 处理CNAME相关逻辑
type CNAMEProcessor struct {
	config       *config.Config
	Logger       *utils.EnhancedLogger
	proxyQuery   func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
	cacheManager *CacheManager                              // 添加缓存管理器
}

// NewCNAMEProcessor 创建新的CNAME处理器
func NewCNAMEProcessor(config *config.Config, logger *utils.EnhancedLogger, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error), cacheManager *CacheManager) *CNAMEProcessor {
	return &CNAMEProcessor{
		config:       config,
		Logger:       logger,
		proxyQuery:   proxyQuery,
		cacheManager: cacheManager,
	}
}

// NewCNAMEProcessorWithoutCache 创建不带缓存功能的CNAME处理器（用于某些特殊场景）
func NewCNAMEProcessorWithoutCache(config *config.Config, logger *utils.EnhancedLogger, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *CNAMEProcessor {
	return &CNAMEProcessor{
		config:       config,
		Logger:       logger,
		proxyQuery:   proxyQuery,
		cacheManager: nil, // 不设置缓存管理器
	}
}

// ProcessDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 使用RFC兼容的CNAME解析
	return cp.ProcessDNSResponseWithCNAMERFC(resp, domain, upstreams)
}

// ProcessDNSResponseWithCNAMERFC 符合RFC 1034/1035标准的CNAME解析
// 只解析指定深度的CNAME链，并返回完整的CNAME链和最终IP记录
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAMERFC(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	cp.Logger.Debug("🔍 开始RFC兼容CNAME解析", map[string]interface{}{
		"domain":          domain,
		"initial_answers": len(resp.Answer),
		"recursion_depth": cp.config.CNAMERecursionDepth,
	})

	// 创建结果响应
	resultResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	resultResp.Id = resp.Id

	// 使用辅助函数进行递归解析，保留完整的CNAME链
	visited := make(map[string]bool) // 防止循环引用
	resultResp = cp.processCNAMEChainWithFullPath(resp, domain, upstreams, visited, 0, cp.config.CNAMERecursionDepth)

	// 限制IP记录数量，但保持CNAME记录在前的正确顺序
	maxIPRecords := cp.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	// 按照DNS协议推荐顺序重新组织记录：CNAME在前，IP在后
	var orderedRecords []dns.RR

	// 首先添加所有CNAME记录
	for _, record := range resultResp.Answer {
		if _, ok := record.(*dns.CNAME); ok {
			orderedRecords = append(orderedRecords, record)
		}
	}

	// 然后添加IP记录（A和AAAA），但限制数量
	var ipRecords []dns.RR
	for _, record := range resultResp.Answer {
		switch record.(type) {
		case *dns.A, *dns.AAAA:
			ipRecords = append(ipRecords, record)
		}
	}

	// 限制IP记录数量并去重
	var finalIPRecords []dns.RR
	uniqueIPs := make(map[string]bool)
	var ipv4Count, ipv6Count int

	for _, record := range ipRecords {
		var ipStr string
		switch r := record.(type) {
		case *dns.A:
			ipStr = r.A.String()
		case *dns.AAAA:
			ipStr = r.AAAA.String()
		}
		if ipStr != "" && !uniqueIPs[ipStr] {
			uniqueIPs[ipStr] = true
			switch record.(type) {
			case *dns.A:
				if ipv4Count < maxIPRecords {
					finalIPRecords = append(finalIPRecords, record)
					ipv4Count++
				}
			case *dns.AAAA:
				if ipv6Count < maxIPRecords {
					finalIPRecords = append(finalIPRecords, record)
					ipv6Count++
				}
			}
			// 总数也不能超过maxIPRecords
			if len(finalIPRecords) >= maxIPRecords {
				break
			}
		}
	}

	// 合并记录：CNAME在前，IP在后
	orderedRecords = append(orderedRecords, finalIPRecords...)

	// 更新结果响应
	resultResp.Answer = orderedRecords

	cp.Logger.Debug("✅ RFC兼容CNAME解析完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(resultResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  cp.countType(resultResp.Answer, "A"),
		"ipv6_count":  cp.countType(resultResp.Answer, "AAAA"),
		"cname_count": cp.countType(resultResp.Answer, "CNAME"),
	})

	return resultResp
}

// processCNAMEChainWithFullPath 递归处理CNAME链，保留完整的解析路径
func (cp *CNAMEProcessor) processCNAMEChainWithFullPath(resp *dns.Msg, originalDomain string, upstreams []string, visited map[string]bool, currentDepth, maxDepth int) *dns.Msg {
	if resp == nil || currentDepth > maxDepth {
		return resp
	}

	// 创建结果响应
	resultResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(originalDomain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	resultResp.Id = resp.Id

	// 首先处理当前响应中的所有记录
	// 根据RFC标准，我们只处理第一条CNAME记录
	var firstCNAME *dns.CNAME
	var otherRecords []dns.RR

	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.CNAME:
			// 防止自引用
			target := strings.ToLower(strings.TrimSuffix(record.Target, "."))
			source := strings.ToLower(strings.TrimSuffix(record.Hdr.Name, "."))

			if target == source {
				cp.Logger.Debug("⚠️ 跳过自引用CNAME", map[string]interface{}{
					"domain": target,
				})
				continue
			}

			// 检查是否已访问过此目标（防止循环）
			if visited[target] {
				cp.Logger.Debug("⚠️ 检测到CNAME循环引用，但仍保留CNAME记录", map[string]interface{}{
					"target": target,
					"source": source,
				})
				// 即使是循环，也添加CNAME记录到结果中，但不继续解析
				newCNAME := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(originalDomain), // 使用原始查询域名
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					Target: record.Target,
				}
				resultResp.Answer = append(resultResp.Answer, newCNAME)
				continue
			}

			// 只保留第一条CNAME记录，根据RFC标准
			if firstCNAME == nil {
				firstCNAME = record
				// 添加CNAME记录到结果（使用原始查询域名作为名称）
				newCNAME := &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(originalDomain), // 使用原始查询域名
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					Target: record.Target,
				}
				resultResp.Answer = append(resultResp.Answer, newCNAME)

				// 如果还有深度可以解析，继续处理CNAME目标
				if currentDepth+1 <= maxDepth {
					// 标记为已访问，防止循环
					visited[target] = true
					visited[source] = true

					queryReq := &dns.Msg{}
					queryReq.SetQuestion(dns.Fqdn(target), resp.Question[0].Qtype)

					// 尝试从缓存获取中间域名的响应
					cachedResp, hit, _, _ := cp.cacheManager.Get(target, resp.Question[0].Qtype)
					var queryResp *dns.Msg
					var err error

					if hit && cachedResp != nil {
						cp.Logger.Debug("🎯 使用缓存的CNAME目标响应", map[string]interface{}{
							"target": target,
							"qtype":  dns.TypeToString[resp.Question[0].Qtype],
						})
						queryResp = cachedResp
					} else {
						// 如果缓存中没有，执行查询
						queryResp, err = cp.proxyQuery(queryReq, upstreams)
						if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
							// 将查询结果缓存
							cp.cacheManager.Set(target, resp.Question[0].Qtype, queryResp, false)
							cp.Logger.Debug("💾 缓存CNAME目标查询结果", map[string]interface{}{
								"target":       target,
								"qtype":        dns.TypeToString[resp.Question[0].Qtype],
								"answer_count": len(queryResp.Answer),
							})
						}
					}

					if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
						// 递归处理CNAME目标的响应
						subResult := cp.processCNAMEChainWithFullPath(queryResp, originalDomain, upstreams, visited, currentDepth+1, maxDepth)

						// 将子结果中的所有记录（除了已添加的当前CNAME）添加到当前结果
						// 但我们只需要添加IP记录，避免重复添加CNAME
						for _, subRR := range subResult.Answer {
							switch subRR.(type) {
							case *dns.A, *dns.AAAA:
								// 只添加IP记录
								resultResp.Answer = append(resultResp.Answer, subRR)
							}
						}
					} else {
						cp.Logger.Debug("❌ CNAME目标查询失败", map[string]interface{}{
							"target": target,
							"error":  err,
						})
					}

					// 移除标记，允许其他分支访问相同的域名
					delete(visited, target)
				}
			} else {
				// 如果不是第一条CNAME，将其作为其他记录处理
				otherRecords = append(otherRecords, record)
			}
		default:
			// 添加其他类型的记录，使用原始域名
			newRecord := dns.Copy(record)
			newRecord.Header().Name = dns.Fqdn(originalDomain) // 使用原始域名
			otherRecords = append(otherRecords, newRecord)
		}
	}

	// 添加非CNAME记录
	for _, record := range otherRecords {
		resultResp.Answer = append(resultResp.Answer, record)
	}

	return resultResp
}

// ProcessDNSResponseWithCNAMEAggressive 更积极地解析CNAME记录以收集更多IP
// 与常规CNAME解析不同，此函数会解析所有CNAME记录以收集尽可能多的IP
func (cp *CNAMEProcessor) ProcessDNSResponseWithCNAMEAggressive(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	cp.Logger.Debug("🔍 开始CNAME积极解析", map[string]interface{}{
		"domain":          domain,
		"initial_answers": len(resp.Answer),
	})

	// 存储所有收集到的IP
	var allIPRecords []dns.RR

	// 使用map来快速去重
	seenIPs := make(map[string]bool)

	// 首先处理原始响应中的IP记录
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.A:
			ipStr := record.A.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制A记录，但使用原始查询域名
				newA := &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain), // 使用原始域名
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					A: record.A,
				}
				allIPRecords = append(allIPRecords, newA)
				cp.Logger.Debug("📡 收集到原始A记录IP", map[string]interface{}{
					"domain":      domain,
					"ip":          ipStr,
					"total_count": len(allIPRecords),
				})
			}
		case *dns.AAAA:
			ipStr := record.AAAA.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制AAAA记录，但使用原始查询域名
				newAAAA := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain), // 使用原始域名
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    record.Hdr.Ttl,
					},
					AAAA: record.AAAA,
				}
				allIPRecords = append(allIPRecords, newAAAA)
				cp.Logger.Debug("📡 收集到原始AAAA记录IP", map[string]interface{}{
					"domain":      domain,
					"ip":          ipStr,
					"total_count": len(allIPRecords),
				})
			}
		}
	}

	// 检查是否已达到最大IP数量限制
	maxIPRecords := cp.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	cp.Logger.Debug("📊 初始IP收集完成", map[string]interface{}{
		"domain":           domain,
		"initial_ip_count": len(allIPRecords),
		"max_limit":        maxIPRecords,
		"need_more":        len(allIPRecords) < maxIPRecords,
		"missing_count":    maxIPRecords - len(allIPRecords),
	})

	// 如果已达到最大IP数量限制，直接返回
	if len(allIPRecords) >= maxIPRecords {
		cp.Logger.Debug("✅ 初始IP已满足需求，无需解析CNAME", map[string]interface{}{
			"collected": len(allIPRecords),
			"limit":     maxIPRecords,
		})
		// 创建并返回响应
		processedResp := &dns.Msg{
			MsgHdr: resp.MsgHdr,
			Question: []dns.Question{
				{
					Name:   dns.Fqdn(domain),
					Qtype:  resp.Question[0].Qtype,
					Qclass: resp.Question[0].Qclass,
				},
			},
			Answer: []dns.RR{},
			Ns:     append([]dns.RR{}, resp.Ns...),
			Extra:  append([]dns.RR{}, resp.Extra...),
		}
		processedResp.Id = resp.Id

		// 按IPv4和IPv6分别限制数量
		var ipv4Records []dns.RR
		var ipv6Records []dns.RR

		for _, record := range allIPRecords {
			switch record.(type) {
			case *dns.A:
				if len(ipv4Records) < maxIPRecords {
					ipv4Records = append(ipv4Records, record)
				}
			case *dns.AAAA:
				if len(ipv6Records) < maxIPRecords {
					ipv6Records = append(ipv6Records, record)
				}
			}
		}

		// 合并IPv4和IPv6记录
		finalIPRecords := append(ipv4Records, ipv6Records...)

		// 添加限制后的IP记录到响应
		for _, record := range finalIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

		cp.Logger.Debug("✅ CNAME积极解析完成", map[string]interface{}{
			"domain":      domain,
			"final_count": len(processedResp.Answer),
			"max_allowed": maxIPRecords,
			"ipv4_count":  cp.countType(processedResp.Answer, "A"),
			"ipv6_count":  cp.countType(processedResp.Answer, "AAAA"),
			"all_collected_ips": func() []string {
				var ips []string
				for _, record := range finalIPRecords {
					switch r := record.(type) {
					case *dns.A:
						ips = append(ips, r.A.String())
					case *dns.AAAA:
						ips = append(ips, r.AAAA.String())
					}
				}
				return ips
			}(),
		})

		return processedResp
	}

	// 如果还有需要收集的IP，才继续解析CNAME链
	remainingIPs := maxIPRecords - len(allIPRecords)
	if remainingIPs <= 0 {
		// 创建并返回响应
		processedResp := &dns.Msg{
			MsgHdr: resp.MsgHdr,
			Question: []dns.Question{
				{
					Name:   dns.Fqdn(domain),
					Qtype:  resp.Question[0].Qtype,
					Qclass: resp.Question[0].Qclass,
				},
			},
			Answer: []dns.RR{},
			Ns:     append([]dns.RR{}, resp.Ns...),
			Extra:  append([]dns.RR{}, resp.Extra...),
		}
		processedResp.Id = resp.Id

		// 按IPv4和IPv6分别限制数量
		var ipv4Records []dns.RR
		var ipv6Records []dns.RR

		for _, record := range allIPRecords {
			switch record.(type) {
			case *dns.A:
				if len(ipv4Records) < maxIPRecords {
					ipv4Records = append(ipv4Records, record)
				}
			case *dns.AAAA:
				if len(ipv6Records) < maxIPRecords {
					ipv6Records = append(ipv6Records, record)
				}
			}
		}

		// 合并IPv4和IPv6记录
		finalIPRecords := append(ipv4Records, ipv6Records...)

		// 添加限制后的IP记录到响应
		for _, record := range finalIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

		cp.Logger.Debug("✅ CNAME积极解析完成", map[string]interface{}{
			"domain":      domain,
			"final_count": len(processedResp.Answer),
			"max_allowed": maxIPRecords,
			"ipv4_count":  cp.countType(processedResp.Answer, "A"),
			"ipv6_count":  cp.countType(processedResp.Answer, "AAAA"),
			"all_collected_ips": func() []string {
				var ips []string
				for _, record := range finalIPRecords {
					switch r := record.(type) {
					case *dns.A:
						ips = append(ips, r.A.String())
					case *dns.AAAA:
						ips = append(ips, r.AAAA.String())
					}
				}
				return ips
			}(),
		})

		return processedResp
	}

	// 只有在需要更多IP时才解析CNAME
	// 收集原始响应中的CNAME记录
	var initialCNAMEs []*dns.CNAME
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			initialCNAMEs = append(initialCNAMEs, cname)
		}
	}

	// 计算还需要多少个IP
	remainingIPs = maxIPRecords - len(allIPRecords)
	if remainingIPs > 0 {
		// 只处理需要数量的CNAME，避免不必要的查询
		for i := 0; i < len(initialCNAMEs) && len(allIPRecords) < maxIPRecords; i++ {
			cname := initialCNAMEs[i]
			target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
			origin := strings.ToLower(strings.TrimSuffix(cname.Hdr.Name, "."))

			// 避免自引用CNAME
			if target == origin {
				cp.Logger.Debug("⚠️ 跳过自引用CNAME", map[string]interface{}{
					"domain": target,
				})
				continue
			}

			cp.Logger.Debug("🔄 处理CNAME目标", map[string]interface{}{
				"target":           target,
				"current_ip_count": len(allIPRecords),
				"need_ip_count":    remainingIPs,
			})

			// 查询CNAME目标
			queryReq := &dns.Msg{}
			queryReq.SetQuestion(dns.Fqdn(target), resp.Question[0].Qtype)

			queryResp, err := cp.proxyQuery(queryReq, upstreams)
			if err != nil || queryResp == nil || queryResp.Rcode != dns.RcodeSuccess {
				cp.Logger.Debug("❌ CNAME目标查询失败", map[string]interface{}{
					"target": target,
					"error":  err,
				})
				continue
			}

			cp.Logger.Debug("📥 CNAME目标查询成功", map[string]interface{}{
				"target":        target,
				"answers_count": len(queryResp.Answer),
			})

			// 从CNAME目标响应中收集IP
			for _, rr := range queryResp.Answer {
				if len(allIPRecords) >= maxIPRecords {
					cp.Logger.Debug("🏁 已达到IP数量限制，停止处理更多CNAME", map[string]interface{}{
						"collected": len(allIPRecords),
						"limit":     maxIPRecords,
					})
					break // 已达到IP数量限制，停止处理更多IP
				}

				switch record := rr.(type) {
				case *dns.A:
					ipStr := record.A.String()
					cp.Logger.Debug("📡 收集到A记录IP", map[string]interface{}{
						"domain":       target,
						"ip":           ipStr,
						"already_seen": seenIPs[ipStr],
					})

					if !seenIPs[ipStr] {
						seenIPs[ipStr] = true
						// 复制A记录，但使用原始查询域名
						newA := &dns.A{
							Hdr: dns.RR_Header{
								Name:   dns.Fqdn(domain), // 使用原始域名
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    record.Hdr.Ttl,
							},
							A: record.A,
						}
						allIPRecords = append(allIPRecords, newA)
						cp.Logger.Debug("✅ 添加IP到结果", map[string]interface{}{
							"ip":          ipStr,
							"total_count": len(allIPRecords),
						})
					}
				case *dns.AAAA:
					ipStr := record.AAAA.String()
					cp.Logger.Debug("📡 收集到AAAA记录IP", map[string]interface{}{
						"domain":       target,
						"ip":           ipStr,
						"already_seen": seenIPs[ipStr],
					})

					if !seenIPs[ipStr] {
						seenIPs[ipStr] = true
						// 复制AAAA记录，但使用原始查询域名
						newAAAA := &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   dns.Fqdn(domain), // 使用原始域名
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    record.Hdr.Ttl,
							},
							AAAA: record.AAAA,
						}
						allIPRecords = append(allIPRecords, newAAAA)
						cp.Logger.Debug("✅ 添加IPV6到结果", map[string]interface{}{
							"ip":          ipStr,
							"total_count": len(allIPRecords),
						})
					}
				case *dns.CNAME:
					// 如果CNAME目标响应中还有CNAME记录，可以选择是否递归处理
					// 为简单起见，这里暂时不递归处理二级CNAME
					cp.Logger.Debug("🔗 发现二级CNAME记录", map[string]interface{}{
						"domain": target,
						"target": record.Target,
					})
				}
			}
		}
	}

	// 创建最终响应
	processedResp := &dns.Msg{
		MsgHdr: resp.MsgHdr,
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain),
				Qtype:  resp.Question[0].Qtype,
				Qclass: resp.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     append([]dns.RR{}, resp.Ns...),
		Extra:  append([]dns.RR{}, resp.Extra...),
	}
	processedResp.Id = resp.Id

	// 按IPv4和IPv6分别限制数量
	var ipv4Records []dns.RR
	var ipv6Records []dns.RR

	for _, record := range allIPRecords {
		switch record.(type) {
		case *dns.A:
			if len(ipv4Records) < maxIPRecords {
				ipv4Records = append(ipv4Records, record)
			}
		case *dns.AAAA:
			if len(ipv6Records) < maxIPRecords {
				ipv6Records = append(ipv6Records, record)
			}
		}
	}

	// 合并IPv4和IPv6记录
	finalIPRecords := append(ipv4Records, ipv6Records...)

	// 添加限制后的IP记录到响应
	for _, record := range finalIPRecords {
		processedResp.Answer = append(processedResp.Answer, record)
	}

	cp.Logger.Debug("✅ CNAME积极解析完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  cp.countType(processedResp.Answer, "A"),
		"ipv6_count":  cp.countType(processedResp.Answer, "AAAA"),
		"all_collected_ips": func() []string {
			var ips []string
			for _, record := range finalIPRecords {
				switch r := record.(type) {
				case *dns.A:
					ips = append(ips, r.A.String())
				case *dns.AAAA:
					ips = append(ips, r.AAAA.String())
				}
			}
			return ips
		}(),
	})

	return processedResp
}

// isSameIP 比较两个DNS记录是否包含相同的IP地址
func (cp *CNAMEProcessor) isSameIP(rr1, rr2 dns.RR) bool {
	a1, ok1 := rr1.(*dns.A)
	a2, ok2 := rr2.(*dns.A)
	if ok1 && ok2 {
		return a1.A.Equal(a2.A)
	}

	aaaa1, ok1 := rr1.(*dns.AAAA)
	aaaa2, ok2 := rr2.(*dns.AAAA)
	if ok1 && ok2 {
		return aaaa1.AAAA.Equal(aaaa2.AAAA)
	}

	// 如果类型不同，则不是相同的IP
	return false
}

// isAAAARecord 检查记录是否为AAAA记录
func (cp *CNAMEProcessor) isAAAARecord(rr dns.RR) bool {
	_, ok := rr.(*dns.AAAA)
	return ok
}

// countType 计算指定类型的记录数量
func (cp *CNAMEProcessor) countType(records []dns.RR, recordType string) int {
	count := 0
	for _, record := range records {
		switch recordType {
		case "A":
			if _, ok := record.(*dns.A); ok {
				count++
			}
		case "AAAA":
			if _, ok := record.(*dns.AAAA); ok {
				count++
			}
		}
	}
	return count
}

// ProcessNonIPResponseWithCNAME 处理非IP记录类型的DNS响应中的CNAME记录
func (cp *CNAMEProcessor) ProcessNonIPResponseWithCNAME(resp *dns.Msg, domain string, qtype uint16, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 检查响应中是否包含CNAME记录
	hasCNAME := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			hasCNAME = true
			break
		}
	}

	// 如果没有CNAME记录，直接返回原响应，但保留AUTHORITY和ADDITIONAL部分
	if !hasCNAME {
		return resp
	}

	// 对于非IP记录查询，如果原始查询类型不是A/AAAA，我们需要递归查询CNAME指向的目标
	// 创建副本以避免修改原始响应
	newResp := &dns.Msg{}
	*newResp = *resp
	newResp.Answer = nil

	// 递归查询CNAME目标
	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			// 创建对CNAME目标的新查询
			cnameReq := &dns.Msg{}
			cnameReq.SetQuestion(cname.Target, qtype)

			// 查询CNAME目标的相同记录类型
			cnameResp, err := cp.proxyQuery(cnameReq, upstreams)
			if err == nil && cnameResp != nil {
				// 无论CNAME目标是否有答案记录，我们都应该处理其权威和附加部分
				// 添加原始的CNAME记录
				newResp.Answer = append(newResp.Answer, dns.Copy(rr))

				// 如果CNAME目标有答案记录，添加它们（修改为原始域名）
				for _, ans := range cnameResp.Answer {
					// 复制记录并修改域名
					newAns := dns.Copy(ans)
					newAns.Header().Name = dns.Fqdn(domain)
					newResp.Answer = append(newResp.Answer, newAns)
				}

				// 保留CNAME目标响应的权威部分和附加部分（这是关键的修复）
				for _, ns := range cnameResp.Ns {
					newNs := dns.Copy(ns)
					newNs.Header().Name = dns.Fqdn(domain)
					newResp.Ns = append(newResp.Ns, newNs)
				}

				for _, extra := range cnameResp.Extra {
					newExtra := dns.Copy(extra)
					// 对于附加部分的记录，不一定需要修改域名
					newResp.Extra = append(newResp.Extra, newExtra)
				}
			} else {
				// 如果CNAME目标查询失败，仍然保留原始的CNAME记录
				newResp.Answer = append(newResp.Answer, dns.Copy(rr))
			}
		} else {
			// 非CNAME记录直接添加
			newResp.Answer = append(newResp.Answer, dns.Copy(rr))
		}
	}

	return newResp
}

// ensureMinimumTTL 确保响应中的TTL不低于最小值
func (cp *CNAMEProcessor) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
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

// extractFinalIPs 递归提取CNAME链的最终IP记录
func (cp *CNAMEProcessor) extractFinalIPs(resp *dns.Msg, originalDomain string, upstreams []string, visited map[string]bool, currentDepth, maxDepth int) []dns.RR {
	if resp == nil || currentDepth > maxDepth {
		return []dns.RR{}
	}

	var finalIPs []dns.RR

	// 查找当前响应中的CNAME记录
	var cnameRecord *dns.CNAME
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			// 防止自引用
			target := strings.ToLower(strings.TrimSuffix(c.Target, "."))
			source := strings.ToLower(strings.TrimSuffix(c.Hdr.Name, "."))

			if target == source {
				cp.Logger.Debug("⚠️ 跳过自引用CNAME", map[string]interface{}{
					"domain": target,
				})
				continue
			}

			// 检查是否已访问过此目标（防止循环）
			if visited[target] {
				cp.Logger.Debug("⚠️ 检测到CNAME循环引用", map[string]interface{}{
					"target": target,
					"source": source,
				})
				continue
			}

			cnameRecord = c
			break // 只处理第一条CNAME记录，符合RFC标准
		}
	}

	if cnameRecord != nil && currentDepth < maxDepth {
		// 有CNAME记录且还有递归深度，继续递归查询
		target := strings.ToLower(strings.TrimSuffix(cnameRecord.Target, "."))

		// 标记为已访问，防止循环
		visited[target] = true
		source := strings.ToLower(strings.TrimSuffix(cnameRecord.Hdr.Name, "."))
		visited[source] = true

		queryReq := &dns.Msg{}
		queryReq.SetQuestion(dns.Fqdn(target), resp.Question[0].Qtype)

		// 尝试从缓存获取中间域名的响应
		cachedResp, hit, _, _ := cp.cacheManager.Get(target, resp.Question[0].Qtype)
		var queryResp *dns.Msg
		var err error

		if hit && cachedResp != nil {
			cp.Logger.Debug("🎯 使用缓存的CNAME目标响应", map[string]interface{}{
				"target": target,
				"qtype":  dns.TypeToString[resp.Question[0].Qtype],
			})
			queryResp = cachedResp
		} else {
			// 如果缓存中没有，执行查询
			queryResp, err = cp.proxyQuery(queryReq, upstreams)
			if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
				// 将查询结果缓存
				cp.cacheManager.Set(target, resp.Question[0].Qtype, queryResp, false)
				cp.Logger.Debug("💾 缓存CNAME目标查询结果", map[string]interface{}{
					"target":       target,
					"qtype":        dns.TypeToString[resp.Question[0].Qtype],
					"answer_count": len(queryResp.Answer),
				})
			}
		}

		if err == nil && queryResp != nil && queryResp.Rcode == dns.RcodeSuccess {
			// 递归处理CNAME目标的响应
			subIPs := cp.extractFinalIPs(queryResp, originalDomain, upstreams, visited, currentDepth+1, maxDepth)
			finalIPs = append(finalIPs, subIPs...)
		} else {
			cp.Logger.Debug("❌ CNAME目标查询失败", map[string]interface{}{
				"target": target,
				"error":  err,
			})
		}

		// 移除标记，允许其他分支访问相同的域名
		delete(visited, target)
	} else {
		// 没有CNAME记录或达到最大递归深度，提取IP记录
		for _, rr := range resp.Answer {
			switch rr.(type) {
			case *dns.A, *dns.AAAA:
				finalIPs = append(finalIPs, rr)
			}
		}
	}

	return finalIPs
}
