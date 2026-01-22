package dns

import (
	"net/netip"
	"strings"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// CloudHandler 处理云服务相关功能
type CloudHandler struct {
	config        *config.Config
	logger        *utils.EnhancedLogger
	cacheManager  *CacheManager
	cloudDetector *CloudDetector
	proxyQuery    func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
}

// NewCloudHandler 创建新的云服务处理器
func NewCloudHandler(config *config.Config, logger *utils.EnhancedLogger, cacheManager *CacheManager, cloudDetector *CloudDetector, proxyQuery func(*dns.Msg, []string) (*dns.Msg, error)) *CloudHandler {
	return &CloudHandler{
		config:        config,
		logger:        logger,
		cacheManager:  cacheManager,
		cloudDetector: cloudDetector,
		proxyQuery:    proxyQuery,
	}
}

// HandleCloudReplacement 处理云IP替换
func (ch *CloudHandler) HandleCloudReplacement(w dns.ResponseWriter, req *dns.Msg, domain string, qtype uint16, cloudType int) error {
	var replaceDomain string
	var cloudTypeName string
	switch CloudType(cloudType) {
	case CloudTypeCloudflare:
		replaceDomain = ch.config.ReplaceCFDomain
		cloudTypeName = "Cloudflare"
	case CloudTypeAWS:
		replaceDomain = ch.config.ReplaceAWSDomain
		cloudTypeName = "AWS"
	default:
		ch.logger.Warn("⚠️ 未知云服务类型", map[string]interface{}{
			"cloud_type": cloudType,
			"domain":     domain,
		})
		return ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
	}

	if replaceDomain == "" {
		ch.logger.Warn("⚠️ 未配置云服务替换域名", map[string]interface{}{
			"cloud_type": cloudTypeName,
			"domain":     domain,
		})
		return ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
	}

	ch.logger.Debug("开始云IP替换查询", map[string]interface{}{
		"original_domain": domain,
		"replace_domain":  replaceDomain,
		"cloud_type":      cloudTypeName,
	})

	// 解析替换缓存时间配置
	replaceCacheTime := ch.config.Cache.TTL // 默认使用缓存TTL
	if ch.config.ReplaceCacheTime != "" {
		if parsedTime, err := time.ParseDuration(ch.config.ReplaceCacheTime); err == nil {
			replaceCacheTime = parsedTime
		} else {
			ch.logger.Warn("⚠️ 解析替换缓存时间失败，使用默认值", map[string]interface{}{
				"replace_cache_time": ch.config.ReplaceCacheTime,
				"error":              err.Error(),
				"default_value":      ch.config.Cache.TTL.String(),
			})
		}
	}

	// 首先检查替换域名是否有缓存
	replaceResp, hit, _, _ := ch.cacheManager.Get(replaceDomain, qtype)
	if hit {
		ch.logger.Debug("🎯 使用替换域名缓存", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
		})
	} else {
		// 如果没有缓存，查询替换域名的IP地址
		replaceReq := &dns.Msg{}
		replaceReq.SetQuestion(dns.Fqdn(replaceDomain), qtype)
		// 保持请求ID一致，避免响应匹配问题
		replaceReq.Id = req.Id

		var err error
		replaceResp, err = ch.proxyQuery(replaceReq, ch.config.Upstream)
		if err != nil || replaceResp == nil || replaceResp.Rcode != dns.RcodeSuccess {
			ch.logger.Warn("⚠️ 替换域名查询失败", map[string]interface{}{
				"replace_domain": replaceDomain,
				"qtype":          dns.TypeToString[qtype],
				"error":          err,
			})

			// 如果替换域名查询失败，返回错误
			return ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
		}
		ch.logger.Debug("🔍 替换域名查询成功", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
		})
	}

	// 处理替换域名的响应，积极解析CNAME并收集尽可能多的IP结果
	processedReplaceResp := ch.processDNSResponseWithCNAMEAggressive(replaceResp, replaceDomain, ch.config.Upstream)
	if processedReplaceResp == nil {
		ch.logger.Error("❌ 替换域名处理失败：处理后响应为空", map[string]interface{}{
			"replace_domain": replaceDomain,
		})
		return ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
	}

	// 如果是首次查询且缓存未命中，将查询结果缓存
	if !hit {
		// 确保替换域名的响应也使用配置的TTL
		if processedReplaceResp != nil {
			ch.ensureMinimumTTL(processedReplaceResp, replaceCacheTime)
		}
		// 缓存原始响应
		ch.cacheManager.Set(replaceDomain, qtype, processedReplaceResp, false)
		ch.logger.Debug("💾 缓存替换域名查询结果", map[string]interface{}{
			"replace_domain": replaceDomain,
			"qtype":          dns.TypeToString[qtype],
			"answer_count":   len(processedReplaceResp.Answer),
		})
	}

	// 创建新的响应，使用原始域名但替换IP
	finalResp := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Response:      true,
			Opcode:        dns.OpcodeQuery,
			Rcode:         processedReplaceResp.Rcode,
			Authoritative: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(domain), // 使用原始域名
				Qtype:  qtype,
				Qclass: req.Question[0].Qclass,
			},
		},
		Answer: []dns.RR{},
		Ns:     []dns.RR{},
		Extra:  []dns.RR{},
	}

	// 从处理后的替换域名响应中提取IP记录，并用于原始域名
	seenIPs := make(map[string]bool) // 用于去重
	for _, rr := range processedReplaceResp.Answer {
		// 只处理IP记录，跳过CNAME记录（因为我们已经递归解析了）
		switch record := rr.(type) {
		case *dns.A:
			ipStr := record.A.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制A记录，但使用原始域名
				newA := &dns.A{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeA,
						Class:  record.Header().Class,
						Ttl:    record.Header().Ttl,
					},
					A: record.A,
				}
				finalResp.Answer = append(finalResp.Answer, newA)
			}
		case *dns.AAAA:
			ipStr := record.AAAA.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				// 复制AAAA记录，但使用原始域名
				newAAAA := &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(domain),
						Rrtype: dns.TypeAAAA,
						Class:  record.Header().Class,
						Ttl:    record.Header().Ttl,
					},
					AAAA: record.AAAA,
				}
				finalResp.Answer = append(finalResp.Answer, newAAAA)
			}
		}
		// 限制返回的记录数量，但使用配置的最大IP记录数
		if len(finalResp.Answer) >= ch.config.MaxIPRecords {
			break
		}
	}

	// 如果没有有效的IP记录
	if len(finalResp.Answer) == 0 {
		ch.logger.Warn("⚠️ 云IP替换失败：没有解析到有效的IP记录", map[string]interface{}{
			"original_domain": domain,
			"replace_domain":  replaceDomain,
			"qtype":           dns.TypeToString[qtype],
		})
		// 如果是AAAA查询且没有IPv6记录，返回空响应让客户端降级到IPv4
		if qtype == dns.TypeAAAA {
			ch.logger.Debug("🔄 AAAA查询无结果，返回空响应让客户端降级到A查询", map[string]interface{}{
				"domain": domain,
			})
			resp := &dns.Msg{}
			resp.SetReply(req)
			resp.RecursionAvailable = true
			resp.Authoritative = false
			w.WriteMsg(resp)
			ch.logger.Info("✅ [DNS查询完成-AAAA无结果降级] ", map[string]interface{}{
				"domain":       domain,
				"qtype":        dns.TypeToString[qtype],
				"client_addr":  w.RemoteAddr().String(),
				"source":       "cloud_replacement_downgrade",
				"answer_count": 0,
				"result":       "noerror_empty",
			})
			return nil
		} else {
			// 对于A查询失败，返回服务器错误
			return ch.sendErrorResponse(w, req, dns.RcodeServerFailure)
		}
	}

	// 确保云域名替换响应的TTL不小于配置的替换缓存时间
	ch.ensureMinimumTTL(finalResp, replaceCacheTime)

	// 同时确保替换域名的响应也使用配置的TTL
	if processedReplaceResp != nil {
		ch.ensureMinimumTTL(processedReplaceResp, replaceCacheTime)
	}

	// 将整个域名标记为云服务域名（确保A/AAAA记录一致性）
	ch.cacheManager.MarkDomainAsCloud(domain, qtype, cloudType)
	// 缓存替换后的响应，使用普通缓存TTL而不是替换缓存TTL
	ch.cacheManager.SetCloudResponse(domain, qtype, finalResp, cloudType, ch.config.Cache.TTL)

	// 如果原始替换域名响应来自查询而非缓存，也需要缓存到云响应缓存
	if !hit {
		ch.cacheManager.SetCloudResponse(replaceDomain, qtype, processedReplaceResp, 0, ch.config.Cache.TTL)
	}

	// 记录云替换后实际返回给客户端的响应详情
	answerDetails := make([]map[string]interface{}, 0)
	for _, ans := range finalResp.Answer {
		answerDetail := map[string]interface{}{
			"type": dns.TypeToString[ans.Header().Rrtype],
			"name": ans.Header().Name,
		}
		switch rr := ans.(type) {
		case *dns.A:
			answerDetail["ip"] = rr.A.String()
		case *dns.AAAA:
			answerDetail["ip"] = rr.AAAA.String()
		case *dns.CNAME:
			answerDetail["target"] = rr.Target
		}
		answerDetails = append(answerDetails, answerDetail)
	}

	ch.logger.Debug("📤 云替换后实际返回给客户端的响应", map[string]interface{}{
		"domain":       req.Question[0].String(),
		"answer_count": len(finalResp.Answer),
		"answers":      answerDetails,
		"rcode":        dns.RcodeToString[finalResp.Rcode],
	})

	ch.logger.Info("✅ [DNS查询完成-云域名替换] ", map[string]interface{}{
		"domain":         domain,
		"qtype":          dns.TypeToString[qtype],
		"client_addr":    w.RemoteAddr().String(),
		"source":         "cloud_replacement",
		"cloud_type":     cloudTypeName,
		"replace_domain": replaceDomain,
		"answer_count":   len(finalResp.Answer),
		"cache_ttl":      replaceCacheTime.String(),
		"result":         "success",
	})

	finalResp.Id = req.Id
	w.WriteMsg(finalResp)
	return nil
}

// replaceCloudIPs 用替换域名的IP替换原始响应中的云服务IP
func (ch *CloudHandler) replaceCloudIPs(originalResp *dns.Msg, originalDetection *CloudDetectionResult) *dns.Msg {
	if originalResp == nil || originalDetection == nil {
		return originalResp
	}

	// 查询替换域名获取IP地址
	replaceDomain := originalDetection.ReplaceDomain
	if replaceDomain == "" {
		return originalResp
	}

	// 查询替换域名的A和AAAA记录
	replaceReqA := &dns.Msg{}
	replaceReqA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeA)

	replaceReqAAAA := &dns.Msg{}
	replaceReqAAAA.SetQuestion(dns.Fqdn(replaceDomain), dns.TypeAAAA)

	var replaceIPs []netip.Addr

	// 获取替换域名的A记录
	if replaceRespA, err := ch.proxyQuery(replaceReqA, ch.config.Upstream); err == nil && replaceRespA != nil && replaceRespA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespA.Answer {
			if a, ok := rr.(*dns.A); ok {
				if ip, err := netip.ParseAddr(a.A.String()); err == nil {
					// 检查IP是否已存在，避免重复
					isDuplicate := false
					for _, existingIP := range replaceIPs {
						if existingIP.Compare(ip) == 0 {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						replaceIPs = append(replaceIPs, ip)
					}
				}
			}
		}
	}

	// 获取替换域名的AAAA记录
	if replaceRespAAAA, err := ch.proxyQuery(replaceReqAAAA, ch.config.Upstream); err == nil && replaceRespAAAA != nil && replaceRespAAAA.Rcode == dns.RcodeSuccess {
		for _, rr := range replaceRespAAAA.Answer {
			if aaaa, ok := rr.(*dns.AAAA); ok {
				if ip, err := netip.ParseAddr(aaaa.AAAA.String()); err == nil {
					// 检查IP是否已存在，避免重复
					isDuplicate := false
					for _, existingIP := range replaceIPs {
						if existingIP.Compare(ip) == 0 {
							isDuplicate = true
							break
						}
					}
					if !isDuplicate {
						replaceIPs = append(replaceIPs, ip)
					}
				}
			}
		}
	}

	if len(replaceIPs) == 0 {
		ch.logger.Warn("⚠️ 替换域名无有效IP记录", map[string]interface{}{
			"replace_domain": replaceDomain,
		})
		return originalResp
	}

	// 创建新的响应，保留原始响应的基本结构，但只包含非IP记录和替换后的IP记录
	newResp := &dns.Msg{}
	*newResp = *originalResp // 复制原始响应结构
	newResp.Answer = nil     // 清空答案部分

	// 复制非IP的记录（如CNAME等）
	for _, rr := range originalResp.Answer {
		switch rr.(type) {
		case *dns.A, *dns.AAAA:
			// 跳过云服务IP记录，稍后用替换IP替换
		default:
			// 保留非IP记录
			newResp.Answer = append(newResp.Answer, dns.Copy(rr))
		}
	}

	// 添加替换IP，根据原始查询类型决定添加哪些类型的IP
	seenIPs := make(map[string]bool) // 用于去重
	for _, ip := range replaceIPs {
		if ip.Is4() && originalResp.Question[0].Qtype == dns.TypeA {
			// 查找原始响应中的任意一个A记录来获取TTL和Header信息作为参考
			var referenceTTL uint32 = 1800 // 默认TTL
			for _, originalRR := range originalResp.Answer {
				if originalA, ok := originalRR.(*dns.A); ok {
					referenceTTL = originalA.Hdr.Ttl
					break
				}
			}

			newA := &dns.A{
				Hdr: dns.RR_Header{
					Name:   originalResp.Question[0].Name, // 使用原始查询的域名
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    referenceTTL, // 使用参考TTL
				},
				A: ip.AsSlice(),
			}
			ipStr := ip.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				newResp.Answer = append(newResp.Answer, newA)
			}
		} else if ip.Is6() && originalResp.Question[0].Qtype == dns.TypeAAAA {
			// 查找原始响应中的任意一个AAAA记录来获取TTL和Header信息作为参考
			var referenceTTL uint32 = 1800 // 默认TTL
			for _, originalRR := range originalResp.Answer {
				if originalAAAA, ok := originalRR.(*dns.AAAA); ok {
					referenceTTL = originalAAAA.Hdr.Ttl
					break
				}
			}

			newAAAA := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   originalResp.Question[0].Name, // 使用原始查询的域名
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    referenceTTL, // 使用参考TTL
				},
				AAAA: ip.AsSlice(),
			}
			ipStr := ip.String()
			if !seenIPs[ipStr] {
				seenIPs[ipStr] = true
				newResp.Answer = append(newResp.Answer, newAAAA)
			}
		}
	}

	ch.logger.Debug("🔄 云IP替换完成", map[string]interface{}{
		"original_ips_count": len(originalDetection.DetectedIPs),
		"replace_ips_count":  len(replaceIPs),
		"final_answer_count": len(newResp.Answer),
	})

	return newResp
}

// processCloudResponse 处理云域名响应，确保符合DNS协议标准
func (ch *CloudHandler) processCloudResponse(resp *dns.Msg, domain string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 检查响应中是否只有IP记录，如果是则跳过CNAME处理
	// 只有在响应中包含CNAME记录时才进行递归处理
	containsCNAME := false
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.CNAME); ok {
			containsCNAME = true
			break
		}
	}

	if !containsCNAME {
		// 如果没有CNAME记录，直接返回响应，只处理TTL
		ch.ensureMinimumTTL(resp, ch.config.Cache.TTL)
		return resp
	}

	// 只有在存在CNAME记录时才进行递归处理
	return ch.processDNSResponseWithCNAME(resp, domain, ch.config.Upstream)
}

// ProcessDNSResponseWithCNAMEAggressive 更积极地解析CNAME记录以收集更多IP
// 与常规CNAME解析不同，此函数会解析所有CNAME记录以收集尽可能多的IP
func (ch *CloudHandler) processDNSResponseWithCNAMEAggressive(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	ch.logger.Debug("🔍 开始CNAME积极解析", map[string]interface{}{
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
				ch.logger.Debug("📡 收集到原始A记录IP", map[string]interface{}{
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
				ch.logger.Debug("📡 收集到原始AAAA记录IP", map[string]interface{}{
					"domain":      domain,
					"ip":          ipStr,
					"total_count": len(allIPRecords),
				})
			}
		}
	}

	// 检查是否已达到最大IP数量限制
	maxIPRecords := ch.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	ch.logger.Debug("📊 初始IP收集完成", map[string]interface{}{
		"domain":           domain,
		"initial_ip_count": len(allIPRecords),
		"max_limit":        maxIPRecords,
		"need_more":        len(allIPRecords) < maxIPRecords,
		"missing_count":    maxIPRecords - len(allIPRecords),
	})

	// 如果已达到最大IP数量限制，直接返回
	if len(allIPRecords) >= maxIPRecords {
		ch.logger.Debug("✅ 初始IP已满足需求，无需解析CNAME", map[string]interface{}{
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

		// 添加所有收集到的IP记录
		for _, record := range allIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

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

		// 添加所有收集到的IP记录
		for _, record := range allIPRecords {
			processedResp.Answer = append(processedResp.Answer, record)
		}

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

	// 使用DFS（深度优先搜索）来遍历CNAME图
	type DomainInfo struct {
		name      string
		upstreams []string
	}

	// 使用栈来实现迭代式DFS，避免递归导致的栈溢出
	stack := []DomainInfo{}
	processed := make(map[string]bool)      // 记录已处理的域名，避免重复处理
	alreadyInStack := make(map[string]bool) // 记录已在栈中的域名，避免重复添加

	// 先将原始CNAME目标添加到处理队列
	for _, cname := range initialCNAMEs {
		target := strings.ToLower(strings.TrimSuffix(cname.Target, "."))
		origin := strings.ToLower(strings.TrimSuffix(cname.Hdr.Name, "."))

		// 避免自引用CNAME
		if target != origin && !processed[target] && !alreadyInStack[target] {
			stack = append(stack, DomainInfo{name: target, upstreams: upstreams})
			alreadyInStack[target] = true
			processed[target] = true // 立即标记为已处理，避免其他路径重复添加
		}
	}

	for len(stack) > 0 && len(allIPRecords) < maxIPRecords {
		// 取出栈顶元素
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		delete(alreadyInStack, current.name) // 从待处理集合中移除

		ch.logger.Debug("🔄 处理CNAME链", map[string]interface{}{
			"domain":           current.name,
			"from_stack":       len(stack),
			"current_ip_count": len(allIPRecords),
			"max_limit":        maxIPRecords,
		})

		// 检查缓存中是否已有该域名的响应
		cachedResp, hit, _, _ := ch.cacheManager.Get(current.name, resp.Question[0].Qtype)
		var queryResp *dns.Msg
		var err error

		if hit && cachedResp != nil {
			ch.logger.Debug("🎯 使用缓存响应", map[string]interface{}{
				"domain":        current.name,
				"answers_count": len(cachedResp.Answer),
			})
			queryResp = cachedResp
		} else {
			// 如果缓存中没有，再发起查询
			queryReq := &dns.Msg{}
			queryReq.SetQuestion(dns.Fqdn(current.name), resp.Question[0].Qtype)

			queryResp, err = ch.proxyQuery(queryReq, current.upstreams)
			if err != nil || queryResp == nil || queryResp.Rcode != dns.RcodeSuccess {
				ch.logger.Debug("❌ 域名查询失败", map[string]interface{}{
					"domain": current.name,
					"error":  err,
				})
				continue
			}

			// 将查询结果缓存
			ch.cacheManager.Set(current.name, resp.Question[0].Qtype, queryResp, false)
		}

		ch.logger.Debug("📥 域名查询成功", map[string]interface{}{
			"domain":        current.name,
			"answers_count": len(queryResp.Answer),
		})

		// 遍历响应中的所有记录
		for _, rr := range queryResp.Answer {
			if len(allIPRecords) >= maxIPRecords {
				break // 已达到最大IP数量限制
			}

			switch record := rr.(type) {
			case *dns.A:
				ipStr := record.A.String()
				ch.logger.Debug("📡 收集到A记录IP", map[string]interface{}{
					"domain":       current.name,
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
					ch.logger.Debug("✅ 添加IP到结果", map[string]interface{}{
						"ip":          ipStr,
						"total_count": len(allIPRecords),
					})
				}
			case *dns.AAAA:
				ipStr := record.AAAA.String()
				ch.logger.Debug("📡 收集到AAAA记录IP", map[string]interface{}{
					"domain":       current.name,
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
					ch.logger.Debug("✅ 添加IPV6到结果", map[string]interface{}{
						"ip":          ipStr,
						"total_count": len(allIPRecords),
					})
				}
			case *dns.CNAME:
				ch.logger.Debug("🔗 发现CNAME记录", map[string]interface{}{
					"domain": current.name,
					"target": record.Target,
				})

				// 将CNAME目标加入待处理队列
				target := strings.ToLower(strings.TrimSuffix(record.Target, "."))
				origin := strings.ToLower(strings.TrimSuffix(record.Hdr.Name, "."))

				// 避免自引用CNAME，且只有在还需要IP时才继续解析
				if target != origin && !processed[target] && !alreadyInStack[target] && len(allIPRecords) < maxIPRecords {
					ch.logger.Debug("📋 将CNAME目标加入处理队列", map[string]interface{}{
						"target": target,
						"origin": origin,
					})
					stack = append(stack, DomainInfo{name: target, upstreams: current.upstreams})
					alreadyInStack[target] = true
					processed[target] = true // 立即标记为已处理，避免重复添加
				} else {
					ch.logger.Debug("⚠️ 检测到自引用CNAME或已达IP限制，跳过", map[string]interface{}{
						"domain":    target,
						"need_more": len(allIPRecords) < maxIPRecords,
					})
				}
			}
		}

		ch.logger.Debug("📊 当前收集状态", map[string]interface{}{
			"domain":              current.name,
			"total_ips_collected": len(allIPRecords),
			"max_limit":           maxIPRecords,
		})

		// 检查是否已达到最大IP数量限制
		if len(allIPRecords) >= maxIPRecords {
			ch.logger.Debug("🏁 达到最大IP数量限制，停止处理", map[string]interface{}{
				"limit":     maxIPRecords,
				"collected": len(allIPRecords),
			})
			break
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

	// 添加所有收集到的IP记录
	for _, record := range allIPRecords {
		processedResp.Answer = append(processedResp.Answer, record)
	}

	ch.logger.Debug("✅ CNAME积极解析完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  ch.countType(processedResp.Answer, "A"),
		"ipv6_count":  ch.countType(processedResp.Answer, "AAAA"),
		"all_collected_ips": func() []string {
			var ips []string
			for _, record := range allIPRecords {
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
func (ch *CloudHandler) isSameIP(rr1, rr2 dns.RR) bool {
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

// processDNSResponseWithCNAME 处理DNS响应并递归解析CNAME记录
// 完整实现：收集所有CNAME记录并递归解析，获取IP后按需补充原始IP记录
func (ch *CloudHandler) processDNSResponseWithCNAME(resp *dns.Msg, domain string, upstreams []string) *dns.Msg {
	if resp == nil {
		return resp
	}

	// 分离CNAME记录和IP记录
	var cnames []*dns.CNAME
	var ipRecords []dns.RR

	for _, rr := range resp.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, cname)
		} else if _, ok := rr.(*dns.A); ok || ch.isAAAARecord(rr) {
			ipRecords = append(ipRecords, rr)
		}
	}

	// 获取最大IP记录数配置，默认为2
	maxIPRecords := ch.config.MaxIPRecords
	if maxIPRecords <= 0 {
		maxIPRecords = 2 // 默认值
	}

	// 创建结果存储
	var finalIPRecords []dns.RR

	// 如果有CNAME记录，优先递归解析
	if len(cnames) > 0 {
		ch.logger.Debug("🔍 检测到CNAME记录，开始递归解析", map[string]interface{}{
			"domain":         domain,
			"cname_count":    len(cnames),
			"max_ip_records": maxIPRecords,
		})

		// 递归解析所有CNAME记录
		for _, cname := range cnames {
			if len(finalIPRecords) >= maxIPRecords {
				break // 已达到最大数量
			}

			ch.logger.Debug("🔄 解析CNAME记录", map[string]interface{}{
				"domain": domain,
				"target": cname.Target,
			})

			// 递归解析CNAME目标，使用传入的上游DNS服务器
			cnameTargetReq := &dns.Msg{}
			cnameTargetReq.SetQuestion(cname.Target, resp.Question[0].Qtype)

			cnameTargetResp, err := ch.proxyQuery(cnameTargetReq, upstreams)
			if err == nil && cnameTargetResp != nil {
				// 递归处理CNAME目标的响应
				// 注意：这里不应该再次应用IP数量限制，而是获取所有可能的IP，
				// 然后由外层逻辑统一控制最终数量
				processedCnameResp := ch.processDNSResponseWithCNAME(cnameTargetResp, cname.Target, upstreams)
				if processedCnameResp != nil {
					// 收集解析出的IP记录，不超过剩余配额
					for _, targetRR := range processedCnameResp.Answer {
						if len(finalIPRecords) >= maxIPRecords {
							break
						}
						if _, ok := targetRR.(*dns.A); ok || ch.isAAAARecord(targetRR) {
							// 检查是否已存在相同的IP记录，避免重复
							isDuplicate := false
							for _, existing := range finalIPRecords {
								if existing.String() == targetRR.String() {
									isDuplicate = true
									break
								}
							}
							if !isDuplicate {
								finalIPRecords = append(finalIPRecords, targetRR)
							}
						}
					}
				}
			} else {
				ch.logger.Debug("❌ CNAME解析失败", map[string]interface{}{
					"domain": domain,
					"target": cname.Target,
					"error":  err,
				})
			}
		}
	}

	// 按IPv4和IPv6分别计数
	var ipv4Records []dns.RR
	var ipv6Records []dns.RR

	for _, record := range finalIPRecords {
		if _, ok := record.(*dns.A); ok {
			ipv4Records = append(ipv4Records, record)
		} else if ch.isAAAARecord(record) {
			ipv6Records = append(ipv6Records, record)
		}
	}

	// IPv4和IPv6各自独立限制为配置的最大值
	maxIPv4 := maxIPRecords
	maxIPv6 := maxIPRecords

	// 截取IPv4和IPv6记录
	var resultRecords []dns.RR

	// 添加IPv4记录（最多maxIPv4个）
	for i, record := range ipv4Records {
		if i >= maxIPv4 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 添加IPv6记录（最多maxIPv6个）
	for i, record := range ipv6Records {
		if i >= maxIPv6 {
			break
		}
		resultRecords = append(resultRecords, record)
	}

	// 如果数量不足，尝试补充原始IP记录
	remainingSlots := maxIPRecords - len(resultRecords)
	if remainingSlots > 0 {
		// 按IPv4和IPv6分别补充
		var additionalIPv4 []dns.RR
		var additionalIPv6 []dns.RR

		for _, record := range ipRecords {
			if _, ok := record.(*dns.A); ok {
				// 检查是否已达到IPv4最大数量
				currentIPv4Count := 0
				for _, res := range resultRecords {
					if _, ok := res.(*dns.A); ok {
						currentIPv4Count++
					}
				}
				if currentIPv4Count < maxIPv4 {
					additionalIPv4 = append(additionalIPv4, record)
				}
			} else if ch.isAAAARecord(record) {
				// 检查是否已达到IPv6最大数量
				currentIPv6Count := 0
				for _, res := range resultRecords {
					if ch.isAAAARecord(res) {
						currentIPv6Count++
					}
				}
				if currentIPv6Count < maxIPv6 {
					additionalIPv6 = append(additionalIPv6, record)
				}
			}
		}

		// 补充IPv4记录
		for _, record := range additionalIPv4 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}

		// 补充IPv6记录
		for _, record := range additionalIPv6 {
			if len(resultRecords) >= maxIPRecords {
				break
			}
			// 确保没有重复
			isDuplicate := false
			for _, existing := range resultRecords {
				if existing.String() == record.String() {
					isDuplicate = true
					break
				}
			}
			if !isDuplicate {
				resultRecords = append(resultRecords, record)
			}
		}
	}

	// 创建并填充最终响应
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

	// 添加IP记录到响应
	for _, record := range resultRecords {
		newRecord := dns.Copy(record)
		newRecord.Header().Name = dns.Fqdn(domain)
		processedResp.Answer = append(processedResp.Answer, newRecord)
	}

	ch.logger.Debug("✅ CNAME处理完成", map[string]interface{}{
		"domain":      domain,
		"final_count": len(processedResp.Answer),
		"max_allowed": maxIPRecords,
		"ipv4_count":  ch.countType(processedResp.Answer, "A"),
		"ipv6_count":  ch.countType(processedResp.Answer, "AAAA"),
	})

	return processedResp
}

// isAAAARecord 检查记录是否为AAAA记录
func (ch *CloudHandler) isAAAARecord(rr dns.RR) bool {
	_, ok := rr.(*dns.AAAA)
	return ok
}

// countType 计算指定类型的记录数量
func (ch *CloudHandler) countType(records []dns.RR, recordType string) int {
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

// ensureMinimumTTL 确保响应中的 TTL 不小于指定的最小值
func (ch *CloudHandler) ensureMinimumTTL(resp *dns.Msg, minTTL time.Duration) {
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

// sendErrorResponse 发送错误响应
func (ch *CloudHandler) sendErrorResponse(w dns.ResponseWriter, req *dns.Msg, rcode int) error {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	w.WriteMsg(resp)
	return nil
}
