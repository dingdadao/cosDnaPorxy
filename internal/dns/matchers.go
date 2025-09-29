package dns

import (
	"bufio"
	"cosDnaPorxy/internal/utils"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// WhitelistMatcher 白名单匹配器
type WhitelistMatcher struct {
	patterns []string
	mu       sync.RWMutex
	logger   *utils.EnhancedLogger
}

// DesignatedMatcher 定向域名匹配器
type DesignatedMatcher struct {
	domains []*DesignatedDomain
	mu      sync.RWMutex
	logger  *utils.EnhancedLogger
}

// DesignatedDomain 定向域名配置
type DesignatedDomain struct {
	Domain       string
	Pattern      string // 添加原始模式字符串
	DNS          string
	Regex        *regexp.Regexp
	UpstreamType string
}

// IsWhitelisted 检查域名是否在白名单中
func (wm *WhitelistMatcher) IsWhitelisted(domain string) bool {
	wm.mu.RLock()
	defer wm.mu.RUnlock()

	for _, pattern := range wm.patterns {
		if wm.matchPattern(pattern, domain) {
			wm.logger.Debug("✅ 白名单匹配", map[string]interface{}{
				"domain":  domain,
				"pattern": pattern,
			})
			return true
		}
	}

	return false
}

// matchPattern 匹配模式
func (wm *WhitelistMatcher) matchPattern(pattern, domain string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	domain = strings.ToLower(domain)

	// 完全匹配
	if pattern == domain {
		return true
	}

	// 通配符前缀：*.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}

	// 通配符后缀：example.*
	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2]
		if domain == prefix || strings.HasPrefix(domain, prefix+".") {
			return true
		}
	}

	// 简单包含匹配
	if strings.Contains(pattern, "*") {
		// 转为正则表达式
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")

		if re, err := regexp.Compile(regexPattern); err == nil {
			return re.MatchString(domain)
		}
	}

	return false
}

// LoadWhitelist 加载白名单
func (wm *WhitelistMatcher) LoadWhitelist(filePath string) error {
	timer := wm.logger.StartTimer("load_whitelist")
	defer timer.End()

	if filePath == "" {
		wm.logger.Warn("白名单文件路径为空")
		return nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		wm.logger.Warn("白名单文件不存在，创建默认文件", map[string]interface{}{
			"file": filePath,
		})

		defaultContent := `# 白名单域名列表
# 支持格式：
# example.com - 完全匹配
# *.example.com - 通配符前缀匹配
# example.* - 通配符后缀匹配

# 示例条目
*.cloudflare.com
*.amazonaws.com
`
		if err := os.WriteFile(filePath, []byte(defaultContent), 0644); err != nil {
			return fmt.Errorf("创建默认白名单文件失败: %w", err)
		}
	}

	patterns, err := wm.readLines(filePath)
	if err != nil {
		return fmt.Errorf("读取白名单文件失败: %w", err)
	}

	wm.mu.Lock()
	wm.patterns = patterns
	wm.mu.Unlock()

	wm.logger.Info("📋 白名单加载完成", map[string]interface{}{
		"file":  filePath,
		"count": len(patterns),
	})

	return nil
}

// GetDesignatedDomain 获取匹配的定向域名
func (dm *DesignatedMatcher) GetDesignatedDomain(domain string) *DesignatedDomain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	for _, dd := range dm.domains {
		if dd.Regex != nil && dd.Regex.MatchString(domain) {
			dm.logger.Debug("🎯 定向域名匹配", map[string]interface{}{
				"domain":     domain,
				"designated": dd.Domain,
				"dns":        dd.DNS,
			})
			return dd
		}
	}

	return nil
}

// LoadDesignatedDomains 加载定向域名
func (dm *DesignatedMatcher) LoadDesignatedDomains(filePath string) error {
	timer := dm.logger.StartTimer("load_designated_domains")
	defer timer.End()

	if filePath == "" {
		dm.logger.Warn("定向域名文件路径为空")
		return nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		dm.logger.Warn("定向域名文件不存在，创建默认文件", map[string]interface{}{
			"file": filePath,
		})

		defaultContent := `# 定向域名配置
# 格式: 域名模式 DNS服务器
# 示例:
# *.example.com 8.8.8.8:53
# *.test.local 192.168.1.1:53
# *.internal https://dns.example.com/dns-query

# 测试条目
*.local 192.168.1.1:53
`
		if err := os.WriteFile(filePath, []byte(defaultContent), 0644); err != nil {
			return fmt.Errorf("创建默认定向域名文件失败: %w", err)
		}
	}

	lines, err := dm.readLines(filePath)
	if err != nil {
		return fmt.Errorf("读取定向域名文件失败: %w", err)
	}

	var domains []*DesignatedDomain
	for lineNum, line := range lines {
		dd, err := dm.parseDesignatedLine(line)
		if err != nil {
			dm.logger.Warn("解析定向域名配置失败", map[string]interface{}{
				"line":    lineNum + 1,
				"content": line,
				"error":   err.Error(),
			})
			continue
		}
		domains = append(domains, dd)
	}

	dm.mu.Lock()
	dm.domains = domains
	dm.mu.Unlock()

	dm.logger.Info("🎯 定向域名加载完成", map[string]interface{}{
		"file":  filePath,
		"count": len(domains),
	})

	return nil
}

// parseDesignatedLine 解析定向域名配置行
func (dm *DesignatedMatcher) parseDesignatedLine(line string) (*DesignatedDomain, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("格式错误，需要：域名 DNS服务器")
	}

	domainPattern := parts[0]
	dnsServer := parts[1]

	// 构建正则表达式
	pattern := strings.ReplaceAll(domainPattern, "*", ".*")
	pattern = "^" + pattern + "$"

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("正则表达式编译失败: %w", err)
	}

	// 确定上游类型
	upstreamType := "udp"
	switch {
	case strings.HasPrefix(dnsServer, "https://"):
		upstreamType = "doh"
	case strings.HasPrefix(dnsServer, "tls://"):
		upstreamType = "dot"
	}

	return &DesignatedDomain{
		Domain:       domainPattern,
		Pattern:      domainPattern, // 设置原始模式字符串
		DNS:          dnsServer,
		Regex:        regex,
		UpstreamType: upstreamType,
	}, nil
}

// readLines 读取文件行
func (wm *WhitelistMatcher) readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// readLines 读取文件行（定向域名版本）
func (dm *DesignatedMatcher) readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// 跳过空行和注释
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}

	return lines, scanner.Err()
}

// loadAllData 加载所有配置数据
func (h *RefactoredHandler) loadAllData() error {
	var lastErr error

	// 加载云服务网段
	if err := h.cloudDetector.LoadNetworkRanges(
		h.config.CloudflareNetFile,
		h.config.CloudflareNetFile6,
		h.config.AWSNetFile,
	); err != nil {
		h.Logger.Error("加载云服务网段失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	// 加载白名单
	if err := h.whitelistMatcher.LoadWhitelist(h.config.WhitelistFile); err != nil {
		h.Logger.Error("加载白名单失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	// 加载定向域名
	if err := h.designatedMatcher.LoadDesignatedDomains(h.config.DesignatedDomain); err != nil {
		h.Logger.Error("加载定向域名失败", map[string]interface{}{
			"error": err.Error(),
		})
		lastErr = err
	}

	return lastErr
}

// refreshDNSRecord 刷新DNS记录（缓存回调）
func (h *RefactoredHandler) refreshDNSRecord(domain string, qtype uint16) error {
	h.Logger.Info("🔄 [缓存刷新开始] ", map[string]interface{}{
		"domain": domain,
		"rule":   "CACHE_REFRESH_START",
	})

	h.Logger.Debug("异步缓存刷新查询开始", map[string]interface{}{
		"domain":    domain,
		"qtype":     dns.TypeToString[qtype],
		"upstreams": h.config.Upstream,
	})

	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 使用类型断言调用不同类型的查询优化器
	var result *ConcurrentQueryResult
	if modernOptimizer, ok := h.queryOptimizer.(*SimpleModernOptimizer); ok {
		// 使用现代查询优化器
		result = modernOptimizer.Query(req, h.config.Upstream)
	} else if traditionalOptimizer, ok := h.queryOptimizer.(*FastQueryOptimizer); ok {
		// 使用传统查询优化器
		result = traditionalOptimizer.Query(req, h.config.Upstream)
	} else {
		h.Logger.Error("❗ [缓存刷新失败] ", map[string]interface{}{
			"domain": domain,
			"rule":   "CACHE_REFRESH_FAILED",
			"error":  "unknown query optimizer type",
		})
		return fmt.Errorf("unknown query optimizer type")
	}
	if result.FastestResult == nil || result.FastestResult.Error != nil {
		errorMsg := "all upstream queries failed"
		if result.FastestResult != nil && result.FastestResult.Error != nil {
			errorMsg = result.FastestResult.Error.Error()
		}
		h.Logger.Error("❌ [缓存刷新失败] ", map[string]interface{}{
			"domain": domain,
			"rule":   "CACHE_REFRESH_FAILED",
			"error":  errorMsg,
		})
		return fmt.Errorf(errorMsg)
	}

	// 验证查询结果：必须有成功响应且包含实际答案记录
	if result.HasSuccess && result.SuccessResult != nil &&
		result.SuccessResult.Response != nil &&
		result.SuccessResult.Response.Rcode == dns.RcodeSuccess &&
		len(result.SuccessResult.Response.Answer) > 0 {

		// 检查是否为云服务
		detection := h.cloudDetector.DetectCloudService(result.SuccessResult.Response)
		isCloud := detection.Type != CloudTypeNone

		if isCloud {
			h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, isCloud, int(detection.Type))
		} else {
			h.cacheManager.Set(domain, qtype, result.SuccessResult.Response, isCloud)
		}

		h.Logger.Info("✅ [缓存刷新成功] ", map[string]interface{}{
			"domain":       domain,
			"rule":         "CACHE_REFRESH_SUCCESS",
			"is_cloud":     isCloud,
			"answer_count": len(result.SuccessResult.Response.Answer),
		})

		h.Logger.Debug("缓存刷新详细信息", map[string]interface{}{
			"domain":        domain,
			"qtype":         dns.TypeToString[qtype],
			"is_cloud":      isCloud,
			"response_time": result.SuccessResult.ResponseTime.String(),
			"answer_count":  len(result.SuccessResult.Response.Answer),
			"rcode":         dns.RcodeToString[result.SuccessResult.Response.Rcode],
		})
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

		h.Logger.Warn("⚠️ [缓存刷新跳过] ", map[string]interface{}{
			"domain":         domain,
			"rule":           "CACHE_REFRESH_SKIP",
			"reason":         failureReason,
			"has_result":     result.FastestResult != nil,
			"has_success":    result.HasSuccess,
			"success_result": result.SuccessResult != nil,
		})

		// 不更新缓存，保持原有缓存内容
		h.Logger.Debug("异步刷新未更新缓存，保持原有缓存内容", map[string]interface{}{
			"domain": domain,
			"qtype":  dns.TypeToString[qtype],
		})
	}

	return nil
}

// startBackgroundTasks 启动后台任务
func (h *RefactoredHandler) startBackgroundTasks() {
	// 白名单刷新任务
	if h.config.WhitelistFile != "" && h.config.WhitelistRefreshInterval > 0 {
		go h.whitelistRefreshTask()
	}

	// 定向域名刷新任务
	if h.config.DesignatedDomain != "" && h.config.DesignatedRefreshInterval > 0 {
		go h.designatedRefreshTask()
	}

	// 网络段刷新任务
	if h.config.NetworkRefreshInterval > 0 {
		go h.networkRefreshTask()
	}
}

// whitelistRefreshTask 白名单刷新任务
func (h *RefactoredHandler) whitelistRefreshTask() {
	ticker := time.NewTicker(h.config.WhitelistRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [白名单定时刷新启动] ", map[string]interface{}{
		"rule":     "WHITELIST_REFRESH_TASK",
		"interval": h.config.WhitelistRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时白名单刷新", map[string]interface{}{
				"file": h.config.WhitelistFile,
			})
			if err := h.whitelistMatcher.LoadWhitelist(h.config.WhitelistFile); err != nil {
				h.Logger.Error("❌ [白名单刷新失败] ", map[string]interface{}{
					"rule":  "WHITELIST_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [白名单刷新成功] ", map[string]interface{}{
					"rule": "WHITELIST_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [白名单刷新任务停止] ", map[string]interface{}{
				"rule": "WHITELIST_REFRESH_STOPPED",
			})
			return
		}
	}
}

// designatedRefreshTask 定向域名刷新任务
func (h *RefactoredHandler) designatedRefreshTask() {
	ticker := time.NewTicker(h.config.DesignatedRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [定向域名定时刷新启动] ", map[string]interface{}{
		"rule":     "DESIGNATED_REFRESH_TASK",
		"interval": h.config.DesignatedRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时定向域名刷新", map[string]interface{}{
				"file": h.config.DesignatedDomain,
			})
			if err := h.designatedMatcher.LoadDesignatedDomains(h.config.DesignatedDomain); err != nil {
				h.Logger.Error("❌ [定向域名刷新失败] ", map[string]interface{}{
					"rule":  "DESIGNATED_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [定向域名刷新成功] ", map[string]interface{}{
					"rule": "DESIGNATED_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [定向域名刷新任务停止] ", map[string]interface{}{
				"rule": "DESIGNATED_REFRESH_STOPPED",
			})
			return
		}
	}
}

// networkRefreshTask 网络段刷新任务
func (h *RefactoredHandler) networkRefreshTask() {
	ticker := time.NewTicker(h.config.NetworkRefreshInterval)
	defer ticker.Stop()

	h.Logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
		"rule":     "NETWORK_REFRESH_TASK",
		"interval": h.config.NetworkRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			h.Logger.Debug("开始定时网络段刷新", map[string]interface{}{
				"cloudflare_v4": h.config.CloudflareNetFile,
				"cloudflare_v6": h.config.CloudflareNetFile6,
				"aws_file":      h.config.AWSNetFile,
			})
			if err := h.cloudDetector.LoadNetworkRanges(
				h.config.CloudflareNetFile,
				h.config.CloudflareNetFile6,
				h.config.AWSNetFile,
			); err != nil {
				h.Logger.Error("❌ [网络段刷新失败] ", map[string]interface{}{
					"rule":  "NETWORK_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				h.Logger.Info("✅ [网络段刷新成功] ", map[string]interface{}{
					"rule": "NETWORK_REFRESH_SUCCESS",
				})
			}
		case <-h.ctx.Done():
			h.Logger.Info("📋 [网络段刷新任务停止] ", map[string]interface{}{
				"rule": "NETWORK_REFRESH_STOPPED",
			})
			return
		}
	}
}
