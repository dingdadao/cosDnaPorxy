package dns

import (
	"bufio"
	"cosDnaPorxy/internal/config"
	"os"
	"regexp"
	"strings"
	"time"
)

// loadWhitelist 加载白名单
func (h *Handler) loadWhitelist() {
	if h.config.WhitelistFile == "" {
		h.logger.Warn("Whitelist file not configured")
		return
	}

	// 尝试创建文件（如果不存在）
	if _, err := os.Stat(h.config.WhitelistFile); os.IsNotExist(err) {
		h.logger.Warn("Whitelist file does not exist, creating: %s", h.config.WhitelistFile)
		err := os.WriteFile(h.config.WhitelistFile, []byte("# Whitelist domains\nexample.com\n"), 0644)
		if err != nil {
			h.logger.Error("Failed to create whitelist file: %v", err)
			return
		}
	}

	f, err := os.Open(h.config.WhitelistFile)
	if err != nil {
		h.logger.Error("Failed to open whitelist: %v", err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var newList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			newList = append(newList, line)
		}
	}

	if err := scanner.Err(); err != nil {
		h.logger.Error("Error reading whitelist file: %v", err)
		return
	}

	h.Lock()
	h.whitelistPattern = newList
	h.Unlock()

	h.logger.Info("✅ Whitelist updated successfully: %d entries", len(newList))
}

// loadDesignatedDomains 加载定向域名规则
func (h *Handler) loadDesignatedDomains() {
	if h.config.DesignatedDomain == "" {
		h.logger.Warn("Designated domains file not configured")
		return
	}

	// 文件不存在则创建默认
	if _, err := os.Stat(h.config.DesignatedDomain); os.IsNotExist(err) {
		h.logger.Warn("Designated domains file not found, creating: %s", h.config.DesignatedDomain)
		defaultContent := []byte("# Format: domain dns_server\n*.example.com 8.8.8.8\n")
		if err := os.WriteFile(h.config.DesignatedDomain, defaultContent, 0644); err != nil {
			h.logger.Error("Failed to create designated domains file: %v", err)
			return
		}
	}

	f, err := os.Open(h.config.DesignatedDomain)
	if err != nil {
		h.logger.Error("Failed to open designated domains file: %v", err)
		return
	}
	defer f.Close()

	var newRules []DesignatedDomain
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			h.logger.Warn("Invalid line format, skipping: %s", line)
			continue
		}

		rawPattern := strings.ToLower(parts[0])
		var regexPattern string
		if strings.Contains(rawPattern, "*") {
			// 通配符转正则 - 修复转义问题
			if strings.HasPrefix(rawPattern, "*.") {
				// 处理 *.lan 格式 - 匹配以 .lan 结尾的域名
				suffix := rawPattern[2:] // 去掉 "*."
				regexPattern = "^.*\\." + regexp.QuoteMeta(suffix) + "$"
				h.logger.Debug("通配符转换: %s -> 以.%s结尾 -> %s", rawPattern, suffix, regexPattern)
			} else {
				// 其他通配符格式
				tempPattern := strings.ReplaceAll(rawPattern, "*", ".*")
				regexPattern = "^" + regexp.QuoteMeta(tempPattern) + "$"
				regexPattern = strings.ReplaceAll(regexPattern, `\\.\*`, ".*")
				h.logger.Debug("通配符转换: %s -> %s -> %s", rawPattern, tempPattern, regexPattern)
			}
		} else if strings.HasPrefix(rawPattern, "/") && strings.HasSuffix(rawPattern, "/") && len(rawPattern) > 2 {
			// 允许用户直接写正则，如 /mgstage.*/
			regexPattern = rawPattern[1 : len(rawPattern)-1]
		} else {
			// 关键词自动模糊匹配
			regexPattern = ".*" + regexp.QuoteMeta(rawPattern) + ".*"
		}

		re, err := regexp.Compile(regexPattern)
		if err != nil {
			h.logger.Warn("Invalid regex for pattern: %s (%v)", rawPattern, err)
			continue
		}

		upstreamType := ""
		upstreamVal := strings.ToLower(parts[1])
		if upstreamVal == "cn_upstream" || upstreamVal == "not_cn_upstream" {
			upstreamType = upstreamVal
		}

		newRules = append(newRules, DesignatedDomain{
			Domain:       rawPattern,
			DNS:          parts[1],
			Regex:        re,
			UpstreamType: upstreamType,
		})
		
		// 添加调试日志
		h.logger.Debug("加载规则: %s -> %s (正则: %s, 类型: %s)", rawPattern, parts[1], regexPattern, upstreamType)
	}

	if err := scanner.Err(); err != nil {
		h.logger.Error("Error reading designated domains file: %v", err)
		return
	}

	h.Lock()
	h.designatedRules = newRules
	h.Unlock()

	h.logger.Info("✅ Designated domains updated successfully: %d entries", len(newRules))
}

// updateNetworks 更新网络列表
func (h *Handler) updateNetworks(cfg *config.Config) {
	h.Lock()
	defer h.Unlock()

	if time.Since(h.lastCFUpdate) < h.cfExpire {
		return
	}

	h.logger.Info("Loading Cloudflare and AWS IP ranges from local cache...")

	cfCachePath4 := cfg.CFMrsFile4
	cfCachePath6 := cfg.CFMrsFile6
	aWSCachePath := cfg.AWSMrsFile46

	// 加载 Cloudflare IPv4
	if _, err := os.Stat(cfCachePath4); err == nil {
		if err := h.cfNetSet4.LoadFromFile(cfCachePath4); err != nil {
			h.logger.Error("Failed to load IPv4 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv4 prefixes", len(h.cfNetSet4.list))
		}
	} else {
		h.logger.Warn("IPv4 cache file not found: %s", cfCachePath4)
	}

	// 加载 Cloudflare IPv6
	if _, err := os.Stat(cfCachePath6); err == nil {
		if err := h.cfNetSet6.LoadFromFile(cfCachePath6); err != nil {
			h.logger.Error("Failed to load IPv6 ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv6 prefixes", len(h.cfNetSet6.list))
		}
	} else {
		h.logger.Warn("IPv6 cache file not found: %s", cfCachePath6)
	}

	// 加载 AWS IP 段
	if _, err := os.Stat(aWSCachePath); err == nil {
		err := LoadAWSIPRanges(aWSCachePath, h.aWSNetSet4, h.aWSNetSet6)
		if err != nil {
			h.logger.Error("Failed to load AWS IP ranges: %v", err)
		} else {
			h.logger.Info("Loaded %d IPv4 prefixes and %d IPv6 prefixes from AWS",
				len(h.aWSNetSet4.list), len(h.aWSNetSet6.list))
		}
	} else {
		h.logger.Warn("AWS cache file not found: %s", aWSCachePath)
	}

	h.lastCFUpdate = time.Now()
}

// runBackgroundTasks 运行后台任务
func (h *Handler) runBackgroundTasks(cfg *config.Config) {
	// 定时更新Cloudflare网络列表
	cfTicker := time.NewTicker(5 * time.Minute)
	defer cfTicker.Stop()

	// 定时重新加载白名单和定向域名
	reloadTicker := time.NewTicker(1 * time.Minute)
	defer reloadTicker.Stop()

	geositeTicker := time.NewTicker(h.geositeManager.GetRefreshDuration())
	defer geositeTicker.Stop()

	for {
		select {
		case <-cfTicker.C:
			h.updateNetworks(cfg)
		case <-reloadTicker.C:
			h.loadWhitelist()
			h.loadDesignatedDomains()
		case <-geositeTicker.C:
			h.geositeManager.UpdateGeoSite()
		}
	}
}

// isWhitelisted 检查域名是否在白名单中
func (h *Handler) isWhitelisted(qname string) bool {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, pattern := range h.whitelistPattern {
		pattern = strings.ToLower(pattern)
		
		// 精确匹配
		if domain == pattern {
			return true
		}
		
		// 通配符匹配 (*.example.com)
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[2:] // 去掉 "*."
			if strings.HasSuffix(domain, "."+suffix) || domain == suffix {
				return true
			}
		}
		
		// 后缀匹配 (example.com)
		if strings.HasSuffix(domain, "."+pattern) || domain == pattern {
			return true
		}
	}
	return false
}

// matchDesignatedDomain 匹配定向域名
func (h *Handler) matchDesignatedDomain(qname string) (*DesignatedDomain, bool) {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, rule := range h.designatedRules {
		if rule.Regex != nil {
			if rule.Regex.(*regexp.Regexp).MatchString(domain) {
				h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
				return &rule, true
			}
		} else {
			pattern := strings.ToLower(rule.Domain)
			if strings.Contains(domain, pattern) || strings.HasSuffix(domain, "."+pattern) {
				h.logger.Debug("Match designated domain: %s via pattern %s", domain, rule.Domain)
				return &rule, true
			}
		}
	}
	return nil, false
}

// getDesignatedRuleForDomain 获取域名的定向规则（不进行匹配，仅查找）
func (h *Handler) getDesignatedRuleForDomain(qname string) (*DesignatedDomain, bool) {
	domain := strings.ToLower(strings.TrimSuffix(qname, "."))
	h.RLock()
	defer h.RUnlock()

	for _, rule := range h.designatedRules {
		if rule.Regex != nil {
			if rule.Regex.(*regexp.Regexp).MatchString(domain) {
				return &rule, true
			}
		} else {
			pattern := strings.ToLower(rule.Domain)
			if strings.Contains(domain, pattern) || strings.HasSuffix(domain, "."+pattern) {
				return &rule, true
			}
		}
	}
	return nil, false
}

// 判断是否为Cloudflare域名
func (h *Handler) isCloudflareDomain(domain string) bool {
	return strings.HasSuffix(domain, ".cloudflare.com") || strings.HasSuffix(domain, ".cf.cloudflare.com")
}

// 判断是否为AWS域名
func (h *Handler) isAWSDomain(domain string) bool {
	return strings.HasSuffix(domain, ".amazonaws.com") || strings.HasSuffix(domain, ".cloudfront.net")
}

// 新增：判断上游是否为国内分流
func (h *Handler) isCNUpstream(server string) bool {
	for _, s := range h.config.CNUpstream {
		if s == server {
			return true
		}
	}
	return false
} 