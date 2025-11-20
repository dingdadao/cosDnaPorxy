package dns

import (
	"bufio"
	"cosDnaPorxy/internal/utils"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
)

// MatchResult 匹配结果
type MatchResult struct {
	Matched bool
	DNS     string
	Pattern string
	Type    string
}

// DomainTrie 域名前缀树结构
type DomainTrie struct {
	children     map[string]*DomainTrie
	dnsServer    string
	pattern      string
	upstreamType string
	isWildcard   bool
	parent       *DomainTrie // 父节点指针，用于多级通配符匹配
}

// NewDomainTrie 创建新的域名前缀树
func NewDomainTrie() *DomainTrie {
	return &DomainTrie{
		children: make(map[string]*DomainTrie),
	}
}

// Insert 插入域名模式
func (t *DomainTrie) Insert(pattern, dnsServer, upstreamType string) {
	if strings.HasPrefix(pattern, "*.") {
		// 处理通配符前缀：*.example.com
		domain := pattern[2:]
		parts := strings.Split(domain, ".")
		// 反向存储：com.example
		reverseParts := make([]string, len(parts))
		for i := 0; i < len(parts); i++ {
			reverseParts[i] = parts[len(parts)-1-i]
		}

		current := t
		for _, part := range reverseParts {
			if current.children[part] == nil {
				newNode := NewDomainTrie()
				newNode.parent = current // 设置父节点指针
				current.children[part] = newNode
			}
			current = current.children[part]
		}
		current.dnsServer = dnsServer
		current.pattern = pattern
		current.upstreamType = upstreamType
		current.isWildcard = true
	} else {
		// 处理精确匹配：example.com
		parts := strings.Split(pattern, ".")
		reverseParts := make([]string, len(parts))
		for i := 0; i < len(parts); i++ {
			reverseParts[i] = parts[len(parts)-1-i]
		}

		current := t
		for _, part := range reverseParts {
			if current.children[part] == nil {
				newNode := NewDomainTrie()
				newNode.parent = current // 设置父节点指针
				current.children[part] = newNode
			}
			current = current.children[part]
		}
		current.dnsServer = dnsServer
		current.pattern = pattern
		current.upstreamType = upstreamType
		current.isWildcard = false
	}
}

// Search 搜索域名匹配
func (t *DomainTrie) Search(domain string) *MatchResult {
	parts := strings.Split(strings.ToLower(domain), ".")
	reverseParts := make([]string, len(parts))
	for i := 0; i < len(parts); i++ {
		reverseParts[i] = parts[len(parts)-1-i]
	}

	current := t
	var lastWildcardMatch *DomainTrie

	for i, part := range reverseParts {
		// 检查精确匹配
		if next := current.children[part]; next != nil {
			current = next
			// 记录最后一个通配符匹配
			if current.isWildcard && current.dnsServer != "" {
				lastWildcardMatch = current
			}
			// 如果是最后一个部分且有精确匹配
			if i == len(reverseParts)-1 && current.dnsServer != "" && !current.isWildcard {
				return &MatchResult{
					Matched: true,
					DNS:     current.dnsServer,
					Pattern: current.pattern,
					Type:    "exact",
				}
			}
		} else {
			// 没有精确匹配，检查是否有通配符匹配
			if wildcardNode := current.children["*"]; wildcardNode != nil && wildcardNode.dnsServer != "" {
				return &MatchResult{
					Matched: true,
					DNS:     wildcardNode.dnsServer,
					Pattern: wildcardNode.pattern,
					Type:    "wildcard",
				}
			}
			// 检查是否有通配符匹配（支持多级子域名）
			if lastWildcardMatch != nil {
				return &MatchResult{
					Matched: true,
					DNS:     lastWildcardMatch.dnsServer,
					Pattern: lastWildcardMatch.pattern,
					Type:    "wildcard",
				}
			}
			// 对于多级子域名，需要检查所有可能的通配符匹配
			// 遍历所有父级节点，查找通配符匹配
			tempCurrent := current
			for j := i; j < len(reverseParts); j++ {
				if wildcardNode := tempCurrent.children["*"]; wildcardNode != nil && wildcardNode.dnsServer != "" {
					return &MatchResult{
						Matched: true,
						DNS:     wildcardNode.dnsServer,
						Pattern: wildcardNode.pattern,
						Type:    "wildcard",
					}
				}
				// 移动到父节点
				if tempCurrent.parent != nil {
					tempCurrent = tempCurrent.parent
				} else {
					break
				}
			}
			break
		}
	}

	// 如果没有精确匹配，使用最后一个通配符匹配
	if lastWildcardMatch != nil {
		return &MatchResult{
			Matched: true,
			DNS:     lastWildcardMatch.dnsServer,
			Pattern: lastWildcardMatch.pattern,
			Type:    "wildcard",
		}
	}

	return &MatchResult{Matched: false}
}

// DesignatedMatcher 高性能定向域名匹配器
type DesignatedMatcher struct {
	// 基本字段
	defaultDNS string
	logger     *utils.EnhancedLogger
	mu         sync.RWMutex

	// 高性能索引结构
	trie        *DomainTrie         // 前缀树（用于大部分匹配）
	exactMap    map[string]string   // 精确匹配哈希表
	wildcards   []*DesignatedDomain // 复杂通配符（正则）
	domainCount int                 // 域名数量统计
	domains     []*DesignatedDomain // 定向域名列表
}

// DesignatedDomain 定向域名配置
type DesignatedDomain struct {
	Domain       string
	Pattern      string
	DNS          string
	Regex        *regexp.Regexp
	UpstreamType string
	MatchType    string // "exact", "wildcard", "regex"
}

// NewDesignatedMatcher 创建高性能匹配器
func NewDesignatedMatcher(logger *utils.EnhancedLogger) *DesignatedMatcher {
	return &DesignatedMatcher{
		logger:    logger,
		trie:      NewDomainTrie(),
		exactMap:  make(map[string]string),
		wildcards: make([]*DesignatedDomain, 0),
		domains:   make([]*DesignatedDomain, 0),
	}
}

// SetDefaultDNS 设置默认DNS服务器
func (dm *DesignatedMatcher) SetDefaultDNS(defaultDNS string) {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.defaultDNS = defaultDNS
	dm.logger.Info("🔧 高性能默认DNS服务器已设置", map[string]interface{}{
		"default_dns": defaultDNS,
	})
}

// GetDefaultDNS 获取默认DNS服务器
func (dm *DesignatedMatcher) GetDefaultDNS() string {
	dm.mu.RLock()
	defer dm.mu.RUnlock()
	return dm.defaultDNS
}

// GetDesignatedDomainOrDefault 高性能匹配方法
func (dm *DesignatedMatcher) GetDesignatedDomainOrDefault(domain string) (string, bool) {
	// 添加空指针检查
	if dm == nil {
		return "", false
	}

	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// 添加默认DNS检查
	if dm.defaultDNS == "" {
		return "", false
	}

	// 1. 快速精确匹配检查
	domainLower := strings.ToLower(domain)
	if dns, exists := dm.exactMap[domainLower]; exists {
		dm.logger.Debug("🎯 精确匹配成功", map[string]interface{}{
			"domain": domainLower,
			"dns":    dns,
		})
		return dns, true
	}

	// 2. 使用前缀树进行快速匹配
	if dm.trie != nil {
		if result := dm.trie.Search(domainLower); result.Matched {
			dm.logger.Debug("🎯 前缀树匹配成功", map[string]interface{}{
				"domain":  domainLower,
				"dns":     result.DNS,
				"pattern": result.Pattern,
				"type":    result.Type,
			})
			return result.DNS, true
		}
	}

	// 3. 复杂正则匹配（仅在必要时）
	dm.logger.Debug("🔍 开始正则匹配检查", map[string]interface{}{
		"domain":         domainLower,
		"wildcard_count": len(dm.wildcards),
	})

	for i, dd := range dm.wildcards {
		if dd != nil && dd.Regex != nil {
			dm.logger.Debug("🔍 检查正则模式", map[string]interface{}{
				"domain":  domainLower,
				"pattern": dd.Pattern,
				"regex":   dd.Regex.String(),
				"index":   i,
			})

			if dd.Regex.MatchString(domainLower) {
				dm.logger.Debug("🎯 正则匹配成功", map[string]interface{}{
					"domain":  domainLower,
					"dns":     dd.DNS,
					"pattern": dd.Pattern,
					"type":    dd.MatchType,
				})
				return dd.DNS, true
			}
		}
	}

	// 4. 返回默认DNS
	dm.logger.Debug("🔄 使用默认DNS", map[string]interface{}{
		"domain": domainLower,
		"dns":    dm.defaultDNS,
	})
	return dm.defaultDNS, dm.defaultDNS != ""
}

// LoadDesignatedDomains 高性能加载定向域名
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
		if err := dm.createDefaultFile(filePath); err != nil {
			return err
		}
	}

	lines, err := dm.readLines(filePath)
	if err != nil {
		return fmt.Errorf("读取定向域名文件失败: %w", err)
	}

	// 创建新的索引结构
	newTrie := NewDomainTrie()
	newExactMap := make(map[string]string)
	newWildcards := make([]*DesignatedDomain, 0)
	newDomains := make([]*DesignatedDomain, 0)

	var exactCount, wildcardCount, regexCount int

	// 批量解析和分类
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

		// 添加到domains列表
		newDomains = append(newDomains, dd)

		// 根据模式类型分类存储
		pattern := strings.ToLower(dd.Pattern)
		if dd.MatchType == "exact" {
			// 精确匹配直接存储到哈希表
			newExactMap[pattern] = dd.DNS
			exactCount++
		} else if dd.MatchType == "wildcard" && strings.HasPrefix(pattern, "*.") {
			// 简单通配符存储到前缀树
			newTrie.Insert(pattern, dd.DNS, dd.UpstreamType)
			wildcardCount++
		} else {
			// 其他类型（suffix_wildcard, keyword, regex）存储到正则表达式列表
			newWildcards = append(newWildcards, dd)
			regexCount++
		}
	}

	// 原子性更新索引结构
	dm.mu.Lock()
	dm.trie = newTrie
	dm.exactMap = newExactMap
	dm.wildcards = newWildcards
	dm.domains = newDomains
	dm.domainCount = len(lines)
	dm.mu.Unlock()

	dm.logger.Info("🎯 高性能定向域名加载完成", map[string]interface{}{
		"file":           filePath,
		"total_count":    len(lines),
		"exact_count":    exactCount,
		"wildcard_count": wildcardCount,
		"regex_count":    regexCount,
		"performance":    "optimized",
	})

	return nil
}

// parseDesignatedLine 解析定向域名配置行（优化版）
func (dm *DesignatedMatcher) parseDesignatedLine(line string) (*DesignatedDomain, error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return nil, fmt.Errorf("格式错误，需要：域名 DNS服务器")
	}

	domainPattern := parts[0]
	dnsServer := parts[1]

	// 处理 default_dns 关键字
	if dnsServer == "default_dns" {
		dm.mu.RLock()
		defaultDNS := dm.defaultDNS
		dm.mu.RUnlock()

		if defaultDNS == "" {
			return nil, fmt.Errorf("使用了 default_dns 关键字，但未设置默认DNS服务器")
		}
		dnsServer = defaultDNS
	}

	// 确定上游类型
	upstreamType := "udp"
	switch {
	case strings.HasPrefix(dnsServer, "https://"):
		upstreamType = "doh"
	case strings.HasPrefix(dnsServer, "tls://"):
		upstreamType = "dot"
	case strings.HasPrefix(dnsServer, "h3://"):
		upstreamType = "doh3"
	}

	// 确定匹配类型和构建索引
	var matchType string
	var regex *regexp.Regexp

	if !strings.Contains(domainPattern, "*") && strings.Contains(domainPattern, ".") {
		// 精确匹配（包含点号的完整域名）
		matchType = "exact"
	} else if strings.HasPrefix(domainPattern, "*.") && !strings.Contains(domainPattern[2:], "*") {
		// 前缀通配符：*.example.com
		matchType = "wildcard"
	} else if strings.HasSuffix(domainPattern, ".*") && !strings.Contains(domainPattern[:len(domainPattern)-2], "*") {
		// 后缀通配符：example.*
		matchType = "suffix_wildcard"
		// 对于后缀通配符，我们需要使用正则表达式来匹配
		pattern := "^" + regexp.QuoteMeta(domainPattern[:len(domainPattern)-2]) + `\..*$`
		var err error
		regex, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("后缀通配符正则表达式编译失败: %w", err)
		}
	} else if !strings.Contains(domainPattern, ".") && !strings.Contains(domainPattern, "*") {
		// 关键字匹配：aaa（不包含点号和星号的简单关键字）
		matchType = "keyword"
		// 对于关键字匹配，我们需要使用正则表达式来匹配包含该关键字的域名
		pattern := `.*` + regexp.QuoteMeta(domainPattern) + `.*`
		var err error
		regex, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("关键字匹配正则表达式编译失败: %w", err)
		}
	} else {
		// 复杂正则匹配
		matchType = "regex"
		pattern := "^" + strings.ReplaceAll(regexp.QuoteMeta(domainPattern), `\*`, ".*") + "$"
		var err error
		regex, err = regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("正则表达式编译失败: %w", err)
		}
	}

	return &DesignatedDomain{
		Domain:       domainPattern,
		Pattern:      domainPattern,
		DNS:          dnsServer,
		Regex:        regex,
		UpstreamType: upstreamType,
		MatchType:    matchType,
	}, nil
}

// createDefaultFile 创建默认文件
func (dm *DesignatedMatcher) createDefaultFile(filePath string) error {
	defaultContent := `# 高性能定向域名配置
# 格式: 域名模式 DNS服务器
# 支持协议:
#   - UDP: udp://IP:PORT 或 IP:PORT
#   - TCP: tcp://IP:PORT  
#   - DoH: https://domain/path
#   - DoT: tls://domain:PORT
#   - DoH3: h3://domain/path
# 特殊关键字:
#   - default_dns: 使用配置文件中设置的默认DNS服务器

# 支持的匹配模式：
# 1. 精确匹配: example.com
# 2. 前缀通配符: *.example.com (匹配 www.example.com, mail.example.com 等)
# 3. 后缀通配符: example.* (匹配 example.com, example.org, example.net 等)
# 4. 关键字匹配: example (匹配任何包含 example 的域名)
# 5. 复杂通配符: *example* (匹配任何包含 example 的域名)

# 性能优先级：精确匹配 > 简单通配符 > 正则表达式

# 示例配置
*.local udp://192.168.1.1:53
*.bing.com default_dns
bing.* default_dns
bing default_dns
`
	return os.WriteFile(filePath, []byte(defaultContent), 0644)
}

// readLines 读取文件行
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

// GetDesignatedDomain 获取匹配的定向域名
func (dm *DesignatedMatcher) GetDesignatedDomain(domain string) *DesignatedDomain {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// 记录开始匹配的调试信息
	dm.logger.Debug("🎯 开始定向域名匹配检查", map[string]interface{}{
		"domain":       domain,
		"domain_count": len(dm.domains),
	})

	// 如果没有配置定向域名，直接返回nil
	if len(dm.domains) == 0 {
		dm.logger.Debug("⚠️ 定向域名为空，跳过匹配", map[string]interface{}{
			"domain": domain,
		})
		return nil
	}

	// 记录所有定向域名模式
	patterns := make([]string, len(dm.domains))
	for i, dd := range dm.domains {
		patterns[i] = dd.Pattern + " -> " + dd.DNS
	}
	dm.logger.Debug("📋 定向域名模式列表", map[string]interface{}{
		"domain":   domain,
		"patterns": patterns,
	})

	for i, dd := range dm.domains {
		dm.logger.Debug("🔎 检查定向域名模式", map[string]interface{}{
			"domain":  domain,
			"pattern": dd.Pattern,
			"dns":     dd.DNS,
			"index":   i + 1,
			"total":   len(dm.domains),
			"regex":   dd.Regex.String(),
		})

		if dd.Regex != nil && dd.Regex.MatchString(domain) {
			dm.logger.Info("🎯 定向域名匹配成功", map[string]interface{}{
				"domain":          domain,
				"matched_pattern": dd.Pattern,
				"designated_dns":  dd.DNS,
				"upstream_type":   dd.UpstreamType,
				"pattern_index":   i + 1,
				"rule":            "DESIGNATED_MATCHED",
			})
			return dd
		} else {
			dm.logger.Debug("❌ 定向域名模式不匹配", map[string]interface{}{
				"domain":  domain,
				"pattern": dd.Pattern,
				"dns":     dd.DNS,
				"index":   i + 1,
				"regex":   dd.Regex.String(),
			})
		}
	}

	dm.logger.Debug("❌ 定向域名匹配失败", map[string]interface{}{
		"domain":          domain,
		"checked_domains": len(dm.domains),
		"result":          "NO_MATCH",
	})

	return nil
}

// GetStats 获取性能统计（兼容接口）
func (dm *DesignatedMatcher) GetStats() map[string]interface{} {
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	return map[string]interface{}{
		"domain_count": len(dm.domains),
		"matcher_type": "traditional",
		"warning":      "建议升级到高性能匹配器以获得更好的性能",
	}
}
