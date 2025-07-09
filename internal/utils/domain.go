package utils

import (
	"regexp"
	"strings"
)

// MatchDomain 判断给定的 pattern 是否匹配指定的域名 - 优化版本
// 支持以下匹配模式：
// 1. 完全匹配：qq.com
// 2. 通配符前缀：*.qq.com 匹配 qq.com 和 a.qq.com
// 3. 通配符后缀：qq.com.* 匹配 qq.com 和 qq.com.cn
// 4. 模糊通配符：如 *qpic.cn*，内部使用正则匹配
func MatchDomain(pattern, domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(domain, ".")) // 统一格式化域名
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	
	if pattern == "" || domain == "" {
		return false
	}

	// 1. 完全匹配
	if pattern == domain {
		return true
	}

	// 2. 通配符前缀：*.qq.com
	if strings.HasPrefix(pattern, "*.") {
		base := pattern[2:] // 去掉 "*."
		if base == "" {
			return false // 避免 "*." 匹配所有域名
		}
		if domain == base || strings.HasSuffix(domain, "."+base) {
			return true
		}
	}

	// 3. 通配符后缀：qq.com.*
	if strings.HasSuffix(pattern, ".*") {
		base := pattern[:len(pattern)-2] // 去掉 ".*"
		if base == "" {
			return false // 避免 ".*" 匹配所有域名
		}
		if domain == base || strings.HasPrefix(domain, base+".") {
			return true
		}
	}

	// 4. 模糊通配符（如 *xx*）
	if strings.Contains(pattern, "*") {
		// 转为正则表达式，处理特殊字符
		regexPattern := "^" + regexp.QuoteMeta(pattern) + "$"
		regexPattern = strings.ReplaceAll(regexPattern, `\*`, ".*")
		
		// 编译正则表达式以提高性能
		re, err := regexp.Compile(regexPattern)
		if err != nil {
			// 正则编译失败，回退到简单字符串匹配
			return strings.Contains(domain, strings.ReplaceAll(pattern, "*", ""))
		}
		
		return re.MatchString(domain)
	}

	return false
}

// SanitizeDomainName 清理域名
func SanitizeDomainName(name string) string {
	if idx := strings.Index(name, `\`); idx != -1 {
		return name[:idx]
	}
	return name
} 