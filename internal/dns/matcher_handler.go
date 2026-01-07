package dns

import (
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"
	"os"

	"github.com/miekg/dns"
)

// MatcherHandler 处理域名匹配相关功能
type MatcherHandler struct {
	config        *config.Config
	logger        *utils.EnhancedLogger
	yamlMatcher   *YAMLMatcher
	chinaMatcher  *ChinaDomainMatcher
	cloudDetector *CloudDetector
	proxyQuery    func(*dns.Msg, []string) (*dns.Msg, error) // 代理查询函数
}

// NewMatcherHandler 创建新的匹配处理器
func NewMatcherHandler(config *config.Config, logger *utils.EnhancedLogger, handler *RefactoredHandler) *MatcherHandler {
	mh := &MatcherHandler{
		config:     config,
		logger:     logger,
		proxyQuery: handler.proxyQuery, // 从handler获取proxyQuery函数
	}

	// 初始化YAML匹配器
	mh.yamlMatcher = NewYAMLMatcher(logger)

	// 初始化中国域名匹配器
	mh.chinaMatcher = NewChinaDomainMatcher(logger)

	// 从handler获取cloudDetector实例
	if handler != nil && handler.cloudDetector != nil {
		mh.cloudDetector = handler.cloudDetector
	}

	return mh
}

// 初始化配置 - 这个方法应该在handler初始化后调用
func (mh *MatcherHandler) InitializeConfig() error {
	// 检查YAML配置文件是否存在，如果不存在则跳过加载
	if mh.config.DesignatedDomain != "" {
		if _, err := os.Stat(mh.config.DesignatedDomain); err == nil {
			// 文件存在，加载配置
			if err := mh.yamlMatcher.LoadYAMLConfig(mh.config.DesignatedDomain); err != nil {
				mh.logger.Error("❌ 加载YAML配置失败", map[string]interface{}{
					"file":  mh.config.DesignatedDomain,
					"error": err.Error(),
				})
				return err
			}
			mh.logger.Info("✅ YAML配置加载成功", map[string]interface{}{
				"file": mh.config.DesignatedDomain,
			})
		} else {
			mh.logger.Info("📋 YAML配置文件不存在，等待定时任务下载", map[string]interface{}{
				"file": mh.config.DesignatedDomain,
			})
		}
	}

	// 检查中国域名配置文件是否存在，如果不存在则跳过加载
	if mh.config.ChinaDomainFile != "" {
		if _, err := os.Stat(mh.config.ChinaDomainFile); err == nil {
			// 文件存在，加载配置
			if err := mh.chinaMatcher.LoadChinaDomains(mh.config.ChinaDomainFile); err != nil {
				mh.logger.Error("❌ 加载中国域名配置失败", map[string]interface{}{
					"file":  mh.config.ChinaDomainFile,
					"error": err.Error(),
				})
				return err
			}
			mh.logger.Info("✅ 中国域名配置加载成功", map[string]interface{}{
				"file": mh.config.ChinaDomainFile,
			})
		} else {
			mh.logger.Info("📋 中国域名配置文件不存在，等待定时任务下载", map[string]interface{}{
				"file": mh.config.ChinaDomainFile,
			})
		}
	}

	return nil
}

// HandleYAMLMatcher 处理YAML定向域名匹配
func (mh *MatcherHandler) HandleYAMLMatcher(domain string, qtype uint16, upstream string) (*dns.Msg, error) {
	// 创建DNS查询请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 使用定向域名配置的DNS服务器进行查询
	resp, err := mh.proxyQuery(req, []string{upstream})
	if err != nil {
		mh.logger.Error("❌ YAML定向域名查询失败", map[string]interface{}{
			"domain":   domain,
			"upstream": upstream,
			"error":    err.Error(),
		})
		return nil, err
	}

	return resp, nil
}

// HandleChinaDomain 处理中国域名匹配
func (mh *MatcherHandler) HandleChinaDomain(domain string, qtype uint16, upstreams []string) (*dns.Msg, error) {
	// 创建DNS查询请求
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn(domain), qtype)

	// 使用中国域名配置的DNS服务器进行查询
	resp, err := mh.proxyQuery(req, upstreams)
	if err != nil {
		mh.logger.Error("❌ 中国域名查询失败", map[string]interface{}{
			"domain":    domain,
			"upstreams": upstreams,
			"error":     err.Error(),
		})
		return nil, err
	}

	return resp, nil
}

// GetYAMLMatcher 返回YAML匹配器
func (mh *MatcherHandler) GetYAMLMatcher() *YAMLMatcher {
	return mh.yamlMatcher
}

// GetChinaMatcher 返回中国域名匹配器
func (mh *MatcherHandler) GetChinaMatcher() *ChinaDomainMatcher {
	return mh.chinaMatcher
}
