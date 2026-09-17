package config

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// 常量定义
const (
	DefaultConfigPath = "config.yaml"
	DefaultLogLevel   = "info"
)

// CacheConfig 缓存配置
type CacheConfig struct {
	MaxItems        int           `yaml:"max_items"`         // 最大缓存条目数
	TTL             time.Duration `yaml:"ttl"`               // 兜底缓存TTL：上游未提供TTL时使用，不再抬高上游TTL
	MaxAsyncWorkers int           `yaml:"max_async_workers"` // 最大异步工作线程数
}

// Config 配置结构体
type Config struct {
	ListenPort                 int           `yaml:"listen_port"`
	Upstream                   []string      `yaml:"upstream"`           // 上游DNS服务器（统一URL scheme）
	Timeout                    time.Duration `yaml:"timeout"`            // 传统协议(UDP/TCP)查询超时
	ModernTimeout              time.Duration `yaml:"modern_timeout"`     // 现代协议(DoH/DoT/DoH3)查询超时
	ReplaceCacheTime           time.Duration `yaml:"replace_cache_time"` // 云替换响应缓存时间
	MaxIPRecords               int           `yaml:"max_ip_records"`     // 替换域名使用的最大IP数
	CNAMERecursionDepth        int           `yaml:"cname_recursion_depth"` // CNAME链收集深度（仅用于云检测）
	ReplaceCFDomain            string        `yaml:"replace_cf_domain"`
	ReplaceAWSDomain           string        `yaml:"replace_aws_domain"`
	DefaultDNS                 string        `yaml:"default_dns"` // 定向域名未指定DNS时的默认DNS
	BackupDNS                  string        `yaml:"backup_dns"`  // 所有上游失败后的备用DNS
	ChinaDNS                   string        `yaml:"china_dns"`   // 中国域名解析DNS
	DesignatedDomain           string        `yaml:"designated_domain"`
	DesignatedDomainURL        string        `yaml:"designated_domain_url"` // 定向域名文件URL（优先于本地文件）
	DesignatedRefreshInterval  time.Duration `yaml:"designated_refresh"`
	ChinaDomainFile            string        `yaml:"china_domain_file"`
	ChinaDomainFileURL         string        `yaml:"china_domain_file_url"` // 中国域名列表URL（优先于本地文件）
	ChinaDomainRefreshInterval time.Duration `yaml:"china_domain_refresh"`
	CloudflareNetFile          string        `yaml:"cloudflare_net_file"`
	CloudflareNetFile6         string        `yaml:"cloudflare_net_file6"`
	AWSNetFile                 string        `yaml:"aws_net_file"`
	NetworkRefreshInterval     time.Duration `yaml:"network_refresh"`
	LogLevel                   string        `yaml:"log_level"`
	LogFormat                  string        `yaml:"log_format"`
	Cache                      CacheConfig   `yaml:"cache"`
	EnableChinaDomainCheck     bool          `yaml:"enable_china_domain_check"`
	EnableCloudflareCheck      bool          `yaml:"enable_cloudflare_check"`
	EnableAWSCheck             bool          `yaml:"enable_aws_check"`
}

// LoadConfig 加载配置文件
func LoadConfig(path string) (*Config, error) {
	cfgData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config Config
	if err := yaml.Unmarshal(cfgData, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// 设置默认值
	if config.LogLevel == "" {
		config.LogLevel = DefaultLogLevel
	}
	if config.LogFormat == "" {
		config.LogFormat = "text"
	}

	// 设置超时默认值
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second
	}
	if config.ModernTimeout == 0 {
		config.ModernTimeout = 3 * time.Second
	}

	// 设置缓存默认值
	if config.Cache.MaxItems == 0 {
		config.Cache.MaxItems = 5000
	}
	if config.Cache.TTL == 0 {
		config.Cache.TTL = 300 * time.Second
	}

	// 设置最大IP记录数默认值
	if config.MaxIPRecords == 0 {
		config.MaxIPRecords = 2
	}

	// 设置CNAME链收集深度默认值（仅用于云检测，不对客户端响应做递归重写）
	if config.CNAMERecursionDepth == 0 {
		config.CNAMERecursionDepth = 1
	}

	// 云替换响应缓存时间默认值
	if config.ReplaceCacheTime == 0 {
		config.ReplaceCacheTime = 30 * time.Minute
	}

	// 设置刷新间隔默认值
	if config.DesignatedRefreshInterval == 0 {
		config.DesignatedRefreshInterval = 30 * time.Minute
	}
	if config.ChinaDomainRefreshInterval == 0 {
		config.ChinaDomainRefreshInterval = 24 * time.Hour
	}
	if config.NetworkRefreshInterval == 0 {
		config.NetworkRefreshInterval = 24 * time.Hour
	}

	// 设置开关默认值（如果配置文件中未明确设置，则启用）
	if !isFieldSetInConfig(cfgData, "enable_china_domain_check") {
		config.EnableChinaDomainCheck = true
	}
	if !isFieldSetInConfig(cfgData, "enable_cloudflare_check") {
		config.EnableCloudflareCheck = true
	}
	if !isFieldSetInConfig(cfgData, "enable_aws_check") {
		config.EnableAWSCheck = true
	}

	return &config, nil
}

// isFieldSetInConfig 检查配置文件中是否设置了某个布尔字段
func isFieldSetInConfig(configData []byte, fieldName string) bool {
	configStr := string(configData)
	lines := strings.Split(configStr, "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		// 跳过注释行
		if strings.HasPrefix(trimmedLine, "#") {
			continue
		}
		// 检查是否是该字段的定义
		if strings.HasPrefix(trimmedLine, fieldName+":") {
			// 提取字段值部分（去掉字段名和冒号）
			valuePart := strings.TrimSpace(strings.SplitN(trimmedLine, ":", 2)[1])

			// 检查是否有注释（# 符号）
			if idx := strings.Index(valuePart, "#"); idx != -1 {
				// 如果有注释，只取注释前的部分
				valuePart = strings.TrimSpace(valuePart[:idx])
			}

			// 检查是否是布尔值
			value := strings.ToLower(strings.TrimSpace(valuePart))
			return value == "true" || value == "false"
		}
	}
	return false
}

// ValidateConfig 验证配置
func ValidateConfig(cfg *Config) error {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", cfg.ListenPort)
	}
	if len(cfg.Upstream) == 0 {
		return fmt.Errorf("no upstream servers configured")
	}
	return nil
}

// LoadAndValidateConfig 加载并验证配置
func LoadAndValidateConfig() *Config {
	configPath := flag.String("c", DefaultConfigPath, "Path to config file")
	flag.Parse()

	config, err := LoadConfig(*configPath)
	if err != nil {
		panic(fmt.Sprintf("Failed to load config: %v", err))
	}

	if err := ValidateConfig(config); err != nil {
		panic(fmt.Sprintf("Invalid config: %v", err))
	}

	return config
}
