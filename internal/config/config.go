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
	DefaultConfigPath = "configs/config.yaml"
	DefaultLogLevel   = "info"
)

// CacheConfig 缓存配置
type CacheConfig struct {
	MaxItems        int           `yaml:"max_items"`         // 最大缓存条目数
	TTL             time.Duration `yaml:"ttl"`               // 最小缓存TTL
	MaxAsyncWorkers int           `yaml:"max_async_workers"` // 最大异步工作线程数
}

// UpstreamServer 上游服务器配置
type UpstreamServer struct {
	Name          string        `yaml:"name"`            // 服务器名称
	Address       string        `yaml:"address"`         // 服务器地址
	Protocol      string        `yaml:"protocol"`        // 协议类型：udp/tcp/doh/dot/doh3
	Endpoint      string        `yaml:"endpoint"`        // DoH/DoH3 端点路径
	CacheTime     time.Duration `yaml:"cache_time"`      // 连接缓存时间
	TLSServerName string        `yaml:"tls_server_name"` // TLS服务器名称
	Weight        int           `yaml:"weight"`          // 权重（用于负载均衡）
	Priority      int           `yaml:"priority"`        // 优先级（数字越小优先级越高）
}

// Config 配置结构体
type Config struct {
	ListenPort                 int              `yaml:"listen_port"`
	Upstream                   []string         `yaml:"upstream"`         // 保留兼容性
	UpstreamServers            []UpstreamServer `yaml:"upstream_servers"` // 新的上游服务器配置
	Timeout                    time.Duration    `yaml:"timeout"`          // DNS查询超时（支持2s、2m、2h格式）
	ModernTimeout              time.Duration    `yaml:"modern_timeout"`   // 现代协议超时（支持2s、2m、2h格式）
	CFMrsFile4                 string           `yaml:"cf_mrs_file4"`
	CFMrsFile4URL              string           `yaml:"cf_mrs_file4_url"`
	CFMrsFile6                 string           `yaml:"cf_mrs_file6"`
	CFCacheTime                string           `yaml:"cf_cache_time"`
	CFMrsFile6URL              string           `yaml:"cf_mrs_file6_url"`
	ReplaceCacheTime           string           `yaml:"replace_cache_time"`
	NoAnswerCacheTime          string           `yaml:"no_answer_cache_time"` // 无答案响应的缓存时间
	MaxIPRecords               int              `yaml:"max_ip_records"`       // 云域名替换时的最大IP记录数
	AWSMrsFile46               string           `yaml:"aws_mrs_file64"`
	AWSMrsFile46URL            string           `yaml:"aws_mrs_file64_url"`
	ReplaceCFDomain            string           `yaml:"replace_cf_domain"`
	ReplaceAWSDomain           string           `yaml:"replace_aws_domain"`
	DefaultDNS                 string           `yaml:"default_dns"` // 默认DNS服务器（支持URL scheme格式）
	BackupDNS                  string           `yaml:"backup_dns"`  // 备用DNS服务器
	WhitelistFile              string           `yaml:"whitelist_file"`
	DesignatedDomain           string           `yaml:"designated_domain"`
	DesignatedDomainURL        string           `yaml:"designated_domain_url"` // 定向域名文件URL
	LogLevel                   string           `yaml:"log_level"`
	LogFormat                  string           `yaml:"log_format"` // 添加日志格式配置
	TLSCertFile                string           `yaml:"tls_cert_file"`
	TLSKeyFile                 string           `yaml:"tls_key_file"`
	Cache                      CacheConfig      `yaml:"cache"`
	CloudflareNetFile          string           `yaml:"cloudflare_net_file"`
	CloudflareNetFile6         string           `yaml:"cloudflare_net_file6"`
	AWSNetFile                 string           `yaml:"aws_net_file"`
	WhitelistRefreshInterval   time.Duration    `yaml:"whitelist_refresh"`         // 白名单刷新间隔（支持30m、1h格式）
	DesignatedRefreshInterval  time.Duration    `yaml:"designated_refresh"`        // 定向域名刷新间隔（支持30m、1h格式）
	NetworkRefreshInterval     time.Duration    `yaml:"network_refresh"`           // 网络段刷新间隔（支持24h、1d格式）
	ChinaDomainFile            string           `yaml:"china_domain_file"`         // 中国域名列表文件
	ChinaDomainFileURL         string           `yaml:"china_domain_file_url"`     // 中国域名列表文件URL
	ChinaDomainRefreshInterval time.Duration    `yaml:"china_domain_refresh"`      // 中国域名刷新间隔（支持24h、1d格式）
	ChinaDNS                   string           `yaml:"china_dns"`                 // 中国DNS服务器
	EnableChinaDomainCheck     bool             `yaml:"enable_china_domain_check"` // 启用中国域名检查
	EnableCloudflareCheck      bool             `yaml:"enable_cloudflare_check"`   // 启用Cloudflare域名检查
	EnableAWSCheck             bool             `yaml:"enable_aws_check"`          // 启用AWS域名检查
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

	// 设置日志格式默认值
	if config.LogFormat == "" {
		config.LogFormat = "text" // 默认文本格式
	}

	// 设置超时默认值
	if config.Timeout == 0 {
		config.Timeout = 5 * time.Second // 默认5秒超时
	}
	if config.ModernTimeout == 0 {
		config.ModernTimeout = 3 * time.Second // 现代协议默认3秒超时
	}

	// 设置缓存默认值
	if config.Cache.MaxItems == 0 {
		config.Cache.MaxItems = 5000 // 默认5000个条目
	}
	if config.Cache.TTL == 0 {
		config.Cache.TTL = 300 * time.Second // 5分钟默认TTL
	}

	// 设置最大IP记录数默认值
	if config.MaxIPRecords == 0 {
		config.MaxIPRecords = 2 // 默认2条记录
	}

	// 设置刷新间隔默认值
	if config.WhitelistRefreshInterval == 0 {
		config.WhitelistRefreshInterval = 30 * time.Minute // 默认30分钟
	}
	if config.DesignatedRefreshInterval == 0 {
		config.DesignatedRefreshInterval = 30 * time.Minute // 默认30分钟
	}
	if config.NetworkRefreshInterval == 0 {
		config.NetworkRefreshInterval = 24 * time.Hour // 默认24小时
	}

	// 设置开关默认值（如果配置文件中未明确设置，则启用）
	if !isFieldSetInConfig(cfgData, "enable_china_domain_check") {
		config.EnableChinaDomainCheck = true // 默认启用中国域名检查
	}
	if !isFieldSetInConfig(cfgData, "enable_cloudflare_check") {
		config.EnableCloudflareCheck = true // 默认启用Cloudflare检查
	}
	if !isFieldSetInConfig(cfgData, "enable_aws_check") {
		config.EnableAWSCheck = true // 默认启用AWS检查
	}

	return &config, nil
}

// isFieldSetInConfig 检查配置文件中是否设置了某个字段
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
