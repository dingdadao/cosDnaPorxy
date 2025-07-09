package config

import (
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
)

// 常量定义
const (
	DefaultConfigPath      = "configs/config.yaml"
	DefaultCFCacheTime     = "1h"
	DefaultReplaceCacheTTL = "30m"
	DefaultLogLevel        = "info"
	DefaultMetricsPort     = 0
)

// DoHConfig 单个DoH配置
type DoHConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Resolver string `yaml:"resolver"`
	Timeout  string `yaml:"timeout"`
}

// DoHGroupConfig 分组DoH配置
type DoHGroupConfig struct {
	CN    DoHConfig `yaml:"cn"`
	NotCN DoHConfig `yaml:"not_cn"`
}

// Config 配置结构体
type Config struct {
	ListenPort       int        `yaml:"listen_port"`
	CNUpstream       []string   `yaml:"cn_upstream"`
	NotCNUpstream    []string   `yaml:"not_cn_upstream"`
	GeositeGroup     string     `yaml:"geosite_group"`
	CFMrsFile4       string     `yaml:"cf_mrs_file4"`
	CFMrsFile4URL    string     `yaml:"cf_mrs_file4_url"`
	CFMrsFile6       string     `yaml:"cf_mrs_file6"`
	CFMrsFile6URL    string     `yaml:"cf_mrs_file6_url"`
	AWSMrsFile46     string     `yaml:"aws_mrs_file64"`
	AWSMrsFile46URL  string     `yaml:"aws_mrs_file64_url"`
	CFMrsCache       string     `yaml:"cf_mrs_cache"`
	ReplaceCFDomain  string     `yaml:"replace_cf_domain"`
	ReplaceAWSDomain string     `yaml:"replace_aws_domain"`
	CFCacheTime      string     `yaml:"cf_cache_time"`
	ReplaceCacheTime string     `yaml:"replace_cache_time"`
	WhitelistFile    string     `yaml:"whitelist_file"`
	DesignatedDomain string     `yaml:"designated_domain"`
	LogLevel         string     `yaml:"log_level"`
	MetricsPort      int        `yaml:"metrics_port"`
	DoTPort          int        `yaml:"dot_port"`
	DoHPort          int        `yaml:"doh_port"`
	TLSCertFile      string     `yaml:"tls_cert_file"`
	TLSKeyFile       string     `yaml:"tls_key_file"`
	GeositeFile      string     `yaml:"geosite_file"`
	GeositeURL       string     `yaml:"geosite_url"`
	GeositeRefresh   string     `yaml:"geosite_refresh"`
	DoH              DoHGroupConfig  `yaml:"doh"`
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
	if config.CFCacheTime == "" {
		config.CFCacheTime = DefaultCFCacheTime
	}
	if config.ReplaceCacheTime == "" {
		config.ReplaceCacheTime = DefaultReplaceCacheTTL
	}
	if config.LogLevel == "" {
		config.LogLevel = DefaultLogLevel
	}
	if config.MetricsPort == 0 {
		config.MetricsPort = DefaultMetricsPort
	}
	
	// 设置DoH默认值
	if config.DoH.CN.Resolver == "" {
		config.DoH.CN.Resolver = "8.8.8.8:53"
	}
	if config.DoH.CN.Timeout == "" {
		config.DoH.CN.Timeout = "5s"
	}
	if config.DoH.NotCN.Resolver == "" {
		config.DoH.NotCN.Resolver = "8.8.8.8:53"
	}
	if config.DoH.NotCN.Timeout == "" {
		config.DoH.NotCN.Timeout = "5s"
	}

	return &config, nil
}

// ValidateConfig 验证配置
func ValidateConfig(cfg *Config) error {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", cfg.ListenPort)
	}
	if len(cfg.CNUpstream) == 0 || len(cfg.NotCNUpstream) == 0 {
		return fmt.Errorf("no upstream servers configured")
	}
	if cfg.ReplaceCFDomain == "" {
		return fmt.Errorf("replace_domain must be set")
	}
	if cfg.CFMrsFile4 == "" || cfg.AWSMrsFile46 == "" {
		return fmt.Errorf("IP ranges URLs must be configured")
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