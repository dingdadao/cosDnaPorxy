package utils

import (
	"cosDnaPorxy/internal/config"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// CreateRequiredDirectories 创建程序运行所需的必要目录
func CreateRequiredDirectories() error {
	// 只创建最必要的目录
	requiredDirs := []string{
		"data",              // 数据文件目录（存放下载的资源）
		"logs",              // 日志文件目录（可选）
	}

	// 检查并创建每个目录（如果不存在）
	for _, dir := range requiredDirs {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			// 目录不存在，创建它
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
			fmt.Printf("📁 创建目录: %s\n", dir)
		} else {
			fmt.Printf("✅ 目录已存在: %s\n", dir)
		}
	}

	return nil
}

// CreateConfigFiles 创建默认配置文件（如果不存在）
func CreateConfigFiles(configPath string) error {
	// 如果用户指定了配置文件路径，检查该目录是否存在
	if configPath != "" && configPath != "configs/config.yaml" {
		configDir := filepath.Dir(configPath)
		if _, err := os.Stat(configDir); os.IsNotExist(err) {
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return fmt.Errorf("failed to create config directory %s: %w", configDir, err)
			}
			fmt.Printf("📁 创建配置目录: %s\n", configDir)
		}
	}

	// 默认配置文件内容
	defaultConfig := `# DNS代理服务器配置
listen_port: 5354
metrics_port: 0

# 上游DNS服务器配置 - 直接使用DoH
cn_upstream:
  - "https://doh.pub/dns-query"
  - "https://dns.alidns.com/dns-query"
not_cn_upstream:
  - "https://dns.google/dns-query"
  - "https://cloudflare-dns.com/dns-query"

doh:
  cn:
    enabled: true
    timeout: "5s"
    resolver: "119.29.29.29:53"
  not_cn:
    enabled: true
    timeout: "5s"
    resolver: "8.8.8.8:53"

# Cloudflare和AWS IP范围文件
cf_mrs_file4: "./data/cloudflare-v4.txt"
cf_mrs_file6: "./data/cloudflare-v6.txt"
aws_mrs_file64: "./data/aws.txt"
cf_mrs_cache: "./data/cloudflare.txt"

# 替换域名配置
replace_cf_domain: "cc.cloudflare.182682.xyz"
replace_aws_domain: "cc.cloudfront.182682.xyz"

# 缓存时间配置
cf_cache_time: 23h59m
replace_cache_time: "30m"

# 域名规则文件
whitelist_file: "./configs/whitelist.txt"
designated_domain: "./configs/designated.txt"

# 日志和监控
log_level: "info"

# TLS配置
doh_port: 0
dot_port: 0
tls_cert_file: "./configs/fullchain.pem"
tls_key_file: "./configs/privkey.pem"

# Geosite配置
geosite_url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat"
geosite_refresh: 72h
geosite_group: "GEOLOCATION-CN"
`

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// 创建默认配置文件
		if err := os.WriteFile(configPath, []byte(defaultConfig), 0644); err != nil {
			return fmt.Errorf("failed to create default config file: %w", err)
		}
		fmt.Printf("📄 创建默认配置文件: %s\n", configPath)
	} else {
		fmt.Printf("✅ 配置文件已存在: %s\n", configPath)
	}

	// 创建默认白名单文件
	whitelistPath := "configs/whitelist.txt"
	if _, err := os.Stat(whitelistPath); os.IsNotExist(err) {
		defaultWhitelist := `# 白名单域名（不进行任何处理）
# 每行一个域名
example.com
localhost
`
		if err := os.WriteFile(whitelistPath, []byte(defaultWhitelist), 0644); err != nil {
			return fmt.Errorf("failed to create whitelist file: %w", err)
		}
		fmt.Printf("📄 创建白名单文件: %s\n", whitelistPath)
	} else {
		fmt.Printf("✅ 白名单文件已存在: %s\n", whitelistPath)
	}

	// 创建默认定向域名文件
	designatedPath := "configs/designated.txt"
	if _, err := os.Stat(designatedPath); os.IsNotExist(err) {
		defaultDesignated := `# 定向域名配置
# 格式：域名 DNS服务器
# 每行一个配置
qq.com 119.29.29.29:53
wechat.com 119.29.29.29:53
`
		if err := os.WriteFile(designatedPath, []byte(defaultDesignated), 0644); err != nil {
			return fmt.Errorf("failed to create designated domain file: %w", err)
		}
		fmt.Printf("📄 创建定向域名文件: %s\n", designatedPath)
	} else {
		fmt.Printf("✅ 定向域名文件已存在: %s\n", designatedPath)
	}

	return nil
}

// CreateTestScripts 创建基本的测试脚本
func CreateTestScripts() error {
	testDir := "scripts/test"
	
	// 基础DNS测试脚本
	basicTestScript := `#!/bin/bash
echo "=== 基础DNS测试 ==="
echo

echo "1. 测试国内域名 baidu.com:"
dig @127.0.0.1 -p 5354 baidu.com +short
echo

echo "2. 测试国外域名 google.com:"
dig @127.0.0.1 -p 5354 google.com +short
echo

echo "3. 测试AAAA记录 google.com:"
dig @127.0.0.1 -p 5354 google.com AAAA +short
echo

echo "=== 测试完成 ==="
`

	testScriptPath := filepath.Join(testDir, "test_dns.sh")
	if _, err := os.Stat(testScriptPath); os.IsNotExist(err) {
		if err := os.WriteFile(testScriptPath, []byte(basicTestScript), 0755); err != nil {
			return fmt.Errorf("failed to create test script: %w", err)
		}
		fmt.Printf("📄 创建测试脚本: %s\n", testScriptPath)
	} else {
		fmt.Printf("✅ 测试脚本已存在: %s\n", testScriptPath)
	}

	return nil
}

// InitResourceFiles 根据配置自动初始化资源文件和目录
func InitResourceFiles(cfg *config.Config) error {
	// 1. 检查/创建data目录
	dataDir := "data"
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return fmt.Errorf("无法创建data目录: %w", err)
		}
		fmt.Println("📁 已创建data目录")
	}

	// 2. 资源文件列表（路径+URL）
	resourceList := []struct {
		File string
		URL  string
		IsAWS bool
	}{
		{cfg.GeositeFile, cfg.GeositeURL, false},
		{cfg.CFMrsFile4, cfg.CFMrsFile4URL, false},
		{cfg.CFMrsFile6, cfg.CFMrsFile6URL, false},
		{cfg.AWSMrsFile46, cfg.AWSMrsFile46URL, true},
	}

	for _, res := range resourceList {
		if res.File == "" || res.URL == "" {
			continue
		}
		if _, err := os.Stat(res.File); os.IsNotExist(err) {
			fmt.Printf("📥 资源文件不存在，自动下载: %s\n", res.File)
			if res.IsAWS {
				if err := downloadAndParseAWSIPRangesToFile(res.URL, res.File); err != nil {
					fmt.Printf("❌ AWS资源下载失败: %v\n", err)
				}
			} else {
				if err := downloadFile(res.File, res.URL); err != nil {
					fmt.Printf("❌ 资源下载失败: %v\n", err)
				}
			}
		} else {
			fmt.Printf("✅ 资源文件已存在: %s\n", res.File)
		}
	}

	// 3. 检查/创建whitelist.txt和designated.txt（空文件）
	for _, f := range []string{cfg.WhitelistFile, cfg.DesignatedDomain} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); os.IsNotExist(err) {
			file, err := os.Create(f)
			if err != nil {
				fmt.Printf("❌ 创建空文件失败: %s %v\n", f, err)
			} else {
				file.Close()
				fmt.Printf("📄 已创建空文件: %s\n", f)
			}
		} else {
			fmt.Printf("✅ 文件已存在: %s\n", f)
		}
	}
	return nil
}

// downloadFile 下载文件
func downloadFile(filePath, url string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

// downloadAndParseAWSIPRangesToFile 下载AWS IP JSON并转为纯文本
func downloadAndParseAWSIPRangesToFile(url, filePath string) error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download AWS IP ranges: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP error: %d", resp.StatusCode)
	}
	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read JSON data: %w", err)
	}
	var awsData struct {
		Prefixes []struct{ IPPrefix string `json:"ip_prefix"` }
		IPv6Prefixes []struct{ IPv6Prefix string `json:"ipv6_prefix"` }
	}
	if err := json.Unmarshal(jsonData, &awsData); err != nil {
		return fmt.Errorf("failed to parse JSON: %w", err)
	}
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create AWS file: %w", err)
	}
	defer file.Close()
	for _, prefix := range awsData.Prefixes {
		if _, err := file.WriteString(prefix.IPPrefix + "\n"); err != nil {
			return fmt.Errorf("failed to write IPv4 prefix: %w", err)
		}
	}
	for _, prefix := range awsData.IPv6Prefixes {
		if _, err := file.WriteString(prefix.IPv6Prefix + "\n"); err != nil {
			return fmt.Errorf("failed to write IPv6 prefix: %w", err)
		}
	}
	return nil
} 