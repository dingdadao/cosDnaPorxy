package dns

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"
)

// FileLoader 处理文件加载相关功能
type FileLoader struct {
	config         *config.Config
	logger         *utils.EnhancedLogger
	cloudDetector  *CloudDetector // 直接使用cloudDetector
	matcherHandler *MatcherHandler
}

// NewFileLoader 创建新的文件加载处理器
func NewFileLoader(config *config.Config, logger *utils.EnhancedLogger, cloudDetector *CloudDetector, matcherHandler *MatcherHandler) *FileLoader {
	return &FileLoader{
		config:         config,
		logger:         logger,
		cloudDetector:  cloudDetector,
		matcherHandler: matcherHandler,
	}
}

// LoadAllData 加载所有数据
func (fl *FileLoader) LoadAllData() error {
	// 仅在文件存在时才加载云服务网段
	if fl.shouldLoadCloudFiles() {
		if err := fl.cloudDetector.LoadNetworkRanges(
			fl.config.CloudflareNetFile,
			fl.config.CloudflareNetFile6,
			fl.config.AWSNetFile,
		); err != nil {
			fl.logger.Error("❌ 云服务网段加载失败", map[string]interface{}{
				"error": err.Error(),
			})
			// 继续执行，不返回错误，确保服务可用
		}
	} else {
		fl.logger.Info("📋 云服务网段文件不存在，等待定时任务下载", map[string]interface{}{
			"cloudflare_v4": fl.config.CloudflareNetFile,
			"cloudflare_v6": fl.config.CloudflareNetFile6,
			"aws_file":      fl.config.AWSNetFile,
		})
	}

	// 仅在文件存在时才加载中国域名
	if fl.shouldLoadChinaDomainFile() {
		if err := fl.LoadChinaDomains(); err != nil {
			fl.logger.Error("❌ 中国域名加载失败", map[string]interface{}{
				"error": err.Error(),
			})
			// 继续执行，不返回错误，确保服务可用
		}
	} else {
		fl.logger.Info("📋 中国域名文件不存在，等待定时任务下载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
		})
	}

	// 仅在文件存在时才加载定向域名
	if fl.shouldLoadDesignatedDomainFile() {
		if err := fl.LoadDesignatedDomains(); err != nil {
			fl.logger.Error("❌ 定向域名加载失败", map[string]interface{}{
				"error": err.Error(),
			})
			// 继续执行，不返回错误，确保服务可用
		}
	} else {
		fl.logger.Info("📋 定向域名文件不存在，等待定时任务下载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
	}

	return nil
}

// LoadSelectiveData 根据开关选择性加载数据
func (fl *FileLoader) LoadSelectiveData(loadChinaDomain, loadCloudServices bool) error {
	fl.logger.Info("🔄 开始选择性加载数据", map[string]interface{}{
		"load_china_domain":   loadChinaDomain,
		"load_cloud_services": loadCloudServices,
		"config_china_check":  fl.config.EnableChinaDomainCheck,
		"config_cf_check":     fl.config.EnableCloudflareCheck,
		"config_aws_check":    fl.config.EnableAWSCheck,
	})

	// 根据开关决定是否加载中国域名
	if loadChinaDomain {
		// 仅在文件存在时才加载中国域名
		if fl.shouldLoadChinaDomainFile() {
			if err := fl.LoadChinaDomains(); err != nil {
				fl.logger.Error("❌ 中国域名加载失败", map[string]interface{}{
					"error": err.Error(),
				})
				// 继续执行，不返回错误，确保服务可用
			}
		} else {
			fl.logger.Info("📋 中国域名文件不存在，等待定时任务下载", map[string]interface{}{
				"file": fl.config.ChinaDomainFile,
			})
		}
	} else {
		fl.logger.Info("⏭️ 中国域名检查已禁用，跳过加载", map[string]interface{}{
			"enabled": false,
		})
	}

	// 根据开关决定是否加载云服务
	if loadCloudServices {
		// 仅在文件存在时才加载云服务网段
		if fl.shouldLoadCloudFiles() {
			// 根据具体开关决定传递哪些文件路径
			cfFile4 := ""
			cfFile6 := ""
			awsFile := ""
			if fl.config.EnableCloudflareCheck {
				cfFile4 = fl.config.CloudflareNetFile
				cfFile6 = fl.config.CloudflareNetFile6
			}
			if fl.config.EnableAWSCheck {
				awsFile = fl.config.AWSNetFile
			}
			if err := fl.cloudDetector.LoadNetworkRanges(
				cfFile4,
				cfFile6,
				awsFile,
			); err != nil {
				fl.logger.Error("❌ 云服务网段加载失败", map[string]interface{}{
					"error": err.Error(),
				})
				// 继续执行，不返回错误，确保服务可用
			}
		} else {
			fl.logger.Info("📋 云服务网段文件不存在，等待定时任务下载", map[string]interface{}{
				"cloudflare_v4": fl.config.CloudflareNetFile,
				"cloudflare_v6": fl.config.CloudflareNetFile6,
				"aws_file":      fl.config.AWSNetFile,
			})
		}
	} else {
		fl.logger.Info("⏭️ 云服务检查已禁用，跳过加载", map[string]interface{}{
			"enable_cloudflare": fl.config.EnableCloudflareCheck,
			"enable_aws":        fl.config.EnableAWSCheck,
		})
	}

	// 总是加载定向域名（除非专门禁用）
	if fl.shouldLoadDesignatedDomainFile() {
		if err := fl.LoadDesignatedDomains(); err != nil {
			fl.logger.Error("❌ 定向域名加载失败", map[string]interface{}{
				"error": err.Error(),
			})
			// 继续执行，不返回错误，确保服务可用
		}
	} else {
		fl.logger.Info("📋 定向域名文件不存在，等待定时任务下载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
	}

	return nil
}

// shouldLoadCloudFiles 检查是否应该加载云服务文件
func (fl *FileLoader) shouldLoadCloudFiles() bool {
	// 检查云服务相关开关，如果都禁用则直接返回false
	if !fl.config.EnableCloudflareCheck && !fl.config.EnableAWSCheck {
		return false
	}

	// 检查任一云服务文件是否存在
	if fl.config.CloudflareNetFile != "" {
		if _, err := os.Stat(fl.config.CloudflareNetFile); err == nil {
			return true
		}
	}
	if fl.config.CloudflareNetFile6 != "" {
		if _, err := os.Stat(fl.config.CloudflareNetFile6); err == nil {
			return true
		}
	}
	if fl.config.AWSNetFile != "" {
		if _, err := os.Stat(fl.config.AWSNetFile); err == nil {
			return true
		}
	}
	return false
}

// shouldLoadChinaDomainFile 检查是否应该加载中国域名文件
func (fl *FileLoader) shouldLoadChinaDomainFile() bool {
	// 检查配置开关，如果禁用则直接返回false
	if !fl.config.EnableChinaDomainCheck {
		return false
	}

	if fl.config.ChinaDomainFile == "" {
		return false
	}
	if _, err := os.Stat(fl.config.ChinaDomainFile); err == nil {
		return true
	}
	return false
}

// shouldLoadDesignatedDomainFile 检查是否应该加载定向域名文件
func (fl *FileLoader) shouldLoadDesignatedDomainFile() bool {
	if fl.config.DesignatedDomain == "" {
		return false
	}
	if _, err := os.Stat(fl.config.DesignatedDomain); err == nil {
		return true
	}
	return false
}

// downloadFile 下载文件
func (fl *FileLoader) downloadFile(url, targetFile string) error {
	// 创建目录
	dir := filepath.Dir(targetFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建临时文件
	tempFile := targetFile + ".tmp"

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 发起GET请求
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载请求失败: %w", err)
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	// 创建临时文件
	out, err := os.Create(tempFile)
	if err != nil {
		return err
	}
	defer out.Close()

	// 将响应内容写入文件
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	// 检查下载的文件是否有效
	if !fl.isFileValid(tempFile) {
		// 删除无效的临时文件
		os.Remove(tempFile)
		return fmt.Errorf("下载的文件内容无效")
	}

	// 替换原文件
	return os.Rename(tempFile, targetFile)
}

// LoadChinaDomains 加载中国域名列表
func (fl *FileLoader) LoadChinaDomains() error {
	fl.logger.Debug("🔄 开始加载中国域名", map[string]interface{}{
		"enable_china_check": fl.config.EnableChinaDomainCheck,
		"china_domain_file":  fl.config.ChinaDomainFile,
	})

	// 检查配置开关，如果禁用则直接返回
	if !fl.config.EnableChinaDomainCheck {
		fl.logger.Info("⏭️ 中国域名检查已禁用，跳过加载", map[string]interface{}{
			"enabled": fl.config.EnableChinaDomainCheck,
		})
		return nil
	}

	// 如果配置文件不存在，直接返回，等待定时任务下载
	if fl.config.ChinaDomainFile == "" {
		fl.logger.Info("📋 中国域名配置文件路径为空，跳过加载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
		})
		return nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(fl.config.ChinaDomainFile); os.IsNotExist(err) {
		fl.logger.Info("📋 中国域名配置文件不存在，开始下载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
			"url":  fl.config.ChinaDomainFileURL,
		})

		// 文件不存在，尝试下载
		if fl.config.ChinaDomainFileURL != "" {
			if err := fl.downloadWithRetry(fl.config.ChinaDomainFileURL, fl.config.ChinaDomainFile); err != nil {
				fl.logger.Error("❌ 下载中国域名文件失败，创建空文件", map[string]interface{}{
					"file":  fl.config.ChinaDomainFile,
					"url":   fl.config.ChinaDomainFileURL,
					"error": err.Error(),
				})
				// 创建空文件以避免后续重复尝试下载
				if createErr := fl.createEmptyFile(fl.config.ChinaDomainFile); createErr != nil {
					fl.logger.Error("❌ 创建空文件失败", map[string]interface{}{
						"file":  fl.config.ChinaDomainFile,
						"error": createErr.Error(),
					})
				}
				return err
			}
			fl.logger.Info("✅ 下载中国域名文件成功", map[string]interface{}{
				"file": fl.config.ChinaDomainFile,
			})
		} else {
			fl.logger.Warn("⚠️ 中国域名文件URL未配置", map[string]interface{}{
				"file": fl.config.ChinaDomainFile,
			})
			return nil
		}
	} else {
		fl.logger.Info("📋 中国域名配置文件已存在，直接加载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
		})
	}

	// 检查文件内容是否有效
	if !fl.isFileValid(fl.config.ChinaDomainFile) {
		fl.logger.Warn("⚠️ 中国域名配置文件内容无效，跳过加载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
		})
		return nil
	}

	// 加载中国域名列表
	if err := fl.matcherHandler.GetChinaMatcher().LoadChinaDomains(fl.config.ChinaDomainFile); err != nil {
		fl.logger.Error("❌ 加载中国域名失败", map[string]interface{}{
			"file":  fl.config.ChinaDomainFile,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 中国域名加载完成", map[string]interface{}{
		"file": fl.config.ChinaDomainFile,
	})

	return nil
}

// ForceDownloadAndReloadChinaDomains 强制下载并重新加载中国域名列表（用于异步刷新）
func (fl *FileLoader) ForceDownloadAndReloadChinaDomains() error {
	// 如果配置文件不存在或URL未配置，直接返回
	if fl.config.ChinaDomainFile == "" || fl.config.ChinaDomainFileURL == "" {
		fl.logger.Warn("⚠️ 中国域名配置文件路径或URL为空，跳过下载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
			"url":  fl.config.ChinaDomainFileURL,
		})
		return nil
	}

	fl.logger.Info("🔄 强制下载中国域名文件", map[string]interface{}{
		"file": fl.config.ChinaDomainFile,
		"url":  fl.config.ChinaDomainFileURL,
	})

	// 强制下载文件
	if err := fl.downloadWithRetry(fl.config.ChinaDomainFileURL, fl.config.ChinaDomainFile); err != nil {
		fl.logger.Error("❌ 强制下载中国域名文件失败", map[string]interface{}{
			"file":  fl.config.ChinaDomainFile,
			"url":   fl.config.ChinaDomainFileURL,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 强制下载中国域名文件成功", map[string]interface{}{
		"file": fl.config.ChinaDomainFile,
	})

	// 检查下载的文件内容是否有效
	if !fl.isFileValid(fl.config.ChinaDomainFile) {
		fl.logger.Warn("⚠️ 下载的中国域名配置文件内容无效，跳过加载", map[string]interface{}{
			"file": fl.config.ChinaDomainFile,
		})
		return fmt.Errorf("下载的中国域名文件内容无效")
	}

	// 重新加载中国域名列表
	if err := fl.matcherHandler.GetChinaMatcher().LoadChinaDomains(fl.config.ChinaDomainFile); err != nil {
		fl.logger.Error("❌ 重新加载中国域名失败", map[string]interface{}{
			"file":  fl.config.ChinaDomainFile,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 中国域名重新加载完成", map[string]interface{}{
		"file": fl.config.ChinaDomainFile,
	})

	return nil
}

// LoadDesignatedDomains 加载定向域名列表
func (fl *FileLoader) LoadDesignatedDomains() error {
	// 如果配置文件不存在，直接返回，等待定时任务下载
	if fl.config.DesignatedDomain == "" {
		fl.logger.Info("📋 定向域名配置文件路径为空，跳过加载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
		return nil
	}

	// 检查文件是否存在
	if _, err := os.Stat(fl.config.DesignatedDomain); os.IsNotExist(err) {
		fl.logger.Info("📋 定向域名配置文件不存在，开始下载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
			"url":  fl.config.DesignatedDomainURL,
		})

		// 文件不存在，尝试下载
		if fl.config.DesignatedDomainURL != "" {
			if err := fl.downloadWithRetry(fl.config.DesignatedDomainURL, fl.config.DesignatedDomain); err != nil {
				fl.logger.Error("❌ 下载定向域名文件失败，创建空文件", map[string]interface{}{
					"file":  fl.config.DesignatedDomain,
					"url":   fl.config.DesignatedDomainURL,
					"error": err.Error(),
				})
				// 创建空文件以避免后续重复尝试下载
				if createErr := fl.createEmptyFile(fl.config.DesignatedDomain); createErr != nil {
					fl.logger.Error("❌ 创建空文件失败", map[string]interface{}{
						"file":  fl.config.DesignatedDomain,
						"error": createErr.Error(),
					})
				}
				return err
			}
			fl.logger.Info("✅ 下载定向域名文件成功", map[string]interface{}{
				"file": fl.config.DesignatedDomain,
			})
		} else {
			fl.logger.Warn("⚠️ 定向域名文件URL未配置", map[string]interface{}{
				"file": fl.config.DesignatedDomain,
			})
			return nil
		}
	} else {
		fl.logger.Info("📋 定向域名配置文件已存在，直接加载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
	}

	// 检查文件内容是否有效
	if !fl.isFileValid(fl.config.DesignatedDomain) {
		fl.logger.Warn("⚠️ 定向域名配置文件内容无效，跳过加载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
		return nil
	}

	// 加载定向域名列表
	if err := fl.matcherHandler.GetYAMLMatcher().LoadYAMLConfig(fl.config.DesignatedDomain); err != nil {
		fl.logger.Error("❌ 加载定向域名失败", map[string]interface{}{
			"file":  fl.config.DesignatedDomain,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 定向域名加载完成", map[string]interface{}{
		"file": fl.config.DesignatedDomain,
	})

	return nil
}

// ForceDownloadAndReloadDesignatedDomains 强制下载并重新加载定向域名列表（用于异步刷新）
func (fl *FileLoader) ForceDownloadAndReloadDesignatedDomains() error {
	// 如果配置文件不存在或URL未配置，直接返回
	if fl.config.DesignatedDomain == "" || fl.config.DesignatedDomainURL == "" {
		fl.logger.Warn("⚠️ 定向域名配置文件路径或URL为空，跳过下载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
			"url":  fl.config.DesignatedDomainURL,
		})
		return nil
	}

	fl.logger.Info("🔄 强制下载定向域名文件", map[string]interface{}{
		"file": fl.config.DesignatedDomain,
		"url":  fl.config.DesignatedDomainURL,
	})

	// 强制下载文件
	if err := fl.downloadWithRetry(fl.config.DesignatedDomainURL, fl.config.DesignatedDomain); err != nil {
		fl.logger.Error("❌ 强制下载定向域名文件失败", map[string]interface{}{
			"file":  fl.config.DesignatedDomain,
			"url":   fl.config.DesignatedDomainURL,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 强制下载定向域名文件成功", map[string]interface{}{
		"file": fl.config.DesignatedDomain,
	})

	// 检查下载的文件内容是否有效
	if !fl.isFileValid(fl.config.DesignatedDomain) {
		fl.logger.Warn("⚠️ 下载的定向域名配置文件内容无效，跳过加载", map[string]interface{}{
			"file": fl.config.DesignatedDomain,
		})
		return fmt.Errorf("下载的定向域名文件内容无效")
	}

	// 重新加载定向域名列表
	if err := fl.matcherHandler.GetYAMLMatcher().LoadYAMLConfig(fl.config.DesignatedDomain); err != nil {
		fl.logger.Error("❌ 重新加载定向域名失败", map[string]interface{}{
			"file":  fl.config.DesignatedDomain,
			"error": err.Error(),
		})
		return err
	}

	fl.logger.Info("✅ 定向域名重新加载完成", map[string]interface{}{
		"file": fl.config.DesignatedDomain,
	})

	return nil
}

// downloadWithRetry 带重试的下载功能
func (fl *FileLoader) downloadWithRetry(url, targetFile string) error {
	// 重试次数
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		fl.logger.Debug("尝试下载文件", map[string]interface{}{
			"url":     url,
			"file":    targetFile,
			"attempt": i + 1,
		})

		if err := fl.downloadFile(url, targetFile); err != nil {
			lastErr = err
			fl.logger.Warn("下载失败，准备重试", map[string]interface{}{
				"url":         url,
				"file":        targetFile,
				"attempt":     i + 1,
				"max_retries": maxRetries,
				"error":       err.Error(),
			})
			// 等待一段时间再重试
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}

		// 下载成功，检查文件内容是否有效
		if fl.isFileValid(targetFile) {
			fl.logger.Info("下载成功且文件内容有效", map[string]interface{}{
				"url":  url,
				"file": targetFile,
			})
			return nil
		} else {
			lastErr = fmt.Errorf("下载的文件内容无效")
			fl.logger.Warn("下载的文件内容无效，准备重试", map[string]interface{}{
				"url":         url,
				"file":        targetFile,
				"attempt":     i + 1,
				"max_retries": maxRetries,
			})
			// 等待一段时间再重试
			time.Sleep(time.Duration(i+1) * time.Second)
		}
	}

	return fmt.Errorf("下载失败，已重试 %d 次: %w", maxRetries, lastErr)
}

// isFileValid 检查文件内容是否有效
func (fl *FileLoader) isFileValid(filePath string) bool {
	// 检查文件是否存在
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return false
	}

	// 读取文件内容
	content, err := os.ReadFile(filePath)
	if err != nil {
		fl.logger.Warn("读取文件失败", map[string]interface{}{
			"file":  filePath,
			"error": err.Error(),
		})
		return false
	}

	// 检查文件是否为空
	if len(content) == 0 {
		fl.logger.Debug("文件为空", map[string]interface{}{
			"file": filePath,
		})
		return false
	}

	// 检查文件内容是否包含有效数据（非纯空白字符）
	trimmedContent := strings.TrimSpace(string(content))
	if len(trimmedContent) == 0 {
		fl.logger.Debug("文件内容为空白字符", map[string]interface{}{
			"file": filePath,
		})
		return false
	}

	return true
}

// createEmptyFile 创建空文件
func (fl *FileLoader) createEmptyFile(filePath string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 创建一个基本的YAML结构，避免完全空文件
	var emptyContent []byte
	if strings.Contains(filePath, "designated") {
		// 为designated.yaml创建基本结构
		emptyContent = []byte("# Empty designated domains configuration\npayload: []\n")
	} else if strings.Contains(filePath, "china") {
		// 为china_domains.yaml创建基本结构
		emptyContent = []byte("# Empty china domains configuration\npayload: []\n")
	} else {
		// 默认空内容
		emptyContent = []byte{}
	}

	return os.WriteFile(filePath, emptyContent, 0644)
}
