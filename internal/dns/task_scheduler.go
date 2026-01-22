package dns

import (
	"context"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"
)

// TaskScheduler 处理定时任务调度
type TaskScheduler struct {
	config        *config.Config
	logger        *utils.EnhancedLogger
	fileLoader    *FileLoader
	cloudDetector *CloudDetector
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewTaskScheduler 创建新的任务调度器
func NewTaskScheduler(
	config *config.Config,
	logger *utils.EnhancedLogger,
	fileLoader *FileLoader,
	cloudDetector *CloudDetector,
) *TaskScheduler {
	ctx, cancel := context.WithCancel(context.Background())

	return &TaskScheduler{
		config:        config,
		logger:        logger,
		fileLoader:    fileLoader,
		cloudDetector: cloudDetector,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// StartBackgroundTasks 启动后台任务
func (ts *TaskScheduler) StartBackgroundTasks() {
	// 延迟启动定时任务，避免与DNS服务器启动冲突
	go func() {
		time.Sleep(2 * time.Second) // 等待DNS服务器启动完成

		// 定向域名刷新任务
		if ts.config.DesignatedDomain != "" && ts.config.DesignatedRefreshInterval > 0 {
			go ts.DesignatedRefreshTask()
		}

		// 中国域名刷新任务
		if ts.config.EnableChinaDomainCheck && ts.config.ChinaDomainFile != "" && ts.config.ChinaDomainRefreshInterval > 0 {
			ts.logger.Info("🔄 [中国域名定时刷新启动] ", map[string]interface{}{
				"rule":     "CHINA_DOMAIN_REFRESH_TASK",
				"interval": ts.config.ChinaDomainRefreshInterval.String(),
				"enabled":  ts.config.EnableChinaDomainCheck,
			})
			go ts.ChinaDomainRefreshTask()
		} else {
			ts.logger.Info("⏭️ [中国域名定时刷新已禁用] ", map[string]interface{}{
				"rule":    "CHINA_DOMAIN_REFRESH_SKIPPED",
				"enabled": ts.config.EnableChinaDomainCheck,
			})
		}

		// 网络段刷新任务（仅在启用云服务检查时启动）
		if (ts.config.EnableCloudflareCheck || ts.config.EnableAWSCheck) && ts.config.NetworkRefreshInterval > 0 {
			ts.logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
				"rule":       "NETWORK_REFRESH_TASK",
				"interval":   ts.config.NetworkRefreshInterval.String(),
				"enable_cf":  ts.config.EnableCloudflareCheck,
				"enable_aws": ts.config.EnableAWSCheck,
			})
			go ts.NetworkRefreshTask()
		} else {
			ts.logger.Info("⏭️ [网络段定时刷新已禁用] ", map[string]interface{}{
				"rule":       "NETWORK_REFRESH_SKIPPED",
				"enable_cf":  ts.config.EnableCloudflareCheck,
				"enable_aws": ts.config.EnableAWSCheck,
			})
		}
	}()
}

// DesignatedRefreshTask 定向域名刷新任务
func (ts *TaskScheduler) DesignatedRefreshTask() {
	ticker := time.NewTicker(ts.config.DesignatedRefreshInterval)
	defer ticker.Stop()

	ts.logger.Info("🔄 [定向域名定时刷新启动] ", map[string]interface{}{
		"rule":     "DESIGNATED_REFRESH_TASK",
		"interval": ts.config.DesignatedRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			ts.logger.Debug("开始定时定向域名刷新", map[string]interface{}{
				"file": ts.config.DesignatedDomain,
				"url":  ts.config.DesignatedDomainURL,
			})
			if err := ts.fileLoader.ForceDownloadAndReloadDesignatedDomains(); err != nil {
				ts.logger.Error("❌ [定向域名刷新失败] ", map[string]interface{}{
					"rule":  "DESIGNATED_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				ts.logger.Info("✅ [定向域名刷新成功] ", map[string]interface{}{
					"rule": "DESIGNATED_REFRESH_SUCCESS",
				})
			}
		case <-ts.ctx.Done():
			ts.logger.Info("📋 [定向域名刷新任务停止] ", map[string]interface{}{
				"rule": "DESIGNATED_REFRESH_STOPPED",
			})
			return
		}
	}
}

// ChinaDomainRefreshTask 中国域名刷新任务
func (ts *TaskScheduler) ChinaDomainRefreshTask() {
	ticker := time.NewTicker(ts.config.ChinaDomainRefreshInterval)
	defer ticker.Stop()

	ts.logger.Info("🔄 [中国域名定时刷新启动] ", map[string]interface{}{
		"rule":     "CHINA_DOMAIN_REFRESH_TASK",
		"interval": ts.config.ChinaDomainRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			ts.logger.Debug("开始定时中国域名刷新", map[string]interface{}{
				"file": ts.config.ChinaDomainFile,
				"url":  ts.config.ChinaDomainFileURL,
			})
			if err := ts.fileLoader.ForceDownloadAndReloadChinaDomains(); err != nil {
				ts.logger.Error("❌ [中国域名刷新失败] ", map[string]interface{}{
					"rule":  "CHINA_DOMAIN_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				ts.logger.Info("✅ [中国域名刷新成功] ", map[string]interface{}{
					"rule": "CHINA_DOMAIN_REFRESH_SUCCESS",
				})
			}
		case <-ts.ctx.Done():
			ts.logger.Info("📋 [中国域名刷新任务停止] ", map[string]interface{}{
				"rule": "CHINA_DOMAIN_REFRESH_STOPPED",
			})
			return
		}
	}
}

// NetworkRefreshTask 网络段刷新任务
func (ts *TaskScheduler) NetworkRefreshTask() {
	ticker := time.NewTicker(ts.config.NetworkRefreshInterval)
	defer ticker.Stop()

	ts.logger.Info("🔄 [网络段定时刷新启动] ", map[string]interface{}{
		"rule":     "NETWORK_REFRESH_TASK",
		"interval": ts.config.NetworkRefreshInterval.String(),
	})

	for {
		select {
		case <-ticker.C:
			// 根据开关决定传递哪些文件路径
			cfFile4 := ""
			cfFile6 := ""
			awsFile := ""
			if ts.config.EnableCloudflareCheck {
				cfFile4 = ts.config.CloudflareNetFile
				cfFile6 = ts.config.CloudflareNetFile6
			}
			if ts.config.EnableAWSCheck {
				awsFile = ts.config.AWSNetFile
			}
			ts.logger.Debug("开始定时网络段刷新", map[string]interface{}{
				"cloudflare_v4": cfFile4,
				"cloudflare_v6": cfFile6,
				"aws_file":      awsFile,
			})
			if err := ts.cloudDetector.LoadNetworkRanges(
				cfFile4,
				cfFile6,
				awsFile,
			); err != nil {
				ts.logger.Error("❌ [网络段刷新失败] ", map[string]interface{}{
					"rule":  "NETWORK_REFRESH_FAILED",
					"error": err.Error(),
				})
			} else {
				ts.logger.Info("✅ [网络段刷新成功] ", map[string]interface{}{
					"rule": "NETWORK_REFRESH_SUCCESS",
				})
			}
		case <-ts.ctx.Done():
			ts.logger.Info("📋 [网络段刷新任务停止] ", map[string]interface{}{
				"rule": "NETWORK_REFRESH_STOPPED",
			})
			return
		}
	}
}

// Stop 停止所有定时任务
func (ts *TaskScheduler) Stop() {
	ts.cancel()
}
