package main

import (
	"log"
	"os"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/recovery"
	"cosDnaPorxy/internal/utils"
)

func main() {
	// 加载配置
	cfg := config.LoadAndValidateConfig()

	// 自动初始化资源文件和目录
	if err := utils.InitResourceFiles(cfg); err != nil {
		log.Printf("资源初始化失败: %v", err)
	}

	// 创建日志系统
	logger := utils.NewEnhancedLogger(cfg.LogLevel, "dns-proxy", cfg.LogFormat == "json")

	logger.Info("🚀 [正在启动DNS代理服务] ", map[string]interface{}{
		"rule": "MAIN_START",
		"pid":  os.Getpid(),
		"port": cfg.ListenPort,
	})

	// 创建panic恢复管理器
	recoveryManager := recovery.NewRecoveryManager(cfg, logger)

	// 启动带panic恢复的服务
	if err := recoveryManager.Start(); err != nil {
		logger.Error("❌ [恢复管理器启动失败] ", map[string]interface{}{
			"rule":  "RECOVERY_MANAGER_START_FAILED",
			"error": err.Error(),
		})
		os.Exit(1)
	}

	logger.Info("💪 [DNS代理服务正常退出] ", map[string]interface{}{
		"rule": "MAIN_EXIT",
	})
}
