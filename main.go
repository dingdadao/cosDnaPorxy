package main

import (
	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/dns"
	"cosDnaPorxy/internal/metrics"
	"cosDnaPorxy/internal/utils"
	"log"
)

func main() {
	// 加载配置
	cfg := config.LoadAndValidateConfig()

	// 自动初始化资源文件和目录
	if err := utils.InitResourceFiles(cfg); err != nil {
		log.Printf("资源初始化失败: %v", err)
	}
	
	// 创建DNS处理器
	handler := dns.NewHandler(cfg)
	
	// 启动监控服务器
	go metrics.StartMetricsServer(cfg.MetricsPort)
	
	// 启动各种DNS服务器
	go dns.StartUDPServer(cfg, handler)
	go dns.StartDoTServer(cfg, handler)
	go dns.StartDoHServer(cfg, handler)

	log.Println("DNS代理服务器启动完成")
	
	// 保持主线程活着
	select {}
}
