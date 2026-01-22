package recovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/dns"
	"cosDnaPorxy/internal/utils"
)

// RecoveryManager panic恢复管理器
type RecoveryManager struct {
	config          *config.Config
	logger          *utils.EnhancedLogger
	dnsHandler      *dns.RefactoredHandler
	udpServer       *dns.Server
	tcpServer       *dns.Server
	ctx             context.Context
	cancel          context.CancelFunc
	mu              sync.RWMutex
	running         bool
	restartCount    int
	panicCount      int
	lastRestart     time.Time
	restartChan     chan struct{}
	maxRestarts     int
	restartInterval time.Duration
	startTime       time.Time
}

// NewRecoveryManager 创建新的panic恢复管理器
func NewRecoveryManager(cfg *config.Config, logger *utils.EnhancedLogger) *RecoveryManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &RecoveryManager{
		config:          cfg,
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
		restartChan:     make(chan struct{}, 1),
		maxRestarts:     100,             // 最大重启次数
		restartInterval: 5 * time.Second, // 初始重启间隔
		running:         false,
		startTime:       time.Now(), // 初始化startTime
	}
}

// Start 启动带panic恢复的服务
func (rm *RecoveryManager) Start() error {
	rm.logger.Info("🔄 [启动恢复管理器] ", map[string]interface{}{
		"rule": "RECOVERY_MANAGER_START",
	})

	// 设置信号处理
	rm.setupSignalHandler()

	// 启动DNS服务
	if err := rm.startDNSService(); err != nil {
		return fmt.Errorf("启动DNS服务失败: %w", err)
	}

	// 主循环
	rm.mainLoop()

	return nil
}

// mainLoop 主循环
func (rm *RecoveryManager) mainLoop() {
	rm.logger.Info("🔄 [进入主循环] ", map[string]interface{}{
		"rule": "MAIN_LOOP_START",
	})

	for {
		select {
		case <-rm.ctx.Done():
			rm.logger.Info("🛑 [主循环退出] ", map[string]interface{}{
				"rule": "MAIN_LOOP_EXIT",
			})
			return

		case <-rm.restartChan:
			rm.handleRestart()

		case <-time.After(30 * time.Second):
			// 定期健康检查
			rm.healthCheck()
			// 检查上下文是否被取消，避免在长时间运行后无法退出
			if rm.ctx.Err() != nil {
				return
			}
		}
	}
}

// startDNSService 启动DNS服务（带panic恢复）
func (rm *RecoveryManager) startDNSService() error {
	defer func() {
		if r := recover(); r != nil {
			rm.handlePanic(r)
		}
	}()

	rm.mu.Lock()
	defer rm.mu.Unlock()

	rm.logger.Info("🚀 [启动DNS服务] ", map[string]interface{}{
		"rule": "DNS_SERVICE_START",
		"port": rm.config.ListenPort,
	})

	// 创建DNS处理器
	handler, err := dns.NewRefactoredHandler(rm.config, rm.logger)
	if err != nil {
		return fmt.Errorf("创建DNS处理器失败: %w", err)
	}
	rm.dnsHandler = handler

	// 创建UDP DNS服务器
	udpServer, err := dns.NewUDPServer(rm.config, handler)
	if err != nil {
		return fmt.Errorf("创建UDP DNS服务器失败: %w", err)
	}

	// 创建TCP DNS服务器
	tcpServer, err := dns.NewTCPServer(rm.config, handler)
	if err != nil {
		return fmt.Errorf("创建TCP DNS服务器失败: %w", err)
	}

	// 创建一个临时的UDP连接来验证端口可用性
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", rm.config.ListenPort))
	if err != nil {
		return fmt.Errorf("解析UDP地址失败: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		rm.logger.Error("❌ [UDP端口检查失败] ", map[string]interface{}{
			"rule":  "PORT_CHECK_FAILED",
			"type":  "UDP",
			"error": err.Error(),
		})
		return fmt.Errorf("UDP端口 %d 已被占用: %w", rm.config.ListenPort, err)
	}
	udpConn.Close()

	// 创建一个临时的TCP连接来验证端口可用性
	tcpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", rm.config.ListenPort))
	if err != nil {
		rm.logger.Error("❌ [TCP端口检查失败] ", map[string]interface{}{
			"rule":  "PORT_CHECK_FAILED",
			"type":  "TCP",
			"error": err.Error(),
		})
		return fmt.Errorf("TCP端口 %d 已被占用: %w", rm.config.ListenPort, err)
	}
	tcpListener.Close()

	// 设置服务器实例
	rm.udpServer = udpServer
	rm.tcpServer = tcpServer

	// 在单独的goroutine中启动UDP服务器（带panic恢复）
	go rm.runDNSServer(udpServer, "UDP")

	// 在单独的goroutine中启动TCP服务器（带panic恢复）
	go rm.runDNSServer(tcpServer, "TCP")

	rm.running = true
	rm.logger.Info("✅ [DNS服务启动成功] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STARTED",
	})

	return nil
}

// runDNSServer 运行DNS服务器（带panic恢复）
func (rm *RecoveryManager) runDNSServer(server *dns.Server, serverType string) {
	defer func() {
		if r := recover(); r != nil {
			rm.handlePanic(r)
			// 触发重启
			select {
			case rm.restartChan <- struct{}{}:
			default:
			}
		}
	}()

	if err := server.Start(); err != nil {
		rm.logger.Error("❌ [DNS服务器运行失败] ", map[string]interface{}{
			"rule":  "DNS_SERVER_FAILED",
			"type":  serverType,
			"error": err.Error(),
		})

		// 检查错误是否是端口被占用
		if strings.Contains(err.Error(), "address already in use") ||
			strings.Contains(err.Error(), "bind: address already in use") {
			rm.logger.Warn("⚠️ [端口已被占用，不触发重启] ", map[string]interface{}{
				"rule": "PORT_ALREADY_IN_USE_NO_RESTART",
				"type": serverType,
			})
			return // 端口被占用时不触发重启
		}

		// 触发重启
		select {
		case rm.restartChan <- struct{}{}:
		default:
		}
	}
}

// stopDNSService 停止DNS服务
func (rm *RecoveryManager) stopDNSService() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.running {
		return
	}

	rm.logger.Info("🔄 [停止DNS服务] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STOP",
	})

	// 停止UDP DNS服务器
	if rm.udpServer != nil {
		rm.udpServer.Stop()
		rm.udpServer = nil
	}

	// 停止TCP DNS服务器
	if rm.tcpServer != nil {
		rm.tcpServer.Stop()
		rm.tcpServer = nil
	}

	// 确保服务器完全停止后等待一段时间，避免端口立即被重用
	time.Sleep(100 * time.Millisecond)

	// 关闭DNS处理器
	if rm.dnsHandler != nil {
		rm.dnsHandler.Close()
		rm.dnsHandler = nil
	}

	rm.running = false
	rm.logger.Info("✅ [DNS服务已停止] ", map[string]interface{}{
		"rule": "DNS_SERVICE_STOPPED",
	})
}

// handlePanic 处理panic
func (rm *RecoveryManager) handlePanic(r interface{}) {
	rm.panicCount++

	// 获取调用栈
	stack := debug.Stack()

	rm.logger.Error("💥 [检测到Panic] ", map[string]interface{}{
		"rule":        "PANIC_DETECTED",
		"panic_msg":   fmt.Sprintf("%v", r),
		"panic_count": rm.panicCount,
		"stack_trace": string(stack),
	})

	// 记录更详细的运行时信息
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	rm.logger.Debug("💾 运行时内存信息", map[string]interface{}{
		"alloc_mb":       m.Alloc / 1024 / 1024,
		"total_alloc_mb": m.TotalAlloc / 1024 / 1024,
		"sys_mb":         m.Sys / 1024 / 1024,
		"num_gc":         m.NumGC,
		"goroutines":     runtime.NumGoroutine(),
	})

	// 触发重启
	select {
	case rm.restartChan <- struct{}{}:
	default:
	}
}

// handleRestart 处理重启
func (rm *RecoveryManager) handleRestart() {
	rm.restartCount++
	rm.lastRestart = time.Now()

	rm.logger.Warn("🔄 [开始服务重启] ", map[string]interface{}{
		"rule":          "SERVICE_RESTART",
		"restart_count": rm.restartCount,
		"panic_count":   rm.panicCount,
	})

	// 检查重启次数限制
	if rm.restartCount > rm.maxRestarts {
		rm.logger.Error("❌ [重启次数超限，服务退出] ", map[string]interface{}{
			"rule":          "RESTART_LIMIT_EXCEEDED",
			"restart_count": rm.restartCount,
			"max_restarts":  rm.maxRestarts,
		})
		rm.cancel()
		return
	}

	// 停止当前服务
	rm.stopDNSService()

	// 额外等待一段时间确保端口完全释放
	time.Sleep(500 * time.Millisecond)

	// 等待一段时间后重启
	rm.logger.Debug("⏱️ 等待重启间隔", map[string]interface{}{
		"interval": rm.restartInterval.String(),
	})
	time.Sleep(rm.restartInterval)

	// 重新启动服务
	if err := rm.startDNSService(); err != nil {
		rm.logger.Error("❌ [重启DNS服务失败] ", map[string]interface{}{
			"rule":  "RESTART_FAILED",
			"error": err.Error(),
		})

		// 增加重启间隔并再次尝试
		rm.restartInterval = time.Duration(float64(rm.restartInterval) * 1.5)
		if rm.restartInterval > 60*time.Second {
			rm.restartInterval = 60 * time.Second
		}

		time.Sleep(rm.restartInterval)
		select {
		case rm.restartChan <- struct{}{}:
		default:
		}
		return
	}

	rm.logger.Info("✅ [服务重启成功] ", map[string]interface{}{
		"rule":          "SERVICE_RESTARTED",
		"restart_count": rm.restartCount,
	})

	// 重置重启间隔
	rm.restartInterval = 5 * time.Second
}

// healthCheck 健康检查
func (rm *RecoveryManager) healthCheck() {
	rm.mu.RLock()
	running := rm.running
	rm.mu.RUnlock()

	if !running {
		rm.logger.Warn("⚠️ [健康检查失败] ", map[string]interface{}{
			"rule":   "HEALTH_CHECK_FAILED",
			"reason": "service_not_running",
		})

		// 触发重启
		select {
		case rm.restartChan <- struct{}{}:
		default:
		}
		return
	}

	// 检查内存使用情况
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	allocMB := m.Alloc / 1024 / 1024
	if allocMB > 500 { // 如果内存使用超过500MB
		rm.logger.Warn("⚠️ [内存使用过高] ", map[string]interface{}{
			"rule":     "HIGH_MEMORY_USAGE",
			"alloc_mb": allocMB,
		})

		// 强制GC
		runtime.GC()
	}

	// 获取统计信息以显示IP统计
	stats := rm.GetStats()
	cacheInfo, ok := stats["cache"].(map[string]interface{})

	logFields := map[string]interface{}{
		"uptime":        time.Since(rm.startTime).String(),
		"restart_count": rm.restartCount,
		"panic_count":   rm.panicCount,
		"memory_mb":     allocMB,
		"goroutines":    runtime.NumGoroutine(),
	}

	// 添加缓存IP统计信息到日志
	if ok && cacheInfo != nil {
		if ipCounts, exists := cacheInfo["ip_counts"].(map[string]interface{}); exists {
			logFields["cached_a_records"] = ipCounts["A"]
			logFields["cached_aaaa_records"] = ipCounts["AAAA"]
			logFields["total_cached_ips"] = ipCounts["A"]
			if aaaaCount, ok := ipCounts["AAAA"].(int); ok {
				if aCount, ok := ipCounts["A"].(int); ok {
					logFields["total_cached_ips"] = aCount + aaaaCount
				}
			}
		}
		logFields["cache_size"] = cacheInfo["size"]
		logFields["cache_valid_entries"] = cacheInfo["valid_entries"]
	}

	rm.logger.Debug("✅ 健康检查通过", logFields)
}

// setupSignalHandler 设置信号处理
func (rm *RecoveryManager) setupSignalHandler() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // 终止信号
		syscall.SIGQUIT, // 退出信号
		syscall.SIGHUP,  // 挂起信号（重新加载配置）
	)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				rm.handlePanic(r)
			}
		}()

		for {
			select {
			case sig := <-sigChan:
				rm.handleSignal(sig)
			case <-rm.ctx.Done():
				return
			}
		}
	}()
}

// handleSignal 处理系统信号
func (rm *RecoveryManager) handleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGHUP:
		rm.logger.Info("🔄 [接收到SIGHUP信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": "SIGHUP",
			"action": "reload_config",
		})
		// 这里可以实现配置重新加载

	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
		rm.logger.Info("📪 [接收到退出信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": sig.String(),
			"action": "graceful_shutdown",
		})
		// 立即开始优雅退出，不等待
		go rm.gracefulShutdown()
	}
}

// gracefulShutdown 优雅退出
func (rm *RecoveryManager) gracefulShutdown() {
	rm.logger.Info("🔄 [开始优雅退出] ", map[string]interface{}{
		"rule": "GRACEFUL_SHUTDOWN_START",
	})

	// 设置优雅关闭超时
	shutdownTimeout := 10 * time.Second
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()

	// 在单独的goroutine中停止服务
	done := make(chan struct{})
	go func() {
		defer close(done)
		// 停止服务
		rm.stopDNSService()
		// 额外等待一段时间确保端口完全释放
		time.Sleep(500 * time.Millisecond)
		// 取消上下文
		rm.cancel()
	}()

	// 等待服务停止或超时
	select {
	case <-done:
		rm.logger.Info("✅ [优雅退出完成] ", map[string]interface{}{
			"rule":          "GRACEFUL_SHUTDOWN_COMPLETE",
			"uptime":        time.Since(rm.startTime).String(),
			"restart_count": rm.restartCount,
			"panic_count":   rm.panicCount,
		})
	case <-shutdownCtx.Done():
		rm.logger.Warn("⚠️ [优雅退出超时，强制退出] ", map[string]interface{}{
			"rule":    "GRACEFUL_SHUTDOWN_TIMEOUT",
			"timeout": shutdownTimeout.String(),
		})
		// 强制退出
		os.Exit(1)
	}
}

// GetStats 获取统计信息
func (rm *RecoveryManager) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	stats := map[string]interface{}{
		"running":         rm.running,
		"restart_count":   rm.restartCount,
		"panic_count":     rm.panicCount,
		"uptime":          time.Since(rm.startTime).String(),
		"memory_alloc_mb": m.Alloc / 1024 / 1024,
		"goroutines":      runtime.NumGoroutine(),
		"max_restarts":    rm.maxRestarts,
	}

	// 如果DNS处理器存在，添加缓存统计信息
	if rm.dnsHandler != nil && rm.dnsHandler.GetCacheManager() != nil {
		// 获取缓存统计信息（不包含详细条目信息以节省资源）
		cacheStats := rm.dnsHandler.GetCacheManager().GetStats(false)
		if cacheStats != nil {
			cacheInfo := map[string]interface{}{
				"size":          cacheStats.Size,
				"max_size":      cacheStats.MaxSize,
				"valid_entries": cacheStats.ValidEntries,
				"expired_count": cacheStats.ExpiredCount,
			}
			// 添加IP统计信息
			if cacheStats.IPCounts != nil {
				cacheInfo["ip_counts"] = cacheStats.IPCounts
			}
			stats["cache"] = cacheInfo

			// 获取热点条目（前10个）
			hotEntries := rm.dnsHandler.GetCacheManager().GetHotEntries(10)
			if len(hotEntries) > 0 {
				hotEntryList := make([]map[string]interface{}, 0, len(hotEntries))
				for _, entry := range hotEntries {
					hotEntryList = append(hotEntryList, map[string]interface{}{
						"domain":      entry.Domain,
						"qtype":       entry.QType,
						"last_access": entry.LastAccess.Format(time.RFC3339),
					})
				}
				stats["hot_entries"] = hotEntryList
			}

			// 获取过期条目（前10个）
			if len(cacheStats.ExpiredEntries) > 0 {
				limit := 10
				if len(cacheStats.ExpiredEntries) < limit {
					limit = len(cacheStats.ExpiredEntries)
				}
				expiredList := make([]string, 0, limit)
				for i := 0; i < limit; i++ {
					expiredList = append(expiredList, cacheStats.ExpiredEntries[i])
				}
				stats["expired_entries"] = expiredList
			}
		}
	}

	if !rm.lastRestart.IsZero() {
		stats["last_restart"] = rm.lastRestart.Format(time.RFC3339)
		stats["time_since_restart"] = time.Since(rm.lastRestart).String()
	}

	return stats
}
