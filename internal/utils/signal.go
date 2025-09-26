package utils

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// SignalHandler 信号处理器
type SignalHandler struct {
	logger        *EnhancedLogger
	shutdownFuncs []func() error
	reloadFuncs   []func() error
	ctx           context.Context
	cancel        context.CancelFunc
}

// NewSignalHandler 创建信号处理器
func NewSignalHandler(logger *EnhancedLogger) *SignalHandler {
	ctx, cancel := context.WithCancel(context.Background())
	return &SignalHandler{
		logger: logger,
		ctx:    ctx,
		cancel: cancel,
	}
}

// AddShutdownFunc 添加关闭时执行的函数
func (sh *SignalHandler) AddShutdownFunc(f func() error) {
	sh.shutdownFuncs = append(sh.shutdownFuncs, f)
}

// AddReloadFunc 添加重新加载时执行的函数
func (sh *SignalHandler) AddReloadFunc(f func() error) {
	sh.reloadFuncs = append(sh.reloadFuncs, f)
}

// Start 开始监听信号
func (sh *SignalHandler) Start() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // 终止信号
		syscall.SIGQUIT, // 退出信号
		syscall.SIGHUP,  // 挂起信号（重新加载配置）
	)

	go func() {
		for {
			select {
			case sig := <-sigChan:
				sh.handleSignal(sig)
			case <-sh.ctx.Done():
				return
			}
		}
	}()
}

// handleSignal 处理信号
func (sh *SignalHandler) handleSignal(sig os.Signal) {
	switch sig {
	case syscall.SIGHUP:
		sh.logger.Info("🔄 [接收到SIGHUP信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": "SIGHUP",
			"action": "reload_config",
		})
		sh.reload()

	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
		sh.logger.Info("📪 [接收到退出信号] ", map[string]interface{}{
			"rule":   "SIGNAL_RECEIVED",
			"signal": sig.String(),
			"action": "graceful_shutdown",
		})
		sh.gracefulShutdown()
	}
}

// reload 重新加载配置
func (sh *SignalHandler) reload() {
	sh.logger.Info("🔄 [开始重新加载配置] ", map[string]interface{}{
		"rule": "CONFIG_RELOAD_START",
	})

	for i, f := range sh.reloadFuncs {
		if err := f(); err != nil {
			sh.logger.Error("❌ [重新加载函数执行失败] ", map[string]interface{}{
				"rule":     "RELOAD_FUNC_FAILED",
				"function": i,
				"error":    err.Error(),
			})
		}
	}

	sh.logger.Info("✅ [配置重新加载完成] ", map[string]interface{}{
		"rule": "CONFIG_RELOAD_COMPLETE",
	})
}

// gracefulShutdown 优雅关闭
func (sh *SignalHandler) gracefulShutdown() {
	sh.logger.Info("🔄 [开始优雅关闭] ", map[string]interface{}{
		"rule": "GRACEFUL_SHUTDOWN_START",
	})

	// 设置关闭超时
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// 执行关闭函数
	done := make(chan struct{})
	go func() {
		for i, f := range sh.shutdownFuncs {
			if err := f(); err != nil {
				sh.logger.Error("❌ [关闭函数执行失败] ", map[string]interface{}{
					"rule":     "SHUTDOWN_FUNC_FAILED",
					"function": i,
					"error":    err.Error(),
				})
			}
		}
		close(done)
	}()

	// 等待关闭完成或超时
	select {
	case <-done:
		sh.logger.Info("✅ [优雅关闭完成] ", map[string]interface{}{
			"rule": "GRACEFUL_SHUTDOWN_COMPLETE",
		})
	case <-shutdownCtx.Done():
		sh.logger.Warn("⚠️ [优雅关闭超时] ", map[string]interface{}{
			"rule": "GRACEFUL_SHUTDOWN_TIMEOUT",
		})
	}

	// 取消上下文
	sh.cancel()
	os.Exit(0)
}

// Stop 停止信号处理
func (sh *SignalHandler) Stop() {
	sh.cancel()
}

// Context 获取上下文
func (sh *SignalHandler) Context() context.Context {
	return sh.ctx
}

// WriteReadinessFile 写入就绪文件（用于健康检查）
func WriteReadinessFile(path string) error {
	return os.WriteFile(path, []byte(fmt.Sprintf("ready:%d", os.Getpid())), 0644)
}

// RemoveReadinessFile 删除就绪文件
func RemoveReadinessFile(path string) error {
	return os.Remove(path)
}
