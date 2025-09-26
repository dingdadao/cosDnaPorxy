package dns

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/utils"

	"github.com/miekg/dns"
)

// Server DNS服务器包装器
type Server struct {
	config  *config.Config
	logger  *utils.EnhancedLogger
	handler *RefactoredHandler
	server  *dns.Server
	conn    net.PacketConn
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.RWMutex
	running bool
}

// NewUDPServer 创建UDP DNS服务器
func NewUDPServer(cfg *config.Config, handler *RefactoredHandler) (*Server, error) {
	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:  cfg,
		logger:  handler.Logger,
		handler: handler,
		ctx:     ctx,
		cancel:  cancel,
	}, nil
}

// Start 启动DNS服务器
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("DNS服务器已在运行")
	}

	// 创建UDP连接
	addr := fmt.Sprintf(":%d", s.config.ListenPort)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("监听UDP端口失败: %w", err)
	}
	s.conn = conn

	// 创建DNS服务器
	s.server = &dns.Server{
		PacketConn: conn,
		Handler:    s.handler,
		Net:        "udp",
	}

	s.running = true

	s.logger.Info("🚀 [UDP DNS服务器启动] ", map[string]interface{}{
		"rule": "UDP_SERVER_START",
		"addr": addr,
	})

	// 启动服务器（阻塞）
	if err := s.server.ActivateAndServe(); err != nil {
		s.running = false
		return fmt.Errorf("DNS服务器启动失败: %w", err)
	}

	return nil
}

// Stop 停止DNS服务器
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.logger.Info("🔄 [停止UDP DNS服务器] ", map[string]interface{}{
		"rule": "UDP_SERVER_STOP",
	})

	// 设置关闭超时
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// 关闭服务器
	if s.server != nil {
		if err := s.server.ShutdownContext(shutdownCtx); err != nil {
			s.logger.Warn("⚠️ DNS服务器关闭警告", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// 关闭连接
	if s.conn != nil {
		if err := s.conn.Close(); err != nil {
			s.logger.Warn("⚠️ 连接关闭警告", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	s.running = false
	s.cancel()

	s.logger.Info("✅ [UDP DNS服务器已停止] ", map[string]interface{}{
		"rule": "UDP_SERVER_STOPPED",
	})
}

// IsRunning 检查服务器是否在运行
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// GetStats 获取服务器统计信息
func (s *Server) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := map[string]interface{}{
		"running": s.running,
		"port":    s.config.ListenPort,
		"type":    "udp",
	}

	if s.running && s.conn != nil {
		stats["local_addr"] = s.conn.LocalAddr().String()
	}

	return stats
}

// StartUDPServer 启动UDP DNS服务器（兼容旧接口）
func StartUDPServer(cfg *config.Config, handler *RefactoredHandler) {
	server, err := NewUDPServer(cfg, handler)
	if err != nil {
		handler.Logger.Error("❌ 创建UDP服务器失败", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	if err := server.Start(); err != nil {
		handler.Logger.Error("❌ 启动UDP服务器失败", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}
}
