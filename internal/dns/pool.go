package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===== DoT 连接池实现 =====

// DoTConnPool DoT连接池
type DoTConnPool struct {
	mu       sync.RWMutex
	conns    map[string]*DoTConn
	maxConns int
	timeout  time.Duration
}

// DoTConn 单个DoT连接
type DoTConn struct {
	conn     net.Conn
	tlsConn  *tls.Conn
	lastUsed time.Time
	inUse    bool
	server   string
}

// NewDoTConnPool 创建新的DoT连接池
func NewDoTConnPool() *DoTConnPool {
	return &DoTConnPool{
		conns:    make(map[string]*DoTConn),
		maxConns: 10,  // 增加每个服务器的最大连接数
		timeout:  30 * time.Second, // 增加连接超时时间
	}
}

// GetConn 获取DoT连接
func (p *DoTConnPool) GetConn(ctx context.Context, server string) (*DoTConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有连接
	if conn, ok := p.conns[server]; ok && !conn.inUse {
		// 检查连接是否还有效
		if time.Since(conn.lastUsed) < p.timeout {
			conn.inUse = true
			conn.lastUsed = time.Now()
			log.Printf("[DoT连接池] 复用现有连接: %s", server)
			return conn, nil
		} else {
			// 连接过期，关闭并移除
			log.Printf("[DoT连接池] 连接已过期，关闭: %s", server)
			conn.Close()
			delete(p.conns, server)
		}
	}

	// 创建新连接
	serverAddr := strings.TrimPrefix(server, "tls://")

	// 创建TCP连接
	log.Printf("[DoT连接池] 开始连接TCP: %s", serverAddr)
	tcpConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)  // 增加TCP连接超时
	if err != nil {
		log.Printf("[DoT连接池] TCP连接失败: %s, 错误: %v", serverAddr, err)
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}
	log.Printf("[DoT连接池] TCP连接成功: %s", serverAddr)

	// 创建TLS连接
	tlsConfig := &tls.Config{
		ServerName:         strings.Split(serverAddr, ":")[0],
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}
	
	// 设置TCP保活
	if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetLinger(0) // 立即关闭
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)

	// 设置TLS握手超时
	handshakeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)  // 增加TLS握手超时
	defer cancel()

	log.Printf("[DoT连接池] 开始TLS握手: %s", serverAddr)
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		log.Printf("[DoT连接池] TLS握手失败: %s, 错误: %v", serverAddr, err)
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	log.Printf("[DoT连接池] TLS握手成功: %s", serverAddr)

	// 检查连接池大小，如果超过限制则清理旧连接
	if len(p.conns) >= p.maxConns {
		p.cleanupOldConnections()
	}

	// 创建新的连接对象
	conn := &DoTConn{
		conn:     tcpConn,
		tlsConn:  tlsConn,
		lastUsed: time.Now(),
		inUse:    true,
		server:   server,
	}

	p.conns[server] = conn
	return conn, nil
}

// cleanupOldConnections 清理旧连接
func (p *DoTConnPool) cleanupOldConnections() {
	var oldestConn *DoTConn
	var oldestTime time.Time
	
	for _, conn := range p.conns {
		if oldestConn == nil || conn.lastUsed.Before(oldestTime) {
			oldestConn = conn
			oldestTime = conn.lastUsed
		}
	}
	
	if oldestConn != nil {
		log.Printf("[DoT连接池] 清理最旧连接: %s", oldestConn.server)
		oldestConn.Close()
		delete(p.conns, oldestConn.server)
	}
}

// PutConn 归还DoT连接
func (p *DoTConnPool) PutConn(conn *DoTConn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	conn.inUse = false
	conn.lastUsed = time.Now()
}



// Close 关闭连接池中的所有连接
func (p *DoTConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = make(map[string]*DoTConn)
}

// Close 关闭单个DoT连接
func (c *DoTConn) Close() {
	if c.tlsConn != nil {
		c.tlsConn.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// ===== DoH 连接池实现 =====

// DoHConnPool DoH连接池
type DoHConnPool struct {
	mu         sync.RWMutex
	clients    map[string]*http.Client
	maxClients int
	timeout    time.Duration
}

// NewDoHConnPool 创建新的DoH连接池
func NewDoHConnPool() *DoHConnPool {
	return &DoHConnPool{
		clients:    make(map[string]*http.Client),
		maxClients: 10, // 每个服务器最多10个客户端
		timeout:    30 * time.Second,
	}
}

// GetClient 获取DoH客户端
func (p *DoHConnPool) GetClient(server string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if client, ok := p.clients[server]; ok {
		return client
	}

	// 检查连接池大小，如果超过限制则清理旧客户端
	if len(p.clients) >= p.maxClients {
		p.cleanupOldClients()
	}

	// 创建新的HTTP客户端，启用连接复用
	client := &http.Client{
		Timeout: p.timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableCompression:  true,
		},
	}

	p.clients[server] = client
	return client
}

// cleanupOldClients 清理旧客户端
func (p *DoHConnPool) cleanupOldClients() {
	// 简单策略：随机选择一个客户端移除
	var oldestServer string
	for server := range p.clients {
		oldestServer = server
		break
	}
	if oldestServer != "" {
		log.Printf("[DoH连接池] 清理旧客户端: %s", oldestServer)
		delete(p.clients, oldestServer)
	}
}

// Close 关闭连接池中的所有客户端
func (p *DoHConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, client := range p.clients {
		client.CloseIdleConnections()
	}
	p.clients = make(map[string]*http.Client)
} 