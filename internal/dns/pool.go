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

	"github.com/miekg/dns"
)

// ===== DoT 连接池实现 =====

// DoTConnPool DoT连接池
type DoTConnPool struct {
	mu       sync.RWMutex
	conns    map[string][]*DoTConn
	maxConns int
	timeout  time.Duration
	
	// 监控指标
	metrics struct {
		TotalConnsCreated int64
		TotalConnsClosed  int64
		TotalConnsReused  int64
		ActiveConns       int64
	}
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
	pool := &DoTConnPool{
		conns:    make(map[string][]*DoTConn),
		maxConns: 20,               // 增加每个服务器的最大连接数到20
		timeout:  90 * time.Second, // 增加连接超时时间到90秒
	}
	
	// 启动健康检查协程
	go pool.healthCheckRoutine()
	
	return pool
}

// GetConn 获取DoT连接
func (p *DoTConnPool) GetConn(ctx context.Context, server string) (*DoTConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有连接
	if connList, ok := p.conns[server]; ok {
		// 遍历连接列表，寻找可用连接
		for i, conn := range connList {
			if !conn.inUse {
				// 检查连接是否还有效
				if time.Since(conn.lastUsed) < p.timeout {
					conn.inUse = true
					conn.lastUsed = time.Now()
					p.metrics.TotalConnsReused++
					p.metrics.ActiveConns++
					log.Printf("[DoT连接池] 复用现有连接: %s", server)
					return conn, nil
				} else {
					// 连接过期，关闭并移除
					log.Printf("[DoT连接池] 连接已过期，关闭: %s", server)
					conn.Close()
					p.metrics.TotalConnsClosed++
					p.metrics.ActiveConns--
					// 从列表中移除过期连接
					connList = append(connList[:i], connList[i+1:]...)
					p.conns[server] = connList
				}
			}
		}
	}

	// 创建新连接
	serverAddr := strings.TrimPrefix(server, "tls://")

	// 创建TCP连接
	log.Printf("[DoT连接池] 开始连接TCP: %s", serverAddr)
	tcpConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second) // 增加TCP连接超时
	if err != nil {
		log.Printf("[DoT连接池] TCP连接失败: %s, 错误: %v", serverAddr, err)
		return nil, fmt.Errorf("failed to dial TCP: %w", err)
	}
	log.Printf("[DoT连接池] TCP连接成功: %s", serverAddr)

	// 设置TCP保活
	if tcpConn, ok := tcpConn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(30 * time.Second)
		tcpConn.SetLinger(0) // 立即关闭
	}

	// 创建TLS连接
	tlsConfig := &tls.Config{
		ServerName:         strings.Split(serverAddr, ":")[0],
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	tlsConn := tls.Client(tcpConn, tlsConfig)

	// 设置TLS握手超时
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second) // 增加TLS握手超时到10秒
	defer cancel()

	log.Printf("[DoT连接池] 开始TLS握手: %s", serverAddr)
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		log.Printf("[DoT连接池] TLS握手失败: %s, 错误: %v", serverAddr, err)
		tcpConn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	log.Printf("[DoT连接池] TLS握手成功: %s", serverAddr)

	// 检查服务器连接数，如果超过限制则清理旧连接
	if connList, ok := p.conns[server]; ok && len(connList) >= 5 { // 每个服务器最多5个连接
		// 清理最旧的连接
		oldestIdx := 0
		oldestTime := connList[0].lastUsed
		for i, conn := range connList {
			if conn.lastUsed.Before(oldestTime) {
				oldestIdx = i
				oldestTime = conn.lastUsed
			}
		}
		log.Printf("[DoT连接池] 服务器连接数达到上限，清理最旧连接: %s", server)
		connList[oldestIdx].Close()
		connList = append(connList[:oldestIdx], connList[oldestIdx+1:]...)
		p.conns[server] = connList
	}

	// 检查总连接池大小，如果超过限制则清理旧连接
	totalConns := 0
	for _, connList := range p.conns {
		totalConns += len(connList)
	}
	if totalConns >= p.maxConns {
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

	// 添加到连接列表
	if _, ok := p.conns[server]; !ok {
		p.conns[server] = []*DoTConn{}
	}
	p.conns[server] = append(p.conns[server], conn)
	p.metrics.TotalConnsCreated++
	p.metrics.ActiveConns++
	return conn, nil
}

// cleanupOldConnections 清理旧连接
func (p *DoTConnPool) cleanupOldConnections() {
	var oldestConn *DoTConn
	var oldestServer string
	var oldestIdx int
	var oldestTime time.Time

	for server, connList := range p.conns {
		for i, conn := range connList {
			if oldestConn == nil || conn.lastUsed.Before(oldestTime) {
				oldestConn = conn
				oldestServer = server
				oldestIdx = i
				oldestTime = conn.lastUsed
			}
		}
	}

	if oldestConn != nil {
		log.Printf("[DoT连接池] 清理最旧连接: %s", oldestConn.server)
		oldestConn.Close()
		p.metrics.TotalConnsClosed++
		if p.metrics.ActiveConns > 0 {
			p.metrics.ActiveConns--
		}
		// 从连接列表中移除
		connList := p.conns[oldestServer]
		connList = append(connList[:oldestIdx], connList[oldestIdx+1:]...)
		if len(connList) == 0 {
			delete(p.conns, oldestServer)
		} else {
			p.conns[oldestServer] = connList
		}
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
	if p.metrics.ActiveConns > 0 {
		p.metrics.ActiveConns--
	}
}

// Close 关闭连接池中的所有连接
func (p *DoTConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, connList := range p.conns {
		for _, conn := range connList {
			conn.Close()
		}
	}
	p.conns = make(map[string][]*DoTConn)
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

// healthCheckRoutine 健康检查协程
func (p *DoTConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for server, connList := range p.conns {
			for i := len(connList) - 1; i >= 0; i-- {
				conn := connList[i]
				// 只检查空闲连接
				if !conn.inUse {
					// 检查连接是否过期
					if time.Since(conn.lastUsed) > p.timeout {
						log.Printf("[DoT连接池] 健康检查：连接已过期，关闭: %s", server)
						conn.Close()
						p.metrics.TotalConnsClosed++
						if p.metrics.ActiveConns > 0 {
							p.metrics.ActiveConns--
						}
						// 从列表中移除
						connList = append(connList[:i], connList[i+1:]...)
					} else {
						// 尝试发送一个简单的DNS查询来检查连接是否健康
						_, cancel := context.WithTimeout(context.Background(), 2*time.Second)
						defer cancel()
						
						// 创建一个简单的DNS查询
						req := new(dns.Msg)
						req.SetQuestion("healthcheck.local.", dns.TypeA)
						req.RecursionDesired = true
						
						// 使用连接发送查询
						dnsConn := &dns.Conn{Conn: conn.tlsConn}
						err := dnsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
						if err != nil {
							log.Printf("[DoT连接池] 健康检查：设置超时失败: %v", err)
							conn.Close()
							p.metrics.TotalConnsClosed++
							if p.metrics.ActiveConns > 0 {
								p.metrics.ActiveConns--
							}
							connList = append(connList[:i], connList[i+1:]...)
							continue
						}
						
						err = dnsConn.WriteMsg(req)
						if err != nil {
							log.Printf("[DoT连接池] 健康检查：写入失败: %v, 关闭连接: %s", err, server)
							conn.Close()
							p.metrics.TotalConnsClosed++
							if p.metrics.ActiveConns > 0 {
								p.metrics.ActiveConns--
							}
							connList = append(connList[:i], connList[i+1:]...)
							continue
						}
						
						// 不等待响应，只是检查写入是否成功
					}
				}
			}
			if len(connList) == 0 {
				delete(p.conns, server)
			} else {
				p.conns[server] = connList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *DoTConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// 计算当前连接数
	totalConns := 0
	for _, connList := range p.conns {
		totalConns += len(connList)
	}
	
	return map[string]interface{}{
		"total_connections":    totalConns,
		"active_connections":   p.metrics.ActiveConns,
		"total_created":        p.metrics.TotalConnsCreated,
		"total_closed":         p.metrics.TotalConnsClosed,
		"total_reused":         p.metrics.TotalConnsReused,
		"max_connections":      p.maxConns,
		"connection_timeout":   p.timeout.String(),
		"servers_count":        len(p.conns),
	}
}

// ===== UDP/TCP 连接池实现 =====

// UDPConnPool UDP连接池
type UDPConnPool struct {
	mu       sync.RWMutex
	clients  map[string][]*UDPClientInfo
	maxConns int
	timeout  time.Duration
	
	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsReused  int64
		ActiveClients       int64
	}
}

// UDPClientInfo 包含DNS客户端和相关信息
type UDPClientInfo struct {
	client   *dns.Client
	lastUsed time.Time
	inUse    bool
	addr     string
}

// NewUDPConnPool 创建新的UDP连接池
func NewUDPConnPool() *UDPConnPool {
	pool := &UDPConnPool{
		clients:  make(map[string][]*UDPClientInfo),
		maxConns: 50,               // 限制最大连接数
		timeout:  60 * time.Second, // 连接超时时间
	}
	
	// 启动健康检查协程
	go pool.healthCheckRoutine()
	
	return pool
}

// GetClient 获取UDP客户端
func (p *UDPConnPool) GetClient(addr string, timeout time.Duration) *dns.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[addr]; ok {
		// 遍历客户端列表，寻找可用客户端
		for i, clientInfo := range clientList {
			if !clientInfo.inUse {
				// 检查连接是否还有效
				if time.Since(clientInfo.lastUsed) < p.timeout {
					clientInfo.inUse = true
					clientInfo.lastUsed = time.Now()
					p.metrics.TotalClientsReused++
					p.metrics.ActiveClients++
					return clientInfo.client
				} else {
					// 连接过期，删除
					clientList = append(clientList[:i], clientList[i+1:]...)
					p.clients[addr] = clientList
					p.metrics.TotalClientsClosed++
					if p.metrics.ActiveClients > 0 {
						p.metrics.ActiveClients--
					}
				}
			}
		}
	}

	// 创建新客户端
	client := &dns.Client{
		Net:            "udp",
		Timeout:        timeout,
		DialTimeout:    timeout,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		SingleInflight: true, // 对于相同的查询只允许一次飞行中的请求
	}

	clientInfo := &UDPClientInfo{
		client:   client,
		lastUsed: time.Now(),
		inUse:    true,
		addr:     addr,
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[addr]; ok && len(clientList) >= 10 { // 每个服务器最多10个客户端
		// 清理最旧的客户端
		oldestIdx := 0
		oldestTime := clientList[0].lastUsed
		for i, clientInfo := range clientList {
			if clientInfo.lastUsed.Before(oldestTime) {
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.clients[addr] = clientList
	}

	// 检查总连接池大小，如果超过限制则清理旧连接
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxConns {
		p.cleanupOldConnections()
	}

	// 添加到客户端列表
	if _, ok := p.clients[addr]; !ok {
		p.clients[addr] = []*UDPClientInfo{}
	}
	p.clients[addr] = append(p.clients[addr], clientInfo)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// PutClient 归还UDP客户端
func (p *UDPConnPool) PutClient(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if clientList, ok := p.clients[addr]; ok {
		// 找到第一个使用中的客户端并归还
		for _, clientInfo := range clientList {
			if clientInfo.inUse {
				clientInfo.inUse = false
				clientInfo.lastUsed = time.Now()
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				break
			}
		}
	}
}

// cleanupOldConnections 清理旧连接
func (p *UDPConnPool) cleanupOldConnections() {
	var oldestAddr string
	var oldestIdx int
	var oldestTime time.Time

	for addr, clientList := range p.clients {
		for i, clientInfo := range clientList {
			if oldestAddr == "" || clientInfo.lastUsed.Before(oldestTime) {
				oldestAddr = addr
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
	}

	if oldestAddr != "" {
		clientList := p.clients[oldestAddr]
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
		if len(clientList) == 0 {
			delete(p.clients, oldestAddr)
		} else {
			p.clients[oldestAddr] = clientList
		}
	}
}

// Close 关闭连接池中的所有连接
func (p *UDPConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients = make(map[string][]*UDPClientInfo)
}

// healthCheckRoutine 健康检查协程
func (p *UDPConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for addr, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				clientInfo := clientList[i]
				// 只检查空闲客户端
				if !clientInfo.inUse {
					// 检查客户端是否过期
					if time.Since(clientInfo.lastUsed) > p.timeout {
						log.Printf("[UDP连接池] 健康检查：客户端已过期，删除: %s", addr)
						// 从列表中移除
						clientList = append(clientList[:i], clientList[i+1:]...)
						p.metrics.TotalClientsClosed++
						if p.metrics.ActiveClients > 0 {
							p.metrics.ActiveClients--
						}
					}
				}
			}
			if len(clientList) == 0 {
				delete(p.clients, addr)
			} else {
				p.clients[addr] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *UDPConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	
	return map[string]interface{}{
		"total_clients":     totalClients,
		"active_clients":    p.metrics.ActiveClients,
		"total_created":     p.metrics.TotalClientsCreated,
		"total_closed":      p.metrics.TotalClientsClosed,
		"total_reused":      p.metrics.TotalClientsReused,
		"max_clients":       p.maxConns,
		"client_timeout":    p.timeout.String(),
		"servers_count":     len(p.clients),
	}
}

// ===== TCP 连接池实现 =====

// TCPConnPool TCP连接池
type TCPConnPool struct {
	mu       sync.RWMutex
	clients  map[string][]*TCPClientInfo
	maxConns int
	timeout  time.Duration
	
	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsReused  int64
		ActiveClients       int64
	}
}

// NewTCPConnPool 创建新的TCP连接池
func NewTCPConnPool() *TCPConnPool {
	pool := &TCPConnPool{
		clients:  make(map[string][]*TCPClientInfo),
		maxConns: 50,               // 限制最大连接数
		timeout:  60 * time.Second, // 连接超时时间
	}
	
	// 启动健康检查协程
	go pool.healthCheckRoutine()
	
	return pool
}

// TCPClientInfo 包含TCP DNS客户端和相关信息
type TCPClientInfo struct {
	client   *dns.Client
	lastUsed time.Time
	inUse    bool
	addr     string
}

// GetClient 获取TCP客户端
func (p *TCPConnPool) GetClient(addr string, timeout time.Duration) *dns.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[addr]; ok {
		// 遍历客户端列表，寻找可用客户端
		for i, clientInfo := range clientList {
			if !clientInfo.inUse {
				// 检查连接是否还有效
				if time.Since(clientInfo.lastUsed) < p.timeout {
					clientInfo.inUse = true
					clientInfo.lastUsed = time.Now()
					p.metrics.TotalClientsReused++
					p.metrics.ActiveClients++
					return clientInfo.client
				} else {
					// 连接过期，删除
					clientList = append(clientList[:i], clientList[i+1:]...)
					p.clients[addr] = clientList
					p.metrics.TotalClientsClosed++
					if p.metrics.ActiveClients > 0 {
						p.metrics.ActiveClients--
					}
				}
			}
		}
	}

	// 创建新客户端
	client := &dns.Client{
		Net:            "tcp",
		Timeout:        timeout,
		DialTimeout:    timeout,
		ReadTimeout:    timeout,
		WriteTimeout:   timeout,
		SingleInflight: true, // 对于相同的查询只允许一次飞行中的请求
	}

	clientInfo := &TCPClientInfo{
		client:   client,
		lastUsed: time.Now(),
		inUse:    true,
		addr:     addr,
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[addr]; ok && len(clientList) >= 10 { // 每个服务器最多10个客户端
		// 清理最旧的客户端
		oldestIdx := 0
		oldestTime := clientList[0].lastUsed
		for i, clientInfo := range clientList {
			if clientInfo.lastUsed.Before(oldestTime) {
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.clients[addr] = clientList
	}

	// 检查总连接池大小，如果超过限制则清理旧连接
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxConns {
		p.cleanupOldConnections()
	}

	// 添加到客户端列表
	if _, ok := p.clients[addr]; !ok {
		p.clients[addr] = []*TCPClientInfo{}
	}
	p.clients[addr] = append(p.clients[addr], clientInfo)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// PutClient 归还TCP客户端
func (p *TCPConnPool) PutClient(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if clientList, ok := p.clients[addr]; ok {
		// 找到第一个使用中的客户端并归还
		for _, clientInfo := range clientList {
			if clientInfo.inUse {
				clientInfo.inUse = false
				clientInfo.lastUsed = time.Now()
				if p.metrics.ActiveClients > 0 {
					p.metrics.ActiveClients--
				}
				break
			}
		}
	}
}

// cleanupOldConnections 清理旧连接
func (p *TCPConnPool) cleanupOldConnections() {
	var oldestAddr string
	var oldestIdx int
	var oldestTime time.Time

	for addr, clientList := range p.clients {
		for i, clientInfo := range clientList {
			if oldestAddr == "" || clientInfo.lastUsed.Before(oldestTime) {
				oldestAddr = addr
				oldestIdx = i
				oldestTime = clientInfo.lastUsed
			}
		}
	}

	if oldestAddr != "" {
		clientList := p.clients[oldestAddr]
		clientList = append(clientList[:oldestIdx], clientList[oldestIdx+1:]...)
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
		if len(clientList) == 0 {
			delete(p.clients, oldestAddr)
		} else {
			p.clients[oldestAddr] = clientList
		}
	}
}

// Close 关闭连接池中的所有连接
func (p *TCPConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.clients = make(map[string][]*TCPClientInfo)
}

// healthCheckRoutine 健康检查协程
func (p *TCPConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for addr, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				clientInfo := clientList[i]
				// 只检查空闲客户端
				if !clientInfo.inUse {
					// 检查客户端是否过期
					if time.Since(clientInfo.lastUsed) > p.timeout {
						log.Printf("[TCP连接池] 健康检查：客户端已过期，删除: %s", addr)
						// 从列表中移除
						clientList = append(clientList[:i], clientList[i+1:]...)
						p.metrics.TotalClientsClosed++
						if p.metrics.ActiveClients > 0 {
							p.metrics.ActiveClients--
						}
					}
				}
			}
			if len(clientList) == 0 {
				delete(p.clients, addr)
			} else {
				p.clients[addr] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *TCPConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	
	return map[string]interface{}{
		"total_clients":     totalClients,
		"active_clients":    p.metrics.ActiveClients,
		"total_created":     p.metrics.TotalClientsCreated,
		"total_closed":      p.metrics.TotalClientsClosed,
		"total_reused":      p.metrics.TotalClientsReused,
		"max_clients":       p.maxConns,
		"client_timeout":    p.timeout.String(),
		"servers_count":     len(p.clients),
	}
}

// ===== DoH 连接池实现 =====

// DoHConnPool DoH连接池
type DoHConnPool struct {
	mu         sync.RWMutex
	clients    map[string][]*http.Client
	maxClients int
	timeout    time.Duration
	clientsPerServer int
	
	// 监控指标
	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsUsed   int64
		ActiveClients       int64
	}
}

// NewDoHConnPool 创建新的DoH连接池
func NewDoHConnPool() *DoHConnPool {
	pool := &DoHConnPool{
		clients:    make(map[string][]*http.Client),
		maxClients: 50,               // 总客户端数上限
		timeout:    90 * time.Second, // 增加超时时间到90秒
		clientsPerServer: 5,          // 每个服务器最多5个客户端
	}
	
	// 启动健康检查协程
	go pool.healthCheckRoutine()
	
	return pool
}

// GetClient 获取DoH客户端
func (p *DoHConnPool) GetClient(server string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 检查现有客户端
	if clientList, ok := p.clients[server]; ok && len(clientList) > 0 {
		// 简单轮询选择客户端
		client := clientList[len(clientList)-1]
		// 将选中的客户端移到列表开头，实现简单的轮询
		clientList = append([]*http.Client{client}, clientList[:len(clientList)-1]...)
		p.clients[server] = clientList
		p.metrics.TotalClientsUsed++
		p.metrics.ActiveClients++
		return client
	}

	// 检查服务器客户端数，如果超过限制则清理旧客户端
	if clientList, ok := p.clients[server]; ok && len(clientList) >= p.clientsPerServer {
		// 清理最旧的客户端
		clientList[0].CloseIdleConnections()
		clientList = clientList[1:]
		p.clients[server] = clientList
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
	}

	// 检查总连接池大小，如果超过限制则清理旧客户端
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxClients {
		p.cleanupOldClients()
	}

	// 创建新的HTTP客户端，启用连接复用
	client := &http.Client{
		Timeout: p.timeout,
		Transport: &http.Transport{
			MaxIdleConns:        200,              // 增加最大空闲连接数
			MaxIdleConnsPerHost: 20,               // 增加每个主机的最大空闲连接数
			IdleConnTimeout:     90 * time.Second, // 增加空闲连接超时时间
			TLSHandshakeTimeout: 10 * time.Second, // 增加TLS握手超时
			DisableCompression:  true,
		},
	}

	// 添加到客户端列表
	if _, ok := p.clients[server]; !ok {
		p.clients[server] = []*http.Client{}
	}
	p.clients[server] = append(p.clients[server], client)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// cleanupOldClients 清理旧客户端
func (p *DoHConnPool) cleanupOldClients() {
	// 简单策略：找到客户端数最多的服务器，清理一个客户端
	var maxServer string
	maxClients := 0

	for server, clientList := range p.clients {
		if len(clientList) > maxClients {
			maxServer = server
			maxClients = len(clientList)
		}
	}

	if maxServer != "" {
		clientList := p.clients[maxServer]
		if len(clientList) > 0 {
			// 清理最旧的客户端
			clientList[0].CloseIdleConnections()
			clientList = clientList[1:]
			log.Printf("[DoH连接池] 清理旧客户端: %s", maxServer)
			p.metrics.TotalClientsClosed++
			if p.metrics.ActiveClients > 0 {
				p.metrics.ActiveClients--
			}
			if len(clientList) == 0 {
				delete(p.clients, maxServer)
			} else {
				p.clients[maxServer] = clientList
			}
		}
	}
}

// Close 关闭连接池中的所有客户端
func (p *DoHConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, clientList := range p.clients {
		for _, client := range clientList {
			client.CloseIdleConnections()
		}
	}
	p.clients = make(map[string][]*http.Client)
}

// healthCheckRoutine 健康检查协程
func (p *DoHConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		for server, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				client := clientList[i]
				// 关闭空闲连接，保持连接池健康
				client.CloseIdleConnections()
				// 这里可以添加更复杂的健康检查逻辑
				// 例如，发送一个简单的HTTP请求来检查连接是否有效
			}
			if len(clientList) == 0 {
				delete(p.clients, server)
			} else {
				p.clients[server] = clientList
			}
		}
		p.mu.Unlock()
	}
}

// GetMetrics 获取连接池指标
func (p *DoHConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	// 计算当前客户端数
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	
	return map[string]interface{}{
		"total_clients":     totalClients,
		"active_clients":    p.metrics.ActiveClients,
		"total_created":     p.metrics.TotalClientsCreated,
		"total_closed":      p.metrics.TotalClientsClosed,
		"total_used":        p.metrics.TotalClientsUsed,
		"max_clients":       p.maxClients,
		"client_timeout":    p.timeout.String(),
		"clients_per_server": p.clientsPerServer,
		"servers_count":     len(p.clients),
	}
}
