package dns

import (
	"crypto/tls"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DoH3ConnPool DoH3 连接池
type DoH3ConnPool struct {
	mu               sync.RWMutex
	clients          map[string][]*http.Client
	maxClients       int
	timeout          time.Duration
	clientsPerServer int

	metrics struct {
		TotalClientsCreated int64
		TotalClientsClosed  int64
		TotalClientsUsed    int64
		ActiveClients       int64
	}
}

// NewDoH3ConnPool 创建新的 DoH3 连接池
func NewDoH3ConnPool() *DoH3ConnPool {
	pool := &DoH3ConnPool{
		clients:          make(map[string][]*http.Client),
		maxClients:       20,
		timeout:          90 * time.Second,
		clientsPerServer: 3,
	}
	go pool.healthCheckRoutine()
	return pool
}

// GetClient 获取 DoH3 客户端
func (p *DoH3ConnPool) GetClient(server string) *http.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	if clientList, ok := p.clients[server]; ok && len(clientList) > 0 {
		client := clientList[len(clientList)-1]
		clientList = append([]*http.Client{client}, clientList[:len(clientList)-1]...)
		p.clients[server] = clientList
		p.metrics.TotalClientsUsed++
		p.metrics.ActiveClients++
		return client
	}

	if clientList, ok := p.clients[server]; ok && len(clientList) >= p.clientsPerServer {
		if tr, ok := clientList[0].Transport.(*http3.Transport); ok {
			_ = tr.Close()
		}
		clientList = clientList[1:]
		p.clients[server] = clientList
		p.metrics.TotalClientsClosed++
		if p.metrics.ActiveClients > 0 {
			p.metrics.ActiveClients--
		}
	}

	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	if totalClients >= p.maxClients {
		p.cleanupOldClients()
	}

	client := &http.Client{
		Timeout: p.timeout,
		Transport: &http3.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
			QUICConfig: &quic.Config{
				MaxIdleTimeout:  3 * time.Minute,
				KeepAlivePeriod: 30 * time.Second,
			},
			DisableCompression: true,
		},
	}

	if _, ok := p.clients[server]; !ok {
		p.clients[server] = []*http.Client{}
	}
	p.clients[server] = append(p.clients[server], client)
	p.metrics.TotalClientsCreated++
	p.metrics.ActiveClients++
	return client
}

// cleanupOldClients 清理旧客户端
func (p *DoH3ConnPool) cleanupOldClients() {
	var maxServer string
	maxClients := 0
	for server, clientList := range p.clients {
		if len(clientList) > maxClients {
			maxServer = server
			maxClients = len(clientList)
		}
	}
	if maxServer == "" {
		return
	}
	clientList := p.clients[maxServer]
	if len(clientList) > 0 {
		if tr, ok := clientList[0].Transport.(*http3.Transport); ok {
			_ = tr.Close()
		}
		clientList = clientList[1:]
		log.Printf("[DoH3连接池] 清理旧客户端: %s", maxServer)
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

// Close 关闭连接池
func (p *DoH3ConnPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, clientList := range p.clients {
		for _, client := range clientList {
			if tr, ok := client.Transport.(*http3.Transport); ok {
				_ = tr.Close()
			}
		}
	}
	p.clients = make(map[string][]*http.Client)
}

// healthCheckRoutine 健康检查
func (p *DoH3ConnPool) healthCheckRoutine() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		p.mu.Lock()
		for server, clientList := range p.clients {
			for i := len(clientList) - 1; i >= 0; i-- {
				client := clientList[i]
				client.CloseIdleConnections()
				_ = i
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

// GetMetrics 获取指标
func (p *DoH3ConnPool) GetMetrics() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	totalClients := 0
	for _, clientList := range p.clients {
		totalClients += len(clientList)
	}
	return map[string]interface{}{
		"total_clients":      totalClients,
		"active_clients":     p.metrics.ActiveClients,
		"total_created":      p.metrics.TotalClientsCreated,
		"total_closed":       p.metrics.TotalClientsClosed,
		"total_used":         p.metrics.TotalClientsUsed,
		"max_clients":        p.maxClients,
		"client_timeout":     p.timeout.String(),
		"clients_per_server": p.clientsPerServer,
		"servers_count":      len(p.clients),
	}
}
