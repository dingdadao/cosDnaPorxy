package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 复现线上 panic：UDP/TCP 客户端池里堆积 3 条过期空闲连接时，
// 旧实现「边 range 边删元素」会在第 3 次删除时越界
// （runtime error: slice bounds out of range [3:1]）
func TestConnPoolGetClientPrunesStaleWithoutPanic(t *testing.T) {
	const addr = "211.142.211.124:53"
	stale := time.Now().Add(-2 * time.Minute)

	t.Run("UDP", func(t *testing.T) {
		p := &UDPConnPool{clients: map[string][]*UDPClientInfo{}, maxConns: 50, timeout: time.Minute}
		for i := 0; i < 3; i++ {
			p.clients[addr] = append(p.clients[addr], &UDPClientInfo{
				client: &dns.Client{Net: "udp"}, lastUsed: stale, inUse: false, addr: addr,
			})
		}

		if c := p.GetClient(addr, time.Second); c == nil {
			t.Fatal("应返回一个可用客户端")
		}
		if got := len(p.clients[addr]); got != 1 {
			t.Errorf("3 条过期连接应被清理，仅剩新建的 1 条，实际 %d 条", got)
		}
	})

	t.Run("TCP", func(t *testing.T) {
		p := &TCPConnPool{clients: map[string][]*TCPClientInfo{}, maxConns: 50, timeout: time.Minute}
		for i := 0; i < 3; i++ {
			p.clients[addr] = append(p.clients[addr], &TCPClientInfo{
				client: &dns.Client{Net: "tcp"}, lastUsed: stale, inUse: false, addr: addr,
			})
		}

		if c := p.GetClient(addr, time.Second); c == nil {
			t.Fatal("应返回一个可用客户端")
		}
		if got := len(p.clients[addr]); got != 1 {
			t.Errorf("3 条过期连接应被清理，仅剩新建的 1 条，实际 %d 条", got)
		}
	})
}

// 未过期且空闲的客户端仍应被复用，且不触发清理
func TestConnPoolGetClientReusesFreshClient(t *testing.T) {
	const addr = "211.142.211.124:53"
	p := &UDPConnPool{clients: map[string][]*UDPClientInfo{}, maxConns: 50, timeout: time.Minute}
	fresh := &UDPClientInfo{client: &dns.Client{Net: "udp"}, lastUsed: time.Now(), inUse: false, addr: addr}
	p.clients[addr] = []*UDPClientInfo{fresh}

	if c := p.GetClient(addr, time.Second); c != fresh.client {
		t.Error("未过期的空闲客户端应被复用")
	}
	if !fresh.inUse {
		t.Error("复用后应标记为使用中")
	}
	if got := len(p.clients[addr]); got != 1 {
		t.Errorf("不应新增或删除客户端，实际 %d 条", got)
	}
}
