package dns

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// newSyntheticConn 构造一条"池中空闲连接"：底层用 net.Pipe，便于观察它是否被池关闭。
// tlsConn 留空——本组测试只验证连接池的复用/淘汰决策，不做真实 TLS I/O。
func newSyntheticConn(server string, lastUsed, created time.Time) (*DoTConn, net.Conn) {
	client, peer := net.Pipe()
	return &DoTConn{
		conn:     client,
		lastUsed: lastUsed,
		created:  created,
		inUse:    false,
		server:   server,
	}, peer
}

// newTestDoTPool 构造不启动健康检查协程、可直接设定空闲阈值的连接池。
func newTestDoTPool(timeout time.Duration) *DoTConnPool {
	return &DoTConnPool{
		conns:    make(map[string][]*DoTConn),
		maxConns: 20,
		timeout:  timeout,
	}
}

// 池空闲阈值必须小于上游空闲断连阈值：实测阿里 DoT 空闲约 5s 即 EOF 断开，
// 若阈值不小于它，池就会把已被断开的死连接当成可复用，导致查询失败与频繁重连。
func TestDoTConnPoolIdleTimeoutBelowUpstreamCutoff(t *testing.T) {
	pool := NewDoTConnPool()
	t.Cleanup(pool.Close)

	if pool.timeout >= 5*time.Second {
		t.Errorf("池空闲阈值 %v 必须小于阿里 DoT 实测约 5s 的空闲断连阈值", pool.timeout)
	}
}

// 空闲时间在阈值内的连接应被复用（不新建），且不触发拨号。
func TestDoTConnPoolReusesLiveConn(t *testing.T) {
	const server = "tls://127.0.0.1:1"
	pool := newTestDoTPool(time.Minute)
	t.Cleanup(pool.Close)

	c, _ := newSyntheticConn(server, time.Now(), time.Now())
	pool.conns[server] = []*DoTConn{c}

	got, err := pool.GetConn(context.Background(), server)
	if err != nil {
		t.Fatalf("未过期的空闲连接应被直接复用，不应拨号: %v", err)
	}
	if got != c {
		t.Errorf("应返回池中那条空闲连接")
	}
	if pool.metrics.TotalConnsReused != 1 {
		t.Errorf("应计入一次复用，实际 %d", pool.metrics.TotalConnsReused)
	}
}

// 空闲时间超过阈值的连接不得复用：应从池中关闭移除，并按新建处理。
func TestDoTConnPoolSkipsExpiredConn(t *testing.T) {
	const server = "tls://127.0.0.1:1" // 端口 1 必然拒绝连接，用于确认走到了"新建"分支
	pool := newTestDoTPool(50 * time.Millisecond)
	t.Cleanup(pool.Close)

	old := time.Now().Add(-time.Minute)
	c, peer := newSyntheticConn(server, old, old)
	pool.conns[server] = []*DoTConn{c}

	if _, err := pool.GetConn(context.Background(), server); err == nil {
		t.Fatalf("过期连接不应被复用，应走新建拨号分支（此处拨号应失败）")
	}
	if pool.metrics.TotalConnsReused != 0 {
		t.Errorf("过期连接不应计入复用，实际 %d", pool.metrics.TotalConnsReused)
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Errorf("过期的空闲连接应已从池中关闭")
	}
}

// 回归：复用连接失败后的重试必须走 GetFreshConn 强制新建，
// 不得复用池中其它空闲连接——否则会再次复用死连接而重复失败。
func TestDoTConnPoolGetFreshConnBypassesReuse(t *testing.T) {
	const server = "tls://127.0.0.1:1"
	pool := newTestDoTPool(time.Minute)
	t.Cleanup(pool.Close)

	c, _ := newSyntheticConn(server, time.Now(), time.Now())
	pool.conns[server] = []*DoTConn{c}

	// GetFreshConn 跳过复用 → 直接拨号 → 连接被拒 → 失败；期间不得产生复用。
	if _, err := pool.GetFreshConn(context.Background(), server); err == nil {
		t.Fatalf("GetFreshConn 应绕过复用并尝试新建（此处拨号应失败）")
	}
	if pool.metrics.TotalConnsReused != 0 {
		t.Errorf("GetFreshConn 不应复用池中连接，实际复用 %d 次", pool.metrics.TotalConnsReused)
	}

	// 对照：同一时刻 GetConn 仍应复用那条空闲连接，证明两者行为确实不同。
	got, err := pool.GetConn(context.Background(), server)
	if err != nil || got != c {
		t.Errorf("GetConn 应复用池中空闲连接，实际 err=%v got_same=%v", err, got == c)
	}
}

// peerClosed 通过 net.Pipe 对端是否读到 io.EOF 判断连接是否已被池关闭。
// 未关闭的连接在无数据时会阻塞到读超时（返回超时错误而非 io.EOF）。
func peerClosed(peer net.Conn) bool {
	_ = peer.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := peer.Read(make([]byte, 1))
	return err == io.EOF
}

// 回归：达到单上游空闲连接上限时，只能裁剪「空闲」连接，
// 绝不能关闭「在用」连接——旧实现会按 lastUsed 关闭最旧连接而误杀在途查询，
// 导致该查询失败并触发重试风暴。
func TestDoTConnPoolTrimKeepsInUseConns(t *testing.T) {
	const server = "tls://127.0.0.1:1"
	pool := newTestDoTPool(time.Minute)
	t.Cleanup(pool.Close)

	// 预置 maxDoTConnsPerServer+1 条空闲连接，构造出「超上限 1 条」的场景
	var idlePeers []net.Conn
	for i := 0; i < maxDoTConnsPerServer+1; i++ {
		c, peer := newSyntheticConn(server, time.Now(), time.Now())
		pool.conns[server] = append(pool.conns[server], c)
		idlePeers = append(idlePeers, peer)
	}

	// 一条正在被查询使用的连接
	inUse, inUsePeer := newSyntheticConn(server, time.Now(), time.Now())
	inUse.inUse = true
	pool.conns[server] = append(pool.conns[server], inUse)

	// 模拟 getConn 新建后登记新连接（新连接处于在用状态）
	fresh, freshPeer := newSyntheticConn(server, time.Now(), time.Now())
	fresh.inUse = true
	pool.registerConn(fresh)

	// 只应裁剪 1 条空闲连接
	closedIdle := 0
	for _, peer := range idlePeers {
		if peerClosed(peer) {
			closedIdle++
		}
	}
	if closedIdle != 1 {
		t.Errorf("应恰好关闭 1 条空闲连接，实际 %d", closedIdle)
	}

	// 在用连接绝不能被关闭
	if peerClosed(inUsePeer) {
		t.Errorf("在用连接被误关闭：达到上限时不得关闭在用连接")
	}
	if peerClosed(freshPeer) {
		t.Errorf("新建的在用连接被误关闭")
	}
}
