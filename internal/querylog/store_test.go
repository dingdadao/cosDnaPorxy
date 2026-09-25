package querylog

import (
	"path/filepath"
	"testing"
	"time"

	"cosDnaPorxy/internal/utils"
)

func testLogger() *utils.EnhancedLogger {
	return utils.NewEnhancedLogger("error", "test", false)
}

// openTestStore 打开临时库并确保关闭
func openTestStore(t *testing.T, opt Options) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "query_log.db"), testLogger(), opt)
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// waitWritten 等待后台批量写入把指定条数落库
func waitWritten(t *testing.T, s *Store, want int64) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats()["written"].(int64) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待落库超时：期望 %d 条，实际 %v", want, s.Stats()["written"])
}

func sampleEntries() []Entry {
	now := time.Now().Unix()
	return []Entry{
		{Time: now - 300, Domain: "a.example.com", QType: "A", Client: "10.0.0.1:5353",
			Action: ActionSplit, ListName: "定向域名", DNS: "https://223.6.6.6/dns-query", DNSMode: "race",
			Rcode: "NOERROR", Answers: "A 1.1.1.1", ElapsedMS: 12},
		{Time: now - 200, Domain: "b.example.com", QType: "AAAA", Client: "10.0.0.2:5353",
			Action: ActionUpstream, DNS: "udp://8.8.8.8:53", Rcode: "NOERROR", Answers: "AAAA ::1", ElapsedMS: 30},
		{Time: now - 100, Domain: "c.example.com", QType: "A", Client: "10.0.0.3:5353",
			Action: ActionOverride, Rcode: "NOERROR", Answers: "A 127.0.0.1", ElapsedMS: 0},
	}
}

func TestAppendAndQuery(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	for _, e := range sampleEntries() {
		s.Append(e)
	}
	waitWritten(t, s, 3)

	all, total, err := s.Query(Filter{})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("期望 3 条，实际 total=%d len=%d", total, len(all))
	}
	// 默认按时间倒序
	if all[0].Domain != "c.example.com" {
		t.Errorf("应按时间倒序，首条为 %s", all[0].Domain)
	}
	// 字段完整性
	if all[0].Action != ActionOverride || all[0].Answers != "A 127.0.0.1" {
		t.Errorf("字段读取异常: %+v", all[0])
	}

	tests := []struct {
		name   string
		filter Filter
		want   int
	}{
		{"关键字命中域名", Filter{Keyword: "b.example"}, 1},
		{"关键字命中应答", Filter{Keyword: "::1"}, 1},
		{"关键字命中列表名", Filter{Keyword: "定向域名"}, 1},
		{"关键字命中上游DNS", Filter{Keyword: "8.8.8.8"}, 1},
		{"按来源过滤", Filter{Action: ActionSplit}, 1},
		{"按类型过滤", Filter{QType: "A"}, 2},
		{"时间区间", Filter{Start: time.Now().Unix() - 250, End: time.Now().Unix()}, 2},
		{"组合无匹配", Filter{Action: ActionSplit, QType: "AAAA"}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rows, n, err := s.Query(tc.filter)
			if err != nil {
				t.Fatalf("查询失败: %v", err)
			}
			if n != int64(tc.want) || len(rows) != tc.want {
				t.Errorf("期望 %d 条，实际 total=%d len=%d", tc.want, n, len(rows))
			}
		})
	}

	// 分页：limit/offset 与倒序保持一致
	page1, total1, err := s.Query(Filter{Limit: 2, Offset: 0})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	page2, _, err := s.Query(Filter{Limit: 2, Offset: 2})
	if err != nil {
		t.Fatalf("分页查询失败: %v", err)
	}
	if total1 != 3 || len(page1) != 2 || len(page2) != 1 {
		t.Fatalf("分页结果异常: total=%d page1=%d page2=%d", total1, len(page1), len(page2))
	}
	if page1[0].Domain == page2[0].Domain {
		t.Errorf("分页不应重复：%s", page1[0].Domain)
	}
}

func TestAppendDisabled(t *testing.T) {
	s := openTestStore(t, Options{Enabled: false})
	s.Append(Entry{Domain: "x.example.com", QType: "A", Action: ActionCache})
	time.Sleep(150 * time.Millisecond)

	if s.Enabled() {
		t.Fatal("应为关闭状态")
	}
	if n := s.Stats()["written"].(int64); n != 0 {
		t.Errorf("关闭时不应写入，实际 %d", n)
	}
	// 热开启后立即生效
	s.UpdateOptions(Options{Enabled: true})
	s.Append(Entry{Domain: "y.example.com", QType: "A", Action: ActionCache})
	waitWritten(t, s, 1)
}

func TestPruneByAgeAndRows(t *testing.T) {
	now := time.Now().Unix()

	t.Run("按保留时长清理", func(t *testing.T) {
		s := openTestStore(t, Options{Enabled: true, Retention: time.Hour, MaxRows: 1000})
		s.Append(Entry{Time: now - 7200, Domain: "old.example.com", QType: "A", Action: ActionCache})
		s.Append(Entry{Time: now - 60, Domain: "new.example.com", QType: "A", Action: ActionCache})
		waitWritten(t, s, 2)

		s.prune()
		rows, total, err := s.Query(Filter{})
		if err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		if total != 1 || len(rows) != 1 || rows[0].Domain != "new.example.com" {
			t.Fatalf("超期记录应被清理，实际 %+v", rows)
		}
	})

	t.Run("按条数上限清理最旧", func(t *testing.T) {
		s := openTestStore(t, Options{Enabled: true, Retention: 100 * time.Hour, MaxRows: 2})
		for i, d := range []string{"d1", "d2", "d3", "d4"} {
			s.Append(Entry{Time: now - int64(400-i*100), Domain: d + ".example.com", QType: "A", Action: ActionCache})
		}
		waitWritten(t, s, 4)

		s.prune()
		rows, total, err := s.Query(Filter{})
		if err != nil {
			t.Fatalf("查询失败: %v", err)
		}
		if total != 2 || len(rows) != 2 {
			t.Fatalf("应保留 2 条，实际 %d", total)
		}
		// 保留的是最新的两条（d3/d4）
		if rows[0].Domain != "d4.example.com" || rows[1].Domain != "d3.example.com" {
			t.Errorf("应保留最新两条，实际 %s / %s", rows[0].Domain, rows[1].Domain)
		}
	})
}

func TestCloseFlushesAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "query_log.db")
	s, err := Open(path, testLogger(), Options{Enabled: true})
	if err != nil {
		t.Fatalf("打开解析日志库失败: %v", err)
	}
	// 未等后台 flush 就关闭，Close 应把队列里剩余日志落库
	s.Append(Entry{Domain: "flush.example.com", QType: "A", Action: ActionError, Rcode: "SERVFAIL"})
	if err := s.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	s2, err := Open(path, testLogger(), Options{Enabled: true})
	if err != nil {
		t.Fatalf("重新打开失败: %v", err)
	}
	t.Cleanup(func() { s2.Close() })
	rows, total, err := s2.Query(Filter{Keyword: "flush.example.com"})
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Rcode != "SERVFAIL" {
		t.Fatalf("关闭前应落库剩余日志，实际 total=%d rows=%+v", total, rows)
	}
}

func TestNormalizeOptionsDefaults(t *testing.T) {
	s := openTestStore(t, Options{Enabled: true})
	opt := s.Options()
	if opt.Retention != DefaultRetention || opt.MaxRows != DefaultMaxRows {
		t.Errorf("缺省值应为 %v/%d，实际 %v/%d", DefaultRetention, DefaultMaxRows, opt.Retention, opt.MaxRows)
	}
}
