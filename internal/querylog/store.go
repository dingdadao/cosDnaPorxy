// Package querylog 解析日志：记录每次客户端 DNS 查询走了哪条路（篡改/缓存/分流/上游/云替换）
// 用的什么策略（列表、DNS 服务器、解析模式、ECS）以及最终结果。
// 存储使用独立于配置库的 SQLite 文件：WAL 模式 + 单连接 + 异步批量写入，
// 写入失败或队列打满都不影响 DNS 解析主链路；按保留时长与条数上限自动清理。
package querylog

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cosDnaPorxy/internal/utils"

	_ "modernc.org/sqlite" // 纯Go SQLite驱动（免cgo）
)

// 解析动作类型（action 字段取值）
const (
	ActionOverride = "override" // 本地域名篡改命中（最高优先级）
	ActionCache    = "cache"    // 缓存命中（含云替换响应缓存）
	ActionSplit    = "split"    // 命中域名分流列表
	ActionUpstream = "upstream" // 走全局上游
	ActionCloud    = "cloud"    // 云 IP 检测后替换
	ActionFiltered = "filtered" // 被 A/AAAA 偏好策略置空（返回空 NODATA）
	ActionRefused  = "refused"  // RD=0 且缓存未命中
	ActionError    = "error"    // 解析失败或错误响应
)

const (
	queueSize  = 8192        // 异步写入队列长度，打满即丢弃并计数
	batchSize  = 256         // 单次事务最大条数
	flushEvery = time.Second // 队列未满时的最大落库间隔
	pruneEvery = 10 * time.Minute
	pruneLimit = 50000 // 单次清理上限，避免长时间持有写锁
	maxLimit   = 500   // 单次查询最大条数
)

// 默认保留策略（配置缺省时使用）
const (
	DefaultRetention = 72 * time.Hour
	DefaultMaxRows   = 200000
)

// Entry 单条解析日志（全量明细：每次客户端查询一行）
type Entry struct {
	ID        int64  `json:"id"`
	Time      int64  `json:"time"` // Unix 秒
	Domain    string `json:"domain"`
	QType     string `json:"qtype"`
	Client    string `json:"client"`
	Action    string `json:"action"`
	ListName  string `json:"list_name"` // 命中的分流列表名称（篡改/缓存/上游为空）
	DNS       string `json:"dns"`       // 实际应答的上游服务器
	DNSMode   string `json:"dns_mode"`  // race/failover
	ECS       string `json:"ecs"`       // ECS 处理说明（注入 xxx / 剥离客户端 ECS）
	Rcode     string `json:"rcode"`
	Answers   string `json:"answers"` // 应答记录摘要
	ElapsedMS int64  `json:"elapsed_ms"`
}

// Options 存储选项（由配置热更新）
type Options struct {
	Enabled   bool
	Retention time.Duration
	MaxRows   int
}

// Filter 查询条件（零值表示不限）
type Filter struct {
	Keyword string // 模糊匹配域名/应答/客户端/列表名/DNS
	Action  string
	QType   string
	Start   int64 // Unix 秒
	End     int64
	Limit   int
	Offset  int
}

// Store 解析日志存储
type Store struct {
	db     *sql.DB
	logger *utils.EnhancedLogger

	ch        chan Entry
	done      chan struct{}
	wg        sync.WaitGroup
	closeOnce sync.Once

	optMu sync.RWMutex
	opt   Options

	dropped atomic.Int64
	written atomic.Int64
}

// Open 打开（必要时创建）解析日志库并启动后台写入与清理任务
func Open(path string, logger *utils.EnhancedLogger, opt Options) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建解析日志目录失败: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开解析日志库失败: %w", err)
	}
	// 单写者模型：单连接避免 database is locked
	db.SetMaxOpenConns(1)

	s := &Store{
		db:     db,
		logger: logger,
		ch:     make(chan Entry, queueSize),
		done:   make(chan struct{}),
		opt:    normalizeOptions(opt),
	}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}

	s.wg.Add(2)
	go s.writeLoop()
	go s.pruneLoop()
	return s, nil
}

// initSchema 初始化表结构与索引，并开启 WAL
func (s *Store) initSchema() error {
	// WAL 降低写入对读取的阻塞；NORMAL 在 WAL 下已足够安全且写入更快
	pragmas := `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`
	if _, err := s.db.Exec(pragmas); err != nil {
		return fmt.Errorf("初始化解析日志库参数失败: %w", err)
	}

	schema := `
CREATE TABLE IF NOT EXISTS query_logs (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	ts         INTEGER NOT NULL,
	domain     TEXT NOT NULL,
	qtype      TEXT NOT NULL,
	client     TEXT NOT NULL DEFAULT '',
	action     TEXT NOT NULL,
	list_name  TEXT NOT NULL DEFAULT '',
	dns        TEXT NOT NULL DEFAULT '',
	dns_mode   TEXT NOT NULL DEFAULT '',
	ecs        TEXT NOT NULL DEFAULT '',
	rcode      TEXT NOT NULL DEFAULT '',
	answers    TEXT NOT NULL DEFAULT '',
	elapsed_ms INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_query_logs_ts ON query_logs(ts);
CREATE INDEX IF NOT EXISTS idx_query_logs_domain ON query_logs(domain);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("初始化解析日志表结构失败: %w", err)
	}
	return nil
}

// normalizeOptions 补齐缺省保留策略
func normalizeOptions(opt Options) Options {
	if opt.Retention <= 0 {
		opt.Retention = DefaultRetention
	}
	if opt.MaxRows <= 0 {
		opt.MaxRows = DefaultMaxRows
	}
	return opt
}

// UpdateOptions 热更新选项（配置保存后调用）
func (s *Store) UpdateOptions(opt Options) {
	s.optMu.Lock()
	s.opt = normalizeOptions(opt)
	s.optMu.Unlock()
}

// Options 返回当前选项
func (s *Store) Options() Options {
	s.optMu.RLock()
	defer s.optMu.RUnlock()
	return s.opt
}

// Enabled 是否记录日志
func (s *Store) Enabled() bool {
	s.optMu.RLock()
	defer s.optMu.RUnlock()
	return s.opt.Enabled
}

// Append 异步追加一条日志（不阻塞调用方；关闭/打满时丢弃并计数）
func (s *Store) Append(e Entry) {
	if !s.Enabled() {
		return
	}
	if e.Time == 0 {
		e.Time = time.Now().Unix()
	}
	select {
	case s.ch <- e:
	default:
		s.dropped.Add(1)
	}
}

// Stats 运行状态（供管理端展示）
func (s *Store) Stats() map[string]interface{} {
	opt := s.Options()
	return map[string]interface{}{
		"enabled":           opt.Enabled,
		"retention_seconds": int64(opt.Retention.Seconds()),
		"max_rows":          opt.MaxRows,
		"written":           s.written.Load(),
		"dropped":           s.dropped.Load(),
		"queued":            len(s.ch),
	}
}

// Query 按条件分页查询（按时间倒序），返回结果与命中总数
func (s *Store) Query(f Filter) ([]Entry, int64, error) {
	where, args := buildWhere(f)

	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_logs`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("统计解析日志失败: %w", err)
	}

	limit := f.Limit
	if limit <= 0 || limit > maxLimit {
		limit = maxLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(`SELECT id, ts, domain, qtype, client, action, list_name, dns, dns_mode, ecs, rcode, answers, elapsed_ms
		FROM query_logs`+where+` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`,
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("查询解析日志失败: %w", err)
	}
	defer rows.Close()

	list := make([]Entry, 0, limit)
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.Time, &e.Domain, &e.QType, &e.Client, &e.Action,
			&e.ListName, &e.DNS, &e.DNSMode, &e.ECS, &e.Rcode, &e.Answers, &e.ElapsedMS); err != nil {
			return nil, 0, fmt.Errorf("读取解析日志失败: %w", err)
		}
		list = append(list, e)
	}
	return list, total, rows.Err()
}

// buildWhere 拼接条件与参数
func buildWhere(f Filter) (string, []interface{}) {
	var conds []string
	var args []interface{}

	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		like := "%" + kw + "%"
		conds = append(conds, `(domain LIKE ? OR answers LIKE ? OR client LIKE ? OR list_name LIKE ? OR dns LIKE ?)`)
		args = append(args, like, like, like, like, like)
	}
	if f.Action != "" {
		conds = append(conds, `action = ?`)
		args = append(args, f.Action)
	}
	if f.QType != "" {
		conds = append(conds, `qtype = ?`)
		args = append(args, f.QType)
	}
	if f.Start > 0 {
		conds = append(conds, `ts >= ?`)
		args = append(args, f.Start)
	}
	if f.End > 0 {
		conds = append(conds, `ts <= ?`)
		args = append(args, f.End)
	}

	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// writeLoop 批量落库：攒够 batchSize 或到达 flushEvery 即写入
func (s *Store) writeLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(flushEvery)
	defer ticker.Stop()

	batch := make([]Entry, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.insertBatch(batch); err != nil {
			s.logger.Error("❌ [解析日志写入失败] ", map[string]interface{}{
				"rule":  "QUERY_LOG_INSERT_FAILED",
				"count": len(batch),
				"error": err.Error(),
			})
		} else {
			s.written.Add(int64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case e := <-s.ch:
			batch = append(batch, e)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-s.done:
			// 退出前把队列里剩余的日志落库，避免丢失
			for {
				select {
				case e := <-s.ch:
					batch = append(batch, e)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

// insertBatch 单事务写入一批日志
func (s *Store) insertBatch(batch []Entry) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO query_logs(ts, domain, qtype, client, action, list_name, dns, dns_mode, ecs, rcode, answers, elapsed_ms)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()

	for _, e := range batch {
		if _, err := stmt.Exec(e.Time, e.Domain, e.QType, e.Client, e.Action,
			e.ListName, e.DNS, e.DNSMode, e.ECS, e.Rcode, e.Answers, e.ElapsedMS); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// pruneLoop 周期性清理超期与超量日志
func (s *Store) pruneLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(pruneEvery)
	defer ticker.Stop()

	s.prune()
	for {
		select {
		case <-ticker.C:
			s.prune()
		case <-s.done:
			return
		}
	}
}

// prune 按保留时长删除超期记录，再按条数上限删除最旧记录
func (s *Store) prune() {
	opt := s.Options()

	if opt.Retention > 0 {
		cutoff := time.Now().Add(-opt.Retention).Unix()
		if res, err := s.db.Exec(`DELETE FROM query_logs WHERE ts < ?`, cutoff); err != nil {
			s.logger.Warn("⚠️ [解析日志超期清理失败] ", map[string]interface{}{
				"rule":  "QUERY_LOG_PRUNE_FAILED",
				"error": err.Error(),
			})
		} else if n, _ := res.RowsAffected(); n > 0 {
			s.logger.Info("🧹 [解析日志已按保留时长清理] ", map[string]interface{}{
				"rule":        "QUERY_LOG_PRUNED_BY_AGE",
				"deleted":     n,
				"retention_s": int64(opt.Retention.Seconds()),
			})
		}
	}

	if opt.MaxRows <= 0 {
		return
	}
	var total int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM query_logs`).Scan(&total); err != nil {
		return
	}
	excess := total - int64(opt.MaxRows)
	if excess <= 0 {
		return
	}
	if excess > pruneLimit {
		excess = pruneLimit
	}
	if res, err := s.db.Exec(`DELETE FROM query_logs WHERE id IN (SELECT id FROM query_logs ORDER BY id ASC LIMIT ?)`, excess); err != nil {
		s.logger.Warn("⚠️ [解析日志超量清理失败] ", map[string]interface{}{
			"rule":  "QUERY_LOG_PRUNE_FAILED",
			"error": err.Error(),
		})
	} else if n, _ := res.RowsAffected(); n > 0 {
		s.logger.Info("🧹 [解析日志已按条数上限清理] ", map[string]interface{}{
			"rule":     "QUERY_LOG_PRUNED_BY_ROWS",
			"deleted":  n,
			"max_rows": opt.MaxRows,
		})
	}
}

// Close 停止后台任务并落库剩余日志后关闭库
func (s *Store) Close() error {
	s.closeOnce.Do(func() { close(s.done) })
	s.wg.Wait()
	return s.db.Close()
}
