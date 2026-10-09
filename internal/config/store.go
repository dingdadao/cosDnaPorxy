package config

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // 纯Go SQLite驱动（免cgo）
)

// Override 本地域名篡改记录（最高优先级：命中后直接返回本地记录，不走缓存与上游）
type Override struct {
	ID      int64  `json:"id"`
	Domain  string `json:"domain"` // 域名，支持精确（example.com）或后缀（.example.com / *.example.com）匹配
	QType   string `json:"qtype"`  // A / AAAA / CNAME
	Value   string `json:"value"`  // A/AAAA为IP地址，CNAME为目标域名
	TTL     uint32 `json:"ttl"`    // 记录TTL（秒）
	Enabled bool   `json:"enabled"`
}

// Store SQLite 配置存储
type Store struct {
	db *sql.DB
}

// OpenStore 打开（必要时创建）SQLite 配置库并初始化表结构
func OpenStore(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("创建配置库目录失败: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("打开配置库失败: %w", err)
	}

	// SQLite 单写者模型，限制连接数为1避免 database is locked
	db.SetMaxOpenConns(1)

	store := &Store{db: db}
	if err := store.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

// initSchema 初始化表结构
func (s *Store) initSchema() error {
	schema := `
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS overrides (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain     TEXT NOT NULL,
	qtype      TEXT NOT NULL,
	value      TEXT NOT NULL,
	ttl        INTEGER NOT NULL DEFAULT 60,
	enabled    INTEGER NOT NULL DEFAULT 1,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_overrides_domain ON overrides(domain);

CREATE TABLE IF NOT EXISTS certs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	domains     TEXT NOT NULL,
	cert_path   TEXT NOT NULL,
	key_path    TEXT NOT NULL,
	fingerprint TEXT NOT NULL,
	not_before  INTEGER NOT NULL,
	not_after   INTEGER NOT NULL,
	source      TEXT NOT NULL,
	updated_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_certs_fingerprint ON certs(fingerprint);
`
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("初始化配置库表结构失败: %w", err)
	}
	return nil
}

// Close 关闭配置库
func (s *Store) Close() error {
	return s.db.Close()
}

// LoadConfig 从配置库加载配置；库中无配置时返回内置默认值并持久化
func (s *Store) LoadConfig() (*Config, error) {
	row := s.db.QueryRow(`SELECT value FROM settings WHERE key = 'config'`)
	var raw string
	err := row.Scan(&raw)
	if err == sql.ErrNoRows {
		cfg := DefaultConfig()
		if err := s.SaveConfig(cfg); err != nil {
			return nil, fmt.Errorf("持久化默认配置失败: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取配置失败: %w", err)
	}

	var j ConfigJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// SaveConfig 保存配置到配置库
func (s *Store) SaveConfig(cfg *Config) error {
	data, err := json.Marshal(cfg.ToJSON())
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}
	_, err = s.db.Exec(`INSERT INTO settings(key, value) VALUES('config', ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, string(data))
	if err != nil {
		return fmt.Errorf("保存配置失败: %w", err)
	}
	return nil
}

// ListOverrides 查询所有域名篡改记录
func (s *Store) ListOverrides() ([]*Override, error) {
	rows, err := s.db.Query(`SELECT id, domain, qtype, value, ttl, enabled FROM overrides ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("查询域名篡改记录失败: %w", err)
	}
	defer rows.Close()

	list := make([]*Override, 0)
	for rows.Next() {
		o := &Override{}
		var enabled int
		if err := rows.Scan(&o.ID, &o.Domain, &o.QType, &o.Value, &o.TTL, &enabled); err != nil {
			return nil, fmt.Errorf("读取域名篡改记录失败: %w", err)
		}
		o.Enabled = enabled == 1
		list = append(list, o)
	}
	return list, rows.Err()
}

// AddOverride 新增域名篡改记录，返回自增ID
func (s *Store) AddOverride(o *Override) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO overrides(domain, qtype, value, ttl, enabled, created_at, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?)`,
		o.Domain, o.QType, o.Value, o.TTL, boolToInt(o.Enabled), now, now)
	if err != nil {
		return 0, fmt.Errorf("新增域名篡改记录失败: %w", err)
	}
	return res.LastInsertId()
}

// UpdateOverride 更新域名篡改记录
func (s *Store) UpdateOverride(o *Override) error {
	res, err := s.db.Exec(`UPDATE overrides SET domain=?, qtype=?, value=?, ttl=?, enabled=?, updated_at=? WHERE id=?`,
		o.Domain, o.QType, o.Value, o.TTL, boolToInt(o.Enabled), time.Now().Unix(), o.ID)
	if err != nil {
		return fmt.Errorf("更新域名篡改记录失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("域名篡改记录不存在: id=%d", o.ID)
	}
	return nil
}

// DeleteOverride 删除域名篡改记录
func (s *Store) DeleteOverride(id int64) error {
	res, err := s.db.Exec(`DELETE FROM overrides WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("删除域名篡改记录失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("域名篡改记录不存在: id=%d", id)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CertRecord 证书元数据（数据库层）
type CertRecord struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Domains     []string  `json:"domains"`
	CertPath    string    `json:"cert_path"`
	KeyPath     string    `json:"key_path"`
	Fingerprint string    `json:"fingerprint"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Source      string    `json:"source"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// marshalDomains 将域名数组序列化为 JSON
func marshalDomains(domains []string) string {
	b, _ := json.Marshal(domains)
	return string(b)
}

// unmarshalDomains 从 JSON 反序列化域名数组
func unmarshalDomains(s string) ([]string, error) {
	var domains []string
	if err := json.Unmarshal([]byte(s), &domains); err != nil {
		return nil, err
	}
	return domains, nil
}

// ListCerts 查询所有证书元数据
func (s *Store) ListCerts() ([]CertRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, domains, cert_path, key_path, fingerprint, not_before, not_after, source, updated_at FROM certs ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("查询证书失败: %w", err)
	}
	defer rows.Close()

	var list []CertRecord
	for rows.Next() {
		var r CertRecord
		var domainsJSON string
		var notBefore, notAfter, updatedAt int64
		if err := rows.Scan(&r.ID, &r.Name, &domainsJSON, &r.CertPath, &r.KeyPath, &r.Fingerprint, &notBefore, &notAfter, &r.Source, &updatedAt); err != nil {
			return nil, fmt.Errorf("读取证书失败: %w", err)
		}
		domains, err := unmarshalDomains(domainsJSON)
		if err != nil {
			return nil, fmt.Errorf("解析证书域名失败: %w", err)
		}
		r.Domains = domains
		r.NotBefore = time.Unix(notBefore, 0)
		r.NotAfter = time.Unix(notAfter, 0)
		r.UpdatedAt = time.Unix(updatedAt, 0)
		list = append(list, r)
	}
	return list, rows.Err()
}

// GetCertByName 按名称查询证书
func (s *Store) GetCertByName(name string) (*CertRecord, error) {
	row := s.db.QueryRow(`SELECT id, name, domains, cert_path, key_path, fingerprint, not_before, not_after, source, updated_at FROM certs WHERE name = ?`, name)
	var r CertRecord
	var domainsJSON string
	var notBefore, notAfter, updatedAt int64
	if err := row.Scan(&r.ID, &r.Name, &domainsJSON, &r.CertPath, &r.KeyPath, &r.Fingerprint, &notBefore, &notAfter, &r.Source, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	domains, err := unmarshalDomains(domainsJSON)
	if err != nil {
		return nil, fmt.Errorf("解析证书域名失败: %w", err)
	}
	r.Domains = domains
	r.NotBefore = time.Unix(notBefore, 0)
	r.NotAfter = time.Unix(notAfter, 0)
	r.UpdatedAt = time.Unix(updatedAt, 0)
	return &r, nil
}

// GetCertByFingerprint 按指纹查询证书
func (s *Store) GetCertByFingerprint(fp string) (*CertRecord, error) {
	row := s.db.QueryRow(`SELECT id, name, domains, cert_path, key_path, fingerprint, not_before, not_after, source, updated_at FROM certs WHERE fingerprint = ?`, fp)
	var r CertRecord
	var domainsJSON string
	var notBefore, notAfter, updatedAt int64
	if err := row.Scan(&r.ID, &r.Name, &domainsJSON, &r.CertPath, &r.KeyPath, &r.Fingerprint, &notBefore, &notAfter, &r.Source, &updatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("读取证书失败: %w", err)
	}
	domains, err := unmarshalDomains(domainsJSON)
	if err != nil {
		return nil, fmt.Errorf("解析证书域名失败: %w", err)
	}
	r.Domains = domains
	r.NotBefore = time.Unix(notBefore, 0)
	r.NotAfter = time.Unix(notAfter, 0)
	r.UpdatedAt = time.Unix(updatedAt, 0)
	return &r, nil
}

// AddOrReplaceCert 添加或替换证书（同 name 覆盖）
func (s *Store) AddOrReplaceCert(r *CertRecord) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO certs(name, domains, cert_path, key_path, fingerprint, not_before, not_after, source, updated_at)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			domains = excluded.domains,
			cert_path = excluded.cert_path,
			key_path = excluded.key_path,
			fingerprint = excluded.fingerprint,
			not_before = excluded.not_before,
			not_after = excluded.not_after,
			source = excluded.source,
			updated_at = excluded.updated_at`,
		r.Name, marshalDomains(r.Domains), r.CertPath, r.KeyPath, r.Fingerprint,
		r.NotBefore.Unix(), r.NotAfter.Unix(), r.Source, now)
	if err != nil {
		return fmt.Errorf("保存证书失败: %w", err)
	}
	return nil
}

// DeleteCert 删除证书
func (s *Store) DeleteCert(name string) error {
	res, err := s.db.Exec(`DELETE FROM certs WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("删除证书失败: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("证书不存在: %s", name)
	}
	return nil
}
