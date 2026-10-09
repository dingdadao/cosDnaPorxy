package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// ConfigJSON 配置的 JSON 表示（web API 与 SQLite 存储共用）
// 时长字段统一使用 "1.5s"、"5m"、"24h" 格式的字符串，便于阅读与编辑
type ConfigJSON struct {
	ListenPort            int             `json:"listen_port"`
	WebAddr               string          `json:"web_addr"`
	WebTLSAddr            string          `json:"web_tls_addr"`
	Upstream              []string        `json:"upstream"`
	Timeout               string          `json:"timeout"`
	ModernTimeout         string          `json:"modern_timeout"`
	ReplaceCacheTime      string          `json:"replace_cache_time"`
	MaxIPRecords          int             `json:"max_ip_records"`
	CNAMERecursionDepth   int             `json:"cname_recursion_depth"`
	ReplaceCFDomain       string          `json:"replace_cf_domain"`
	ReplaceAWSDomain      string          `json:"replace_aws_domain"`
	ReplaceCFAPI          string          `json:"replace_cf_api"`
	ReplaceAPICount       int             `json:"replace_api_count"`
	BackupDNS             string          `json:"backup_dns"`
	IPPrefer              string          `json:"ip_prefer"`
	SplitLists            []SplitListJSON `json:"split_lists"`
	CloudflareNetFile     string          `json:"cloudflare_net_file"`
	CloudflareNetFile6    string          `json:"cloudflare_net_file6"`
	AWSNetFile            string          `json:"aws_net_file"`
	NetworkRefresh        string          `json:"network_refresh"`
	LogLevel              string          `json:"log_level"`
	LogFormat             string          `json:"log_format"`
	Cache                 CacheJSON       `json:"cache"`
	QueryLog              QueryLogJSON    `json:"query_log"`
	EnableCloudflareCheck bool            `json:"enable_cloudflare_check"`
	EnableAWSCheck        bool            `json:"enable_aws_check"`

	EnableDot         bool              `json:"enable_dot"`
	DotAddr           string            `json:"dot_addr"`
	EnableDoh         bool              `json:"enable_doh"`
	DohAddr           string            `json:"doh_addr"`
	DohPath           string            `json:"doh_path"`
	EnableDoh3        bool              `json:"enable_doh3"`
	Doh3Addr          string            `json:"doh3_addr"`
	DohAltSvc         string            `json:"doh_alt_svc"`
	Doh3QuicMaxIdle   string            `json:"doh3_quic_max_idle"`
	Doh3QuicKeepalive string            `json:"doh3_quic_keepalive"`
	Doh3Allow0Rtt     bool              `json:"doh3_allow_0rtt"`
	CertStoreDir      string            `json:"cert_store_dir"`
	CertDefault       string            `json:"cert_default"`
	WebTLS            bool              `json:"web_tls"`
	WebhookToken      string            `json:"webhook_token"`
	TrustedProxies    stringOrList      `json:"trusted_proxies"`
	ClientIPSources   stringOrList      `json:"client_ip_sources"`
	ClientIPHeaders   stringOrList      `json:"client_ip_headers"`
	ClientIPStatic    map[string]string `json:"client_ip_static,omitempty"`
	ClientGroups      []ClientGroupJSON `json:"client_groups"`
	AllowACLs         stringOrList      `json:"allow_acls"`
	SourceEnabled     bool              `json:"source_enabled"`
	SourceDBDir       string            `json:"source_db_dir"`
	SourceBaseURL     string            `json:"source_base_url"`
	SourceUpdateHours int               `json:"source_update_hours"`

	// 以下为旧版（两组硬编码分流列表）字段，仅用于导入兼容。
	// 读取时若 split_lists 为空则据此合成迁移；写入时不再输出。
	LegacyDefaultDNS             string `json:"default_dns,omitempty"`
	LegacyChinaDNS               string `json:"china_dns,omitempty"`
	LegacyDesignatedDomain       string `json:"designated_domain,omitempty"`
	LegacyDesignatedDomainURL    string `json:"designated_domain_url,omitempty"`
	LegacyDesignatedRefresh      string `json:"designated_refresh,omitempty"`
	LegacyChinaDomainFile        string `json:"china_domain_file,omitempty"`
	LegacyChinaDomainFileURL     string `json:"china_domain_file_url,omitempty"`
	LegacyChinaDomainRefresh     string `json:"china_domain_refresh,omitempty"`
	LegacyEnableChinaDomainCheck bool   `json:"enable_china_domain_check,omitempty"`
}

// stringOrList 兼容 dns 字段的历史写法（单个字符串）与列表写法（字符串数组）
type stringOrList []string

func (s *stringOrList) UnmarshalJSON(data []byte) error {
	var one string
	if err := json.Unmarshal(data, &one); err == nil {
		*s = oneOrNil(one)
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// oneOrNil 单值转单元素数组，空串返回 nil
func oneOrNil(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// SplitListJSON 域名分流列表的 JSON 表示
type SplitListJSON struct {
	Name             string        `json:"name"`
	Enabled          bool          `json:"enabled"`
	Invert           bool          `json:"invert"`
	DNS              stringOrList  `json:"dns"`
	DNSMode          string        `json:"dns_mode"`
	DomainFile       string        `json:"domain_file"`
	DomainURL        string        `json:"domain_url"`
	Refresh          string        `json:"refresh"`
	EnableCloudCheck bool          `json:"enable_cloud_check"`
	ECS              ECSPolicyJSON `json:"ecs"`
	IPPrefer         string        `json:"ip_prefer"`
}

// ClientGroupJSON 客户端分组的 JSON 表示
type ClientGroupJSON struct {
	Name             string        `json:"name"`
	Enabled          bool          `json:"enabled"`
	Priority         int           `json:"priority"`
	Match            stringOrList  `json:"match"`
	Invert           bool          `json:"invert"`
	DNS              stringOrList  `json:"dns"`
	DNSMode          string        `json:"dns_mode"`
	ECS              ECSPolicyJSON `json:"ecs"`
	EnableCloudCheck bool          `json:"enable_cloud_check"`
	IPPrefer         string        `json:"ip_prefer"`
	AllowDomainSplit bool          `json:"allow_domain_split"`
}

// ECSPolicyJSON ECS 策略的 JSON 表示（缺字段时为零值＝关闭，老配置不受影响）
type ECSPolicyJSON struct {
	Enabled bool   `json:"enabled"`
	ISPType string `json:"isp_type"`
	Subnet  string `json:"subnet"`
}

// CacheJSON 缓存配置的 JSON 表示
type CacheJSON struct {
	MaxItems        int    `json:"max_items"`
	TTL             string `json:"ttl"`
	MaxAsyncWorkers int    `json:"max_async_workers"`
}

// QueryLogJSON 解析日志配置的 JSON 表示（缺字段时按默认策略启用，老配置不受影响）
type QueryLogJSON struct {
	Enabled   bool   `json:"enabled"`
	Retention string `json:"retention"`
	MaxRows   int    `json:"max_rows"`
}

// ToJSON 将内存配置转换为 JSON 表示
func (c *Config) ToJSON() *ConfigJSON {
	lists := make([]SplitListJSON, 0, len(c.SplitLists))
	for _, l := range c.SplitLists {
		lists = append(lists, SplitListJSON{
			Name:             l.Name,
			Enabled:          l.Enabled,
			Invert:           l.Invert,
			DNS:              stringOrList(l.DNS),
			DNSMode:          l.DNSMode,
			DomainFile:       l.DomainFile,
			DomainURL:        l.DomainURL,
			Refresh:          l.Refresh.String(),
			EnableCloudCheck: l.EnableCloudCheck,
			ECS: ECSPolicyJSON{
				Enabled: l.ECS.Enabled,
				ISPType: l.ECS.ISPType,
				Subnet:  l.ECS.Subnet,
			},
			IPPrefer: l.IPPrefer,
		})
	}

	groups := make([]ClientGroupJSON, 0, len(c.ClientGroups))
	for _, g := range c.ClientGroups {
		groups = append(groups, ClientGroupJSON{
			Name:     g.Name,
			Enabled:  g.Enabled,
			Priority: g.Priority,
			Match:    stringOrList(g.Match),
			Invert:   g.Invert,
			DNS:      stringOrList(g.DNS),
			DNSMode:  g.DNSMode,
			ECS: ECSPolicyJSON{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			EnableCloudCheck: g.EnableCloudCheck,
			IPPrefer:         g.IPPrefer,
			AllowDomainSplit: g.AllowDomainSplit,
		})
	}

	return &ConfigJSON{
		ListenPort:          c.ListenPort,
		WebAddr:             c.WebAddr,
		WebTLSAddr:          c.WebTLSAddr,
		Upstream:            c.Upstream,
		Timeout:             c.Timeout.String(),
		ModernTimeout:       c.ModernTimeout.String(),
		ReplaceCacheTime:    c.ReplaceCacheTime.String(),
		MaxIPRecords:        c.MaxIPRecords,
		CNAMERecursionDepth: c.CNAMERecursionDepth,
		ReplaceCFDomain:     c.ReplaceCFDomain,
		ReplaceAWSDomain:    c.ReplaceAWSDomain,
		ReplaceCFAPI:        c.ReplaceCFAPI,
		ReplaceAPICount:     c.ReplaceAPICount,
		BackupDNS:           c.BackupDNS,
		IPPrefer:            c.IPPrefer,
		SplitLists:          lists,
		CloudflareNetFile:   c.CloudflareNetFile,
		CloudflareNetFile6:  c.CloudflareNetFile6,
		AWSNetFile:          c.AWSNetFile,
		NetworkRefresh:      c.NetworkRefreshInterval.String(),
		LogLevel:            c.LogLevel,
		LogFormat:           c.LogFormat,
		Cache: CacheJSON{
			MaxItems:        c.Cache.MaxItems,
			TTL:             c.Cache.TTL.String(),
			MaxAsyncWorkers: c.Cache.MaxAsyncWorkers,
		},
		QueryLog: QueryLogJSON{
			Enabled:   c.QueryLog.Enabled,
			Retention: c.QueryLog.Retention.String(),
			MaxRows:   c.QueryLog.MaxRows,
		},
		EnableCloudflareCheck: c.EnableCloudflareCheck,
		EnableAWSCheck:        c.EnableAWSCheck,

		EnableDot:         c.EnableDoT,
		DotAddr:           c.DoTAddr,
		EnableDoh:         c.EnableDoH,
		DohAddr:           c.DoHAddr,
		DohPath:           c.DoHPath,
		EnableDoh3:        c.EnableDoH3,
		Doh3Addr:          c.DoH3Addr,
		DohAltSvc:         c.DoHAltSvc,
		Doh3QuicMaxIdle:   c.DoH3QUICMaxIdle.String(),
		Doh3QuicKeepalive: c.DoH3QUICKeepAlive.String(),
		Doh3Allow0Rtt:     c.DoH3Allow0RTT,
		CertStoreDir:      c.CertStoreDir,
		CertDefault:       c.CertDefault,
		WebTLS:            c.WebTLS,
		WebhookToken:      c.WebhookToken,
		TrustedProxies:    stringOrList(c.TrustedProxies),
		ClientIPSources:   stringOrList(c.ClientIPSources),
		ClientIPHeaders:   stringOrList(c.ClientIPHeaders),
		ClientIPStatic:    c.ClientIPStatic,
		ClientGroups:      groups,
		AllowACLs:         stringOrList(c.AllowACLs),
		SourceEnabled:     c.SourceEnabled,
		SourceDBDir:       c.SourceDBDir,
		SourceBaseURL:     c.SourceBaseURL,
		SourceUpdateHours: c.SourceUpdateHours,
	}
}

// parseDuration 解析时长字符串，空值返回 fallback
func parseDuration(s string, fallback time.Duration) (time.Duration, error) {
	if s == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: %w", s, err)
	}
	return d, nil
}

// legacySplitLists 将旧版两组硬编码字段合成为分流列表（用于旧配置迁移）
func (j *ConfigJSON) legacySplitLists() []SplitList {
	refreshOr := func(s string, fallback time.Duration) time.Duration {
		d, err := parseDuration(s, fallback)
		if err != nil {
			return fallback
		}
		return d
	}

	lists := make([]SplitList, 0, 2)
	if j.LegacyDefaultDNS != "" || j.LegacyDesignatedDomain != "" || j.LegacyDesignatedDomainURL != "" {
		lists = append(lists, SplitList{
			Name:       "定向域名",
			Enabled:    true,
			DNS:        oneOrNil(j.LegacyDefaultDNS),
			DomainFile: j.LegacyDesignatedDomain,
			DomainURL:  j.LegacyDesignatedDomainURL,
			Refresh:    refreshOr(j.LegacyDesignatedRefresh, 30*time.Minute),
		})
	}
	if j.LegacyChinaDNS != "" || j.LegacyChinaDomainFile != "" || j.LegacyChinaDomainFileURL != "" {
		lists = append(lists, SplitList{
			Name:       "中国域名",
			Enabled:    j.LegacyEnableChinaDomainCheck,
			DNS:        oneOrNil(j.LegacyChinaDNS),
			DomainFile: j.LegacyChinaDomainFile,
			DomainURL:  j.LegacyChinaDomainFileURL,
			Refresh:    refreshOr(j.LegacyChinaDomainRefresh, 24*time.Hour),
		})
	}
	return lists
}

// ToConfig 将 JSON 表示转换为内存配置（解析时长字符串并校验）
func (j *ConfigJSON) ToConfig() (*Config, error) {
	def := DefaultConfig()

	splitLists := make([]SplitList, 0, len(j.SplitLists))
	for i, l := range j.SplitLists {
		refresh, err := parseDuration(l.Refresh, 0)
		if err != nil {
			return nil, fmt.Errorf("split_lists[%d].refresh: %w", i, err)
		}
		if !ValidIPPrefer(l.IPPrefer) {
			return nil, fmt.Errorf("split_lists[%d].ip_prefer: 非法取值 %q", i, l.IPPrefer)
		}
		splitLists = append(splitLists, SplitList{
			Name:             l.Name,
			Enabled:          l.Enabled,
			Invert:           l.Invert,
			DNS:              []string(l.DNS),
			DNSMode:          l.DNSMode,
			DomainFile:       l.DomainFile,
			DomainURL:        l.DomainURL,
			Refresh:          refresh,
			EnableCloudCheck: l.EnableCloudCheck,
			ECS: ECSPolicy{
				Enabled: l.ECS.Enabled,
				ISPType: l.ECS.ISPType,
				Subnet:  l.ECS.Subnet,
			},
			IPPrefer: l.IPPrefer,
		})
	}
	if len(splitLists) == 0 {
		splitLists = j.legacySplitLists()
	}

	// A/AAAA 偏好档位：空值=不干预，非法值直接拒绝（避免静默失效）
	if !ValidIPPrefer(j.IPPrefer) {
		return nil, fmt.Errorf("ip_prefer: 非法取值 %q", j.IPPrefer)
	}

	// 老配置里没有 query_log 字段（retention 与 max_rows 均为零值）时整体按默认策略，默认启用
	queryLog := QueryLogConfig{Enabled: j.QueryLog.Enabled, MaxRows: j.QueryLog.MaxRows}
	if j.QueryLog.Retention == "" && j.QueryLog.MaxRows == 0 {
		queryLog = def.QueryLog
	}

	cfg := &Config{
		ListenPort:          j.ListenPort,
		WebAddr:             j.WebAddr,
		WebTLSAddr:          j.WebTLSAddr,
		Upstream:            j.Upstream,
		MaxIPRecords:        j.MaxIPRecords,
		CNAMERecursionDepth: j.CNAMERecursionDepth,
		ReplaceCFDomain:     j.ReplaceCFDomain,
		ReplaceAWSDomain:    j.ReplaceAWSDomain,
		ReplaceCFAPI:        j.ReplaceCFAPI,
		ReplaceAPICount:     j.ReplaceAPICount,
		BackupDNS:           j.BackupDNS,
		IPPrefer:            j.IPPrefer,
		SplitLists:          splitLists,
		CloudflareNetFile:   j.CloudflareNetFile,
		CloudflareNetFile6:  j.CloudflareNetFile6,
		AWSNetFile:          j.AWSNetFile,
		LogLevel:            j.LogLevel,
		LogFormat:           j.LogFormat,
		Cache: CacheConfig{
			MaxItems:        j.Cache.MaxItems,
			MaxAsyncWorkers: j.Cache.MaxAsyncWorkers,
		},
		QueryLog:              queryLog,
		EnableCloudflareCheck: j.EnableCloudflareCheck,
		EnableAWSCheck:        j.EnableAWSCheck,
	}

	clientGroups := make([]ClientGroup, 0, len(j.ClientGroups))
	for i, g := range j.ClientGroups {
		if !ValidIPPrefer(g.IPPrefer) {
			return nil, fmt.Errorf("client_groups[%d].ip_prefer: 非法取值 %q", i, g.IPPrefer)
		}
		clientGroups = append(clientGroups, ClientGroup{
			Name:     g.Name,
			Enabled:  g.Enabled,
			Priority: g.Priority,
			Match:    []string(g.Match),
			Invert:   g.Invert,
			DNS:      []string(g.DNS),
			DNSMode:  g.DNSMode,
			ECS: ECSPolicy{
				Enabled: g.ECS.Enabled,
				ISPType: g.ECS.ISPType,
				Subnet:  g.ECS.Subnet,
			},
			EnableCloudCheck: g.EnableCloudCheck,
			IPPrefer:         g.IPPrefer,
			AllowDomainSplit: g.AllowDomainSplit,
		})
	}
	cfg.ClientGroups = clientGroups
	cfg.SourceEnabled = j.SourceEnabled
	cfg.SourceDBDir = j.SourceDBDir
	cfg.SourceBaseURL = j.SourceBaseURL
	cfg.SourceUpdateHours = j.SourceUpdateHours
	cfg.TrustedProxies = []string(j.TrustedProxies)
	cfg.ClientIPSources = []string(j.ClientIPSources)
	cfg.ClientIPHeaders = []string(j.ClientIPHeaders)
	cfg.ClientIPStatic = j.ClientIPStatic
	cfg.AllowACLs = []string(j.AllowACLs)

	cfg.EnableDoT = j.EnableDot
	cfg.DoTAddr = j.DotAddr
	cfg.EnableDoH = j.EnableDoh
	cfg.DoHAddr = j.DohAddr
	cfg.DoHPath = j.DohPath
	cfg.EnableDoH3 = j.EnableDoh3
	cfg.DoH3Addr = j.Doh3Addr
	cfg.DoHAltSvc = j.DohAltSvc
	cfg.DoH3Allow0RTT = j.Doh3Allow0Rtt
	cfg.CertStoreDir = j.CertStoreDir
	cfg.CertDefault = j.CertDefault
	cfg.WebTLS = j.WebTLS
	cfg.WebhookToken = j.WebhookToken

	var err error
	if cfg.Timeout, err = parseDuration(j.Timeout, def.Timeout); err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	if cfg.ModernTimeout, err = parseDuration(j.ModernTimeout, def.ModernTimeout); err != nil {
		return nil, fmt.Errorf("modern_timeout: %w", err)
	}
	if cfg.ReplaceCacheTime, err = parseDuration(j.ReplaceCacheTime, def.ReplaceCacheTime); err != nil {
		return nil, fmt.Errorf("replace_cache_time: %w", err)
	}
	if cfg.NetworkRefreshInterval, err = parseDuration(j.NetworkRefresh, def.NetworkRefreshInterval); err != nil {
		return nil, fmt.Errorf("network_refresh: %w", err)
	}
	if cfg.Cache.TTL, err = parseDuration(j.Cache.TTL, def.Cache.TTL); err != nil {
		return nil, fmt.Errorf("cache.ttl: %w", err)
	}
	if cfg.QueryLog.Retention, err = parseDuration(j.QueryLog.Retention, queryLog.Retention); err != nil {
		return nil, fmt.Errorf("query_log.retention: %w", err)
	}
	if cfg.DoH3QUICMaxIdle, err = parseDuration(j.Doh3QuicMaxIdle, def.DoH3QUICMaxIdle); err != nil {
		return nil, fmt.Errorf("doh3_quic_max_idle: %w", err)
	}
	if cfg.DoH3QUICKeepAlive, err = parseDuration(j.Doh3QuicKeepalive, def.DoH3QUICKeepAlive); err != nil {
		return nil, fmt.Errorf("doh3_quic_keepalive: %w", err)
	}

	return cfg, nil
}
