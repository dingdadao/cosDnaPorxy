package config

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// 常量定义
const (
	DefaultStorePath    = "./data/config.db"    // SQLite 配置库存储路径
	DefaultQueryLogPath = "./data/query_log.db" // 解析日志库存储路径（独立于配置库）
	DefaultWebAddr      = ":5380"               // Web 管理端默认监听地址
	DefaultLogLevel     = "info"
)

// 解析日志默认保留策略
const (
	DefaultQueryLogRetention = 72 * time.Hour // 默认保留 3 天
	DefaultQueryLogMaxRows   = 200000         // 默认最多 20 万条
)

// 支持的 ECS 线路类型（白名单外的取值一律不注入）
const (
	ECSTypeTelecom = "telecom" // 电信
	ECSTypeUnicom  = "unicom"  // 联通
	ECSTypeMobile  = "mobile"  // 移动
)

// ValidECSType 判断线路类型是否受支持
func ValidECSType(t string) bool {
	switch t {
	case ECSTypeTelecom, ECSTypeUnicom, ECSTypeMobile:
		return true
	}
	return false
}

// ECSPolicy 分流列表的 EDNS Client Subnet 策略（RFC 7871）：按手动指定的公网 IP 让上游返回对应线路的结果
type ECSPolicy struct {
	Enabled bool   // 是否向上游注入 ECS（关闭时命中该列表仅剥离客户端自带 ECS）
	ISPType string // 线路类型：telecom/unicom/mobile
	Subnet  string // 手动指定的公网 IP 或 CIDR（裸 IP 按 /24，IPv6 裸 IP 按 /56）
}

// Resolve 解析待注入的地址前缀：开关未打开、类型不在白名单、地址不可解析时均返回 ok=false（不注入）
func (e ECSPolicy) Resolve() (netip.Prefix, bool) {
	if !e.Enabled || !ValidECSType(e.ISPType) {
		return netip.Prefix{}, false
	}
	s := strings.TrimSpace(e.Subnet)
	if s == "" {
		return netip.Prefix{}, false
	}
	// CIDR 写法直接取其前缀
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, false
		}
		return p.Masked(), true
	}
	// 裸 IP 按运营商可识别的最小前缀补齐
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 24 // IPv4
	if ip.Is6() {
		bits = 56 // IPv6（RFC 7871 建议值）
	}
	p := netip.PrefixFrom(ip, bits)
	if !p.IsValid() {
		return netip.Prefix{}, false
	}
	return p.Masked(), true
}

// CacheConfig 缓存配置
type CacheConfig struct {
	MaxItems        int           // 最大缓存条目数
	TTL             time.Duration // 兜底缓存TTL：上游未提供TTL时使用，不再抬高上游TTL
	MaxAsyncWorkers int           // 最大异步工作线程数
}

// 分流列表的 DNS 解析模式
const (
	DNSModeRace     = "race"     // 并发竞速：同时查询所有 DNS，取最快成功的结果（默认）
	DNSModeFailover = "failover" // 串行故障转移：按 DNS 顺序依次查询，前一个失败/超时才用下一个
)

// A/AAAA 偏好档位：列表未配置时跟随全局默认，全局默认与"不干预"等效
// 语义前提：客户端 QTYPE 永远被尊重（查A回A、查AAAA回AAAA），"优先"只能靠抑制次优类型（返回空 NODATA）实现
const (
	IPPreferAuto  = ""            // 不干预：完全按客户端 QTYPE 返回（默认）
	IPPreferA     = "prefer_a"    // 优先A：查询AAAA且该域名确有A记录时返回空 NODATA；无A（纯v6域名）则照常返回AAAA
	IPPreferAAAA  = "prefer_aaaa" // 优先AAAA：不抑制A；AAAA不因云替换缺v6而被置空，降级返回上游真实AAAA
	IPPreferOnlyA = "only_a"      // 只能A：查询AAAA一律返回空 NODATA
)

// ValidIPPrefer 判断 A/AAAA 偏好档位取值是否合法（空串＝不干预）
func ValidIPPrefer(v string) bool {
	switch v {
	case IPPreferAuto, IPPreferA, IPPreferAAAA, IPPreferOnlyA:
		return true
	}
	return false
}

// SplitList 域名分流列表：命中列表内域名时改用该列表的 DNS 解析
// 数组顺序即匹配优先级，命中第一条即生效
type SplitList struct {
	Name             string        // 自定义名称（仅用于展示与日志）
	Enabled          bool          // 是否启用该列表
	Invert           bool          // 取反匹配：域名不在清单内时命中本列表（清单为空时不参与匹配）
	DNS              []string      // 命中后使用的 DNS 服务器列表（按 DNSMode 解析；支持 udp/tcp/https/tls/h3）
	DNSMode          string        // DNS 解析模式：race(并发竞速，默认/空值)/failover(串行故障转移)
	DomainFile       string        // 域名列表本地文件路径
	DomainURL        string        // 域名列表远程 URL（优先于本地文件）
	Refresh          time.Duration // 列表刷新间隔
	EnableCloudCheck bool          // 命中该列表后是否仍做云服务检测（默认否=跳过检测与替换）
	ECS              ECSPolicy     // 命中该列表后的 EDNS Client Subnet 策略
	IPPrefer         string        // A/AAAA 偏好档位（空值=跟随全局默认）
}

// QueryLogConfig 解析日志配置：每次客户端查询记录一行（独立 SQLite 库）
type QueryLogConfig struct {
	Enabled   bool          // 是否记录解析日志
	Retention time.Duration // 保留时长，超期自动删除
	MaxRows   int           // 最大保留条数，超出后删除最旧记录
}

// Config 配置结构体（内存表示，时长为 time.Duration）
type Config struct {
	ListenPort             int
	WebAddr                string         // Web 管理端监听地址
	Upstream               []string       // 上游DNS服务器（统一URL scheme）
	Timeout                time.Duration  // 传统协议(UDP/TCP)查询超时
	ModernTimeout          time.Duration  // 现代协议(DoH/DoT/DoH3)查询超时
	ReplaceCacheTime       time.Duration  // 云替换响应缓存时间
	MaxIPRecords           int            // 替换域名使用的最大IP数
	CNAMERecursionDepth    int            // CNAME链收集深度（仅用于云检测）
	ReplaceCFDomain        string         // Cloudflare IP 替换域名
	ReplaceAWSDomain       string         // AWS IP 替换域名
	ReplaceCFAPI           string         // CF 替换 IP 接口地址（非空时改从接口取 IP，不再解析 ReplaceCFDomain）
	ReplaceAPICount        int            // 从替换接口取前 N 条 IP（默认 1）
	BackupDNS              string         // 所有上游失败后的备用DNS
	IPPrefer               string         // 全局默认 A/AAAA 偏好档位（未命中分流列表或列表未配置时生效）
	SplitLists             []SplitList    // 域名分流列表（按顺序匹配）
	CloudflareNetFile      string         // Cloudflare IP段数据文件
	CloudflareNetFile6     string         // Cloudflare IPv6段数据文件
	AWSNetFile             string         // AWS IP段数据文件
	NetworkRefreshInterval time.Duration  // 云IP段数据文件刷新间隔
	LogLevel               string         // 日志级别：debug/info/warn/error
	LogFormat              string         // 日志格式：text/json
	Cache                  CacheConfig    // 缓存配置
	QueryLog               QueryLogConfig // 解析日志配置
	EnableCloudflareCheck  bool           // Cloudflare IP 检测与替换开关
	EnableAWSCheck         bool           // AWS IP 检测与替换开关
}

// DefaultConfig 返回内置默认配置（首次启动且数据库中无配置时使用）
func DefaultConfig() *Config {
	return &Config{
		ListenPort: 53,
		WebAddr:    DefaultWebAddr,
		Upstream: []string{
			"https://223.5.5.5/dns-query", // 阿里DNS
			"https://doh.pub/dns-query",   // 腾讯DoH
			"udp://119.29.29.29:53",       // 腾讯DNS
		},
		Timeout:             1500 * time.Millisecond,
		ModernTimeout:       1000 * time.Millisecond,
		ReplaceCacheTime:    30 * time.Minute,
		MaxIPRecords:        2,
		CNAMERecursionDepth: 1,
		ReplaceCFDomain:     "cf.blogluo.eu.org",
		ReplaceAWSDomain:    "cc.cloudfront.182682.xyz",
		ReplaceCFAPI:        "",
		ReplaceAPICount:     1,
		BackupDNS:           "udp://114.114.114.114:53",
		SplitLists: []SplitList{
			{
				Name:       "定向域名",
				Enabled:    true,
				DNS:        []string{"https://223.6.6.6/dns-query"},
				DomainFile: "./data/designated.yaml",
				DomainURL:  "https://raw.githubusercontent.com/dingdadao/cosDnaPorxy/refs/heads/master/scripts/shell/designated.yaml",
				Refresh:    30 * time.Minute,
			},
			{
				Name:       "中国域名",
				Enabled:    true,
				DNS:        []string{"udp://223.5.5.5:53"},
				DomainFile: "./data/china_domains.yaml",
				DomainURL:  "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/China/China_Domain.yaml",
				Refresh:    24 * time.Hour,
			},
		},
		CloudflareNetFile:      "./data/cf_mrs_file4.txt",
		CloudflareNetFile6:     "./data/cf_mrs_file6.txt",
		AWSNetFile:             "./data/aws.txt",
		NetworkRefreshInterval: 96 * time.Hour,
		LogLevel:               "debug",
		LogFormat:              "text",
		Cache: CacheConfig{
			MaxItems:        5000,
			TTL:             5 * time.Minute,
			MaxAsyncWorkers: 2,
		},
		QueryLog: QueryLogConfig{
			Enabled:   true,
			Retention: DefaultQueryLogRetention,
			MaxRows:   DefaultQueryLogMaxRows,
		},
		EnableCloudflareCheck: true,
		EnableAWSCheck:        false,
	}
}

// ValidateConfig 验证配置
func ValidateConfig(cfg *Config) error {
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: %d", cfg.ListenPort)
	}
	if len(cfg.Upstream) == 0 {
		return fmt.Errorf("no upstream servers configured")
	}
	if cfg.WebAddr == "" {
		cfg.WebAddr = DefaultWebAddr
	}
	if cfg.Cache.MaxItems <= 0 {
		cfg.Cache.MaxItems = 5000
	}
	if cfg.Cache.TTL <= 0 {
		cfg.Cache.TTL = 5 * time.Minute
	}
	if cfg.Cache.MaxAsyncWorkers <= 0 {
		cfg.Cache.MaxAsyncWorkers = 2
	}
	if cfg.QueryLog.Retention <= 0 {
		cfg.QueryLog.Retention = DefaultQueryLogRetention
	}
	if cfg.QueryLog.MaxRows <= 0 {
		cfg.QueryLog.MaxRows = DefaultQueryLogMaxRows
	}
	if cfg.ReplaceCFAPI != "" && !strings.HasPrefix(cfg.ReplaceCFAPI, "http://") && !strings.HasPrefix(cfg.ReplaceCFAPI, "https://") {
		return fmt.Errorf("invalid replace_cf_api: %s", cfg.ReplaceCFAPI)
	}
	if cfg.ReplaceAPICount <= 0 {
		cfg.ReplaceAPICount = 1
	}
	return nil
}
