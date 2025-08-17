package dns

import (
	"encoding/csv"
	"encoding/json"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 常量定义
const (
	CFType  = 1
	AWSType = 2
)

// DesignatedDomain 定向域名配置
// UpstreamType: "cn_upstream"/"not_cn_upstream"/""(具体IP)
type DesignatedDomain struct {
	Domain       string
	DNS          string
	Regex        interface{} // *regexp.Regexp
	UpstreamType string      // "cn_upstream"/"not_cn_upstream"/""
}

// ServerHealth DNS服务器健康状态
type ServerHealth struct {
	LastCheck    time.Time
	IsHealthy    bool
	Latency      time.Duration
	FailureCount int
	SuccessCount int
	sync.RWMutex
}

// AWSIPRanges AWS IP范围结构
type AWSIPRanges struct {
	Prefixes     []AWSPrefix `json:"prefixes"`
	IPv6Prefixes []AWSPrefix `json:"ipv6_prefixes"`
}

// AWSPrefix AWS前缀结构
type AWSPrefix struct {
	IPPrefix   string `json:"ip_prefix,omitempty"`
	IPv6Prefix string `json:"ipv6_prefix,omitempty"`
	Service    string `json:"service"`
	Region     string `json:"region"`
}

// NetIPX IP前缀集合
type NetIPX struct {
	sync.RWMutex
	list []netip.Prefix
}

// AddPrefix 添加前缀
func (n *NetIPX) AddPrefix(p netip.Prefix) {
	n.list = append(n.list, p)
}

// Contains 检查IP是否在集合中
func (n *NetIPX) Contains(ip netip.Addr) bool {
	n.RLock()
	defer n.RUnlock()
	for _, p := range n.list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// LoadFromFile 从文件加载IP前缀
func (n *NetIPX) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	var prefixes []netip.Prefix
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err == nil {
			prefixes = append(prefixes, p)
		}
	}

	n.Lock()
	n.list = prefixes
	n.Unlock()
	return nil
}

// LoadAWSIPRanges 加载AWS IP范围
func LoadAWSIPRanges(path string, set4, set6 *NetIPX) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var ranges AWSIPRanges
	if err := json.Unmarshal(data, &ranges); err != nil {
		return err
	}

	for _, p := range ranges.Prefixes {
		if p.IPPrefix == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p.IPPrefix)
		if err != nil {
			continue
		}
		set4.AddPrefix(prefix)
	}

	for _, p := range ranges.IPv6Prefixes {
		if p.IPv6Prefix == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p.IPv6Prefix)
		if err != nil {
			continue
		}
		set6.AddPrefix(prefix)
	}

	return nil
}

// 域名标签结构体
// Tag: 标签（如designated, cn, not_cn, cloudflare, aws, unknown等）
// Upstream: 分流策略
// Updated: 更新时间戳
type DomainTag struct {
	Tag      string
	Upstream string
	Updated  int64
}

// 标签系统全局变量
var (
	TagMapSimple   = make(map[string]*DomainTag) // 域名->标签
	TagDirtySimple = make(map[string]struct{})
	TagMapMu       sync.RWMutex // 添加互斥锁保护
	maxTagMapSize  = 100000     // 限制标签map最大大小
	
	// 旧的标签系统变量（保持向后兼容）
	TagMap   = make(map[string]*DomainTag) // 域名->标签
	TagDirty = make(map[string]struct{})   // 本次运行新增/变更的域名
)

// 极简标签常量
const (
	TAG_UNKNOWN   = 0
	TAG_DINGXIANG = 1
	TAG_CN        = 2
	TAG_NOT_CN    = 3
	TAG_CF        = 4
	TAG_AWS       = 5
	TAG_WHITELIST = 6
)

const (
	tagSimpleCSVFile    = "data/domain_tags_simple.csv"
	tagSimpleFlushBatch = 1
)

// 冷加载极简标签
func LoadDomainTagsSimple() error {
	f, err := os.Open(tagSimpleCSVFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	for _, rec := range records {
		if len(rec) < 2 {
			continue
		}
		tag := TAG_UNKNOWN
		if v, err := strconv.Atoi(rec[1]); err == nil {
			tag = v
		}
		TagMapSimple[rec[0]] = &DomainTag{Tag: rec[0], Upstream: strconv.Itoa(tag), Updated: time.Now().Unix()}
	}
	return nil
}

// 追加标签并标记为dirty
func AddOrUpdateDomainTagSimple(domain string, tag int) {
	TagMapMu.Lock()
	defer TagMapMu.Unlock()
	
	// 检查map大小，如果超过限制则清理旧数据
	if len(TagMapSimple) >= maxTagMapSize {
		// 清理最旧的1000个标签
		cleanupOldTags(1000)
	}
	
	TagMapSimple[domain] = &DomainTag{
		Tag:      strconv.Itoa(tag),
		Upstream: strconv.Itoa(tag),
		Updated:  time.Now().Unix(),
	}
	TagDirtySimple[domain] = struct{}{}
	if len(TagDirtySimple) >= tagSimpleFlushBatch {
		go FlushDomainTagsSimpleToFile()
	}
}

// 清理旧标签
func cleanupOldTags(count int) {
	// 简单的清理策略：随机删除一些标签
	deleted := 0
	for domain := range TagMapSimple {
		if deleted >= count {
			break
		}
		delete(TagMapSimple, domain)
		delete(TagDirtySimple, domain)
		deleted++
	}
}

// 批量写入并释放map
func FlushDomainTagsSimpleToFile() {
	TagMapMu.Lock()
	defer TagMapMu.Unlock()
	
	if len(TagDirtySimple) == 0 {
		return
	}
	
	// 先读出原有数据，合并写回
	existing := make(map[string]string)
	if f, err := os.Open(tagSimpleCSVFile); err == nil {
		reader := csv.NewReader(f)
		records, _ := reader.ReadAll()
		for _, rec := range records {
			if len(rec) < 2 {
				continue
			}
			existing[rec[0]] = rec[1]
		}
		f.Close()
	}
	
	// 更新dirty部分
	for domain := range TagDirtySimple {
		tag := TagMapSimple[domain]
		existing[domain] = tag.Tag // 写入Tag字段
	}
	
	// 写回全部
	f, err := os.Create(tagSimpleCSVFile)
	if err != nil {
		return
	}
	writer := csv.NewWriter(f)
	for domain, tag := range existing {
		_ = writer.Write([]string{domain, tag})
	}
	writer.Flush()
	f.Close()
	
	// 清空dirty map，但保留TagMapSimple中的数据
	TagDirtySimple = make(map[string]struct{})
}
