package dns

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"
)

// 常量定义
const (
	CFType = 1
	AWSType = 2
)

// DesignatedDomain 定向域名配置
type DesignatedDomain struct {
	Domain string
	DNS    string
	Regex  interface{} // *regexp.Regexp
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