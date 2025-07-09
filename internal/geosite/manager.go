package geosite

import (
	"cosDnaPorxy/v2ray.com/core/common/protocol"
	"google.golang.org/protobuf/proto"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Manager geosite 加载缓存结构（带锁）
type Manager struct {
	sync.RWMutex
	lastUpdate time.Time
	data       *protocol.GeoSiteList
	url        string
	refresh    time.Duration
	client     *http.Client
}

// NewManager 创建新的Geosite管理器
func NewManager(url string, gtime string) (*Manager, error) {
	refreshDur, err := time.ParseDuration(gtime)
	if err != nil {
		return nil, err
	}

	return &Manager{
		url:     url,
		refresh: refreshDur,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

// UpdateGeoSite 更新Geosite数据
func (g *Manager) UpdateGeoSite() {
	const cacheFile = "./data/geosite.dat"

	// 先尝试从本地文件加载
	data, err := os.ReadFile(cacheFile)
	if err == nil {
		list := &protocol.GeoSiteList{}
		if err := proto.Unmarshal(data, list); err == nil {
			g.Lock()
			g.data = list
			g.lastUpdate = time.Now()
			g.Unlock()
			log.Printf("[geosite] 从本地缓存加载成功，标签数: %d", len(list.Entry))
			return
		}
		log.Printf("[geosite] 本地缓存文件解码失败: %v", err)
	} else {
		log.Printf("[geosite] 本地缓存文件不存在或读取失败: %v", err)
	}

	// 本地加载失败，则尝试网络下载
	resp, err := g.client.Get(g.url)
	if err != nil {
		log.Printf("[geosite] 下载失败: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[geosite] 读取响应失败: %v", err)
		return
	}

	list := &protocol.GeoSiteList{}
	if err := proto.Unmarshal(body, list); err != nil {
		log.Printf("[geosite] 远程数据解码失败: %v", err)
		return
	}

	// 下载成功才写本地缓存
	if err := os.WriteFile(cacheFile, body, 0644); err != nil {
		log.Printf("[geosite] 本地缓存保存失败: %v", err)
	}

	g.Lock()
	g.data = list
	g.lastUpdate = time.Now()
	g.Unlock()

	log.Printf("[geosite] 成功下载并更新 geosite.dat，标签数: %d", len(list.Entry))
}

// CheckDomainInTag 检查域名是否在指定标签中
func (g *Manager) CheckDomainInTag(domain, tag string) bool {
	g.RLock()
	defer g.RUnlock()

	if g.data == nil {
		log.Println("[geosite] data为空")
		return false
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	tag = strings.ToLower(tag)

	for _, entry := range g.data.Entry {
		if strings.ToLower(entry.CountryCode) != tag {
			continue
		}
		
		// 检查该国家/地区的所有域名规则
		for _, rule := range entry.Domain {
			ruleVal := strings.ToLower(rule.Value)
			matched := false
			
			switch rule.Type {
			case protocol.Domain_Plain:
				// 完全匹配
				matched = domain == ruleVal

			case protocol.Domain_Domain:
				// domain == rule 或 .rule 结尾
				matched = domain == ruleVal || strings.HasSuffix(domain, "."+ruleVal)

			case protocol.Domain_RootDomain:
				// DOMAIN-SUFFIX: 后缀匹配
				matched = strings.HasSuffix(domain, ruleVal)

			case protocol.Domain_Regex:
				// 正则匹配
				var err error
				matched, err = regexp.MatchString(ruleVal, domain)
				if err != nil {
					log.Printf("[geosite] 正则匹配错误: %s -> %s: %v", domain, ruleVal, err)
					continue
				}

			default:
				log.Printf("[geosite] 未知的域名类型: %d", rule.Type)
				continue
			}
			
			// 如果匹配成功，立即返回
			if matched {
				log.Printf("[geosite] 域名匹配成功: %s -> %s (类型: %d)", domain, ruleVal, rule.Type)
				return true
			}
		}
	}
	
	log.Printf("[geosite] 域名未匹配: %s (标签: %s)", domain, tag)
	return false
}

// GetRefreshDuration 获取刷新间隔
func (g *Manager) GetRefreshDuration() time.Duration {
	return g.refresh
} 