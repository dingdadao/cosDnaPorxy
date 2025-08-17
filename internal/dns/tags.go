package dns

import (
	"encoding/csv"
	"os"
	"time"
)

// 标签系统相关常量
const (
	tagCSVFile    = "data/domain_tags.csv"
	tagFlushBatch = 200
)

// 冷加载标签系统
func LoadDomainTags() error {
	f, err := os.Open(tagCSVFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // 文件不存在视为无标签
		}
		return err
	}
	defer f.Close()
	reader := csv.NewReader(f)
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}
	TagMapMu.Lock()
	defer TagMapMu.Unlock()
	for _, rec := range records {
		if len(rec) < 3 {
			continue
		}
		TagMap[rec[0]] = &DomainTag{
			Tag:      rec[1],
			Upstream: rec[2],
			Updated:  time.Now().Unix(),
		}
	}
	return nil
}

// 查询标签系统
func QueryDomainTag(domain string) (*DomainTag, bool) {
	TagMapMu.RLock()
	tag, ok := TagMap[domain]
	TagMapMu.RUnlock()
	return tag, ok
}

// 追加标签并标记为dirty
func AddOrUpdateDomainTag(domain, tag, upstream string) {
	TagMapMu.Lock()
	TagMap[domain] = &DomainTag{
		Tag:      tag,
		Upstream: upstream,
		Updated:  time.Now().Unix(),
	}
	TagDirty[domain] = struct{}{}
	TagMapMu.Unlock()
	// 异步批量写入
	if len(TagDirty) >= tagFlushBatch {
		go FlushDomainTagsToFile()
	}
}

// 异步批量写入标签到CSV
func FlushDomainTagsToFile() {
	TagMapMu.Lock()
	defer TagMapMu.Unlock()
	if len(TagDirty) == 0 {
		return
	}
	// 先读出原有数据，合并写回
	existing := make(map[string][]string)
	if f, err := os.Open(tagCSVFile); err == nil {
		reader := csv.NewReader(f)
		records, _ := reader.ReadAll()
		for _, rec := range records {
			if len(rec) < 3 {
				continue
			}
			existing[rec[0]] = rec
		}
		f.Close()
	}
	// 更新dirty部分
	for domain := range TagDirty {
		tag := TagMap[domain]
		existing[domain] = []string{domain, tag.Tag, tag.Upstream}
	}
	// 写回全部
	f, err := os.Create(tagCSVFile)
	if err != nil {
		return
	}
	writer := csv.NewWriter(f)
	for _, rec := range existing {
		_ = writer.Write(rec)
	}
	writer.Flush()
	f.Close()
	// 清空dirty
	TagDirty = make(map[string]struct{})
} 