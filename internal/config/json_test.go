package config

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestConfigJSONRoundTrip(t *testing.T) {
	// 默认配置 → JSON → 内存配置，应无任何字段丢失或变形
	orig := DefaultConfig()
	got, err := orig.ToJSON().ToConfig()
	if err != nil {
		t.Fatalf("往返转换失败: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Errorf("往返不一致:\n orig=%+v\n got =%+v", orig, got)
	}
}

func TestConfigJSONRoundTripModified(t *testing.T) {
	// 修改过的配置往返也应保持一致（含时长格式如 45m0s）
	orig := DefaultConfig()
	orig.ReplaceCacheTime = 45 * time.Minute
	orig.SplitLists[0].Refresh = 90 * time.Minute
	orig.SplitLists[0].Invert = true
	orig.SplitLists[1].EnableCloudCheck = true
	orig.SplitLists[0].ECS = ECSPolicy{Enabled: true, ISPType: ECSTypeTelecom, Subnet: "1.2.3.0/24"}
	orig.SplitLists[1].ECS = ECSPolicy{Enabled: true, ISPType: ECSTypeMobile, Subnet: "240e:1:2::"}
	orig.Cache.TTL = 123 * time.Minute
	orig.Upstream = []string{"udp://1.1.1.1:53", "h3://dns.adguard.com"}
	orig.IPPrefer = IPPreferA
	orig.SplitLists[0].IPPrefer = IPPreferOnlyA
	orig.SplitLists[1].IPPrefer = IPPreferAAAA

	got, err := orig.ToJSON().ToConfig()
	if err != nil {
		t.Fatalf("往返转换失败: %v", err)
	}
	if !reflect.DeepEqual(orig, got) {
		t.Errorf("修改后往返不一致:\n orig=%+v\n got =%+v", orig, got)
	}
}

func TestConfigJSONEmptyUpstream(t *testing.T) {
	// Upstream为空slice时往返后应为空（ValidateConfig负责报错）
	j := DefaultConfig().ToJSON()
	j.Upstream = nil
	got, err := j.ToConfig()
	if err != nil {
		t.Fatalf("转换失败: %v", err)
	}
	if len(got.Upstream) != 0 {
		t.Errorf("空upstream应保持为空: %v", got.Upstream)
	}
}

func TestConfigJSONLegacyMigration(t *testing.T) {
	// 旧版两组硬编码字段应自动迁移为两条分流列表
	raw := []byte(`{
		"listen_port": 5354,
		"upstream": ["udp://1.1.1.1:53"],
		"default_dns": "https://223.6.6.6/dns-query",
		"designated_domain": "./data/designated.yaml",
		"designated_domain_url": "https://example.com/d.yaml",
		"designated_refresh": "45m",
		"china_dns": "udp://223.5.5.5:53",
		"china_domain_file": "./data/china_domains.yaml",
		"china_domain_file_url": "",
		"china_domain_refresh": "12h",
		"enable_china_domain_check": false
	}`)

	var j ConfigJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("解析旧配置失败: %v", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("转换旧配置失败: %v", err)
	}

	if len(cfg.SplitLists) != 2 {
		t.Fatalf("应迁移出2条分流列表，实际 %d 条", len(cfg.SplitLists))
	}
	first, second := cfg.SplitLists[0], cfg.SplitLists[1]
	if first.Name != "定向域名" || !reflect.DeepEqual(first.DNS, []string{"https://223.6.6.6/dns-query"}) || !first.Enabled {
		t.Errorf("定向域名迁移结果不符: %+v", first)
	}
	if first.Refresh != 45*time.Minute {
		t.Errorf("定向域名刷新间隔应为45m，实际 %v", first.Refresh)
	}
	if first.DomainFile != "./data/designated.yaml" || first.DomainURL != "https://example.com/d.yaml" {
		t.Errorf("定向域名文件字段迁移结果不符: %+v", first)
	}
	if second.Name != "中国域名" || !reflect.DeepEqual(second.DNS, []string{"udp://223.5.5.5:53"}) || second.Enabled {
		t.Errorf("中国域名迁移结果不符: %+v", second)
	}
	if second.Refresh != 12*time.Hour {
		t.Errorf("中国域名刷新间隔应为12h，实际 %v", second.Refresh)
	}
}

func TestConfigJSONSplitListDNSCompat(t *testing.T) {
	// 分流列表 dns 字段兼容旧的单字符串写法，统一按列表处理；写回时输出数组
	raw := []byte(`{
		"listen_port": 5354,
		"upstream": ["udp://1.1.1.1:53"],
		"split_lists": [
			{"name":"旧写法","enabled":true,"dns":"udp://223.5.5.5:53","domain_file":"./data/a.yaml","refresh":"30m"},
			{"name":"新写法","enabled":true,"dns":["https://1.1.1.1/dns-query","tls://1.1.1.1:853"],"domain_file":"./data/b.yaml","refresh":"30m"},
			{"name":"空写法","enabled":true,"dns":"","domain_file":"./data/c.yaml","refresh":"30m"}
		]
	}`)

	var j ConfigJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("转换配置失败: %v", err)
	}
	if !reflect.DeepEqual(cfg.SplitLists[0].DNS, []string{"udp://223.5.5.5:53"}) {
		t.Errorf("单字符串应转为单元素列表: %v", cfg.SplitLists[0].DNS)
	}
	if !reflect.DeepEqual(cfg.SplitLists[1].DNS, []string{"https://1.1.1.1/dns-query", "tls://1.1.1.1:853"}) {
		t.Errorf("列表写法应原样保留: %v", cfg.SplitLists[1].DNS)
	}
	if len(cfg.SplitLists[2].DNS) != 0 {
		t.Errorf("空字符串应为空列表: %v", cfg.SplitLists[2].DNS)
	}

	out, err := json.Marshal(cfg.ToJSON())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(out), `"dns":["udp://223.5.5.5:53"]`) {
		t.Errorf("写回应统一为数组形式: %s", out)
	}
}

func TestConfigJSONMissingInvertDefaultsOff(t *testing.T) {
	// 无 invert 字段的老配置应解析为正序匹配，行为与升级前一致；显式 true 应往返保留
	raw := []byte(`{
		"listen_port": 5354,
		"upstream": ["udp://1.1.1.1:53"],
		"split_lists": [
			{"name":"老配置","enabled":true,"dns":["udp://223.5.5.5:53"],"domain_file":"./data/a.yaml","refresh":"30m"},
			{"name":"取反","enabled":true,"invert":true,"dns":["udp://223.5.5.5:53"],"domain_file":"./data/b.yaml","refresh":"30m"}
		]
	}`)

	var j ConfigJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("转换配置失败: %v", err)
	}
	if cfg.SplitLists[0].Invert {
		t.Errorf("缺省 invert 应为 false: %+v", cfg.SplitLists[0])
	}
	if !cfg.SplitLists[1].Invert {
		t.Errorf("显式 invert=true 应保留: %+v", cfg.SplitLists[1])
	}

	out, err := json.Marshal(cfg.ToJSON())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(out), `"invert":true`) {
		t.Errorf("写回应含 invert 字段: %s", out)
	}
}

// A/AAAA 偏好档位：非法取值必须在 JSON→内存 边界被拒绝；合法取值与缺省（不干预）正常通过
func TestConfigJSONIPPreferValidation(t *testing.T) {
	base := func(listPrefer, globalPrefer string) []byte {
		return []byte(`{
			"listen_port": 5354,
			"upstream": ["udp://1.1.1.1:53"],
			"ip_prefer": "` + globalPrefer + `",
			"split_lists": [
				{"name":"测试","enabled":true,"dns":["udp://223.5.5.5:53"],"domain_file":"./data/a.yaml","refresh":"30m","ip_prefer":"` + listPrefer + `"}
			]
		}`)
	}

	for name, raw := range map[string][]byte{
		"列表档位非法": base("prefer_ipv4", ""),
		"全局档位非法": base("", "only_aaaa"),
	} {
		var j ConfigJSON
		if err := json.Unmarshal(raw, &j); err != nil {
			t.Fatalf("%s: 解析配置失败: %v", name, err)
		}
		if _, err := j.ToConfig(); err == nil {
			t.Errorf("%s: 应返回错误", name)
		}
	}

	// 缺省（空）与四种合法取值均应通过，且往返保持
	for _, prefer := range []string{"", IPPreferA, IPPreferAAAA, IPPreferOnlyA} {
		var j ConfigJSON
		if err := json.Unmarshal(base(prefer, prefer), &j); err != nil {
			t.Fatalf("解析配置失败: %v", err)
		}
		cfg, err := j.ToConfig()
		if err != nil {
			t.Fatalf("档位 %q 应合法，实际报错: %v", prefer, err)
		}
		if cfg.IPPrefer != prefer || cfg.SplitLists[0].IPPrefer != prefer {
			t.Errorf("档位 %q 往返丢失: global=%q list=%q", prefer, cfg.IPPrefer, cfg.SplitLists[0].IPPrefer)
		}
	}
}

// CF 替换接口：字段往返保持；非法 URL 被 ValidateConfig 拒绝；条数缺省兜底为 1
func TestConfigJSONReplaceCFAPIRoundTrip(t *testing.T) {
	orig := DefaultConfig()
	orig.ReplaceCFAPI = "https://cf.niao.fun/api/results?select=cm"
	orig.ReplaceAPICount = 2

	got, err := orig.ToJSON().ToConfig()
	if err != nil {
		t.Fatalf("往返转换失败: %v", err)
	}
	if got.ReplaceCFAPI != orig.ReplaceCFAPI || got.ReplaceAPICount != 2 {
		t.Errorf("接口字段往返丢失: api=%q count=%d", got.ReplaceCFAPI, got.ReplaceAPICount)
	}

	got.ReplaceCFAPI = "cf.niao.fun/api/results"
	if err := ValidateConfig(got); err == nil {
		t.Error("缺少 http(s):// 前缀的接口地址应被拒绝")
	}

	got.ReplaceCFAPI = ""
	got.ReplaceAPICount = 0
	if err := ValidateConfig(got); err != nil {
		t.Fatalf("接口留空应合法: %v", err)
	}
	if got.ReplaceAPICount != 1 {
		t.Errorf("条数缺省应兜底为 1，实际 %d", got.ReplaceAPICount)
	}
}

func TestConfigJSONMissingECSDefaultsOff(t *testing.T) {
	// 无 ecs 字段的老配置应解析为“关闭且不注入”，行为与升级前一致
	raw := []byte(`{
		"listen_port": 5354,
		"upstream": ["udp://1.1.1.1:53"],
		"split_lists": [
			{"name":"老配置","enabled":true,"dns":["udp://223.5.5.5:53"],"domain_file":"./data/a.yaml","refresh":"30m"}
		]
	}`)

	var j ConfigJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("转换配置失败: %v", err)
	}
	if cfg.SplitLists[0].ECS.Enabled {
		t.Errorf("缺省 ecs 应为关闭: %+v", cfg.SplitLists[0].ECS)
	}
	if _, ok := cfg.SplitLists[0].ECS.Resolve(); ok {
		t.Error("缺省 ecs 不应注入")
	}
}
