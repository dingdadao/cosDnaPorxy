package config

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// legacyJSON 构造一份「旧版」配置 JSON：带 client_groups、无 isp_groups/custom_groups
func legacyJSON(t *testing.T, raw string) *ConfigJSON {
	t.Helper()
	var j ConfigJSON
	if err := json.Unmarshal([]byte(raw), &j); err != nil {
		t.Fatalf("解析旧配置失败: %v", err)
	}
	return &j
}

// 旧版 client_groups 迁移：isp:<name> → 运营商固定分组，纯 IP/CIDR → 自定义分组
func TestMigrateLegacyClientGroups(t *testing.T) {
	j := legacyJSON(t, `{
		"listen_port": 15353,
		"upstream": ["udp://223.5.5.5:53"],
		"china_dns": "udp://223.5.5.5:53",
		"china_domain_file": "./data/china.yaml",
		"enable_china_domain_check": true,
		"client_groups": [
			{"name":"电信用户","enabled":true,"priority":5,"match":["isp:telecom"],
			 "dns":["udp://223.5.5.5:53"],"dns_mode":"race"},
			{"name":"移动用户","enabled":true,"priority":3,"match":["isp:mobile"],
			 "dns":["udp://211.136.192.6:53"],"dns_mode":"failover"},
			{"name":"机房出口","enabled":true,"priority":9,"match":["10.0.0.0/8","2001:db8::/32"],
			 "dns":["udp://1.1.1.1:53"]},
			{"name":"混合","enabled":true,"priority":1,"match":["isp:unicom","192.168.0.0/16"],
			 "dns":["udp://100.10.10.10:53"]},
			{"name":"取反组","enabled":true,"priority":0,"match":["isp:cmcc"],"invert":true,
			 "dns":["udp://120.196.165.24:53"]},
			{"name":"已停用","enabled":false,"priority":0,"match":["isp:cmcc"],"dns":["udp://1.1.1.1:53"]}
		]
	}`)

	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}

	// 运营商分组：telecom / cmcc（mobile 别名） / unicom，按出现顺序，各组保留自定义 DNS
	if len(cfg.ISPGroups) != 3 {
		t.Fatalf("运营商分组数量 = %d，期望 3: %+v", len(cfg.ISPGroups), cfg.ISPGroups)
	}
	got := []ISPKey{cfg.ISPGroups[0].ISP, cfg.ISPGroups[1].ISP, cfg.ISPGroups[2].ISP}
	want := []ISPKey{ISPGroupTelecom, ISPGroupCMCC, ISPGroupUnicom}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("运营商分组[%d] = %q，期望 %q", i, got[i], want[i])
		}
	}
	if !slices.Equal(cfg.ISPGroups[0].FallbackDNS, []string{"udp://223.5.5.5:53"}) {
		t.Errorf("迁移后的运营商分组应保留兜底 DNS，得到 %v", cfg.ISPGroups[0].FallbackDNS)
	}
	if cfg.ISPGroups[1].DNSMode != "failover" {
		t.Errorf("mobile 别名应归入 cmcc 并保留 dns_mode，得到 %+v", cfg.ISPGroups[1])
	}

	// 自定义分组：机房出口（纯网段） + 混合（取其中纯网段部分）
	if len(cfg.CustomGroups) != 2 {
		t.Fatalf("自定义分组数量 = %d，期望 2: %+v", len(cfg.CustomGroups), cfg.CustomGroups)
	}
	if cfg.CustomGroups[0].Name != "机房出口" || cfg.CustomGroups[0].Priority != 9 {
		t.Errorf("自定义分组[0] 异常: %+v", cfg.CustomGroups[0])
	}
	if len(cfg.CustomGroups[0].Match) != 2 {
		t.Errorf("机房出口应保留两个网段，得到 %v", cfg.CustomGroups[0].Match)
	}
	if cfg.CustomGroups[1].Name != "混合" || len(cfg.CustomGroups[1].Match) != 1 ||
		cfg.CustomGroups[1].Match[0] != "192.168.0.0/16" {
		t.Errorf("混合组应只保留纯网段匹配项: %+v", cfg.CustomGroups[1])
	}

	// 旧字段不得回写
	out := cfg.ToJSON()
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if jsonHas(raw, "client_groups") {
		t.Error("新版序列化不应再输出 client_groups")
	}
	if !jsonHas(raw, "isp_groups") || !jsonHas(raw, "custom_groups") {
		t.Error("新版序列化应输出 isp_groups / custom_groups")
	}
}

// 新版字段存在时忽略旧字段，避免新旧并存互相覆盖
func TestLegacyClientGroupsIgnoredWhenNewPresent(t *testing.T) {
	j := legacyJSON(t, `{
		"listen_port": 15353,
		"upstream": ["udp://223.5.5.5:53"],
		"split_lists": [{"name":"默认","enabled":true,"dns":["udp://223.5.5.5:53"],"domain_file":"./data/a.yaml","refresh":"1h"}],
		"isp_groups": [{"isp":"other","enabled":true,"split_refs":["默认"],"fallback_dns":["udp://1.1.1.1:53"]}],
		"client_groups": [{"name":"旧分组","enabled":true,"match":["isp:telecom"],"dns":["udp://9.9.9.9:53"]}]
	}`)

	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}
	if len(cfg.ISPGroups) != 1 || cfg.ISPGroups[0].ISP != ISPGroupOther {
		t.Fatalf("应以新版 isp_groups 为准，得到 %+v", cfg.ISPGroups)
	}
	if len(cfg.CustomGroups) != 0 {
		t.Fatalf("不应从旧字段迁移出自定义分组，得到 %+v", cfg.CustomGroups)
	}
}

// 迁移不依赖全局分流列表：只要旧分组有 DNS 即迁移为运营商分组
func TestLegacyClientGroupsMigratesWithoutLists(t *testing.T) {
	j := legacyJSON(t, `{
		"listen_port": 15353,
		"upstream": ["udp://223.5.5.5:53"],
		"client_groups": [{"name":"旧分组","enabled":true,"match":["isp:telecom"],"dns":["udp://9.9.9.9:53"]}]
	}`)

	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}
	if len(cfg.ISPGroups) != 1 || cfg.ISPGroups[0].ISP != ISPGroupTelecom {
		t.Fatalf("无分流列表时也应迁移运营商分组，得到 %+v", cfg.ISPGroups)
	}
}

// 旧配置没有 source_* 字段时按默认启用运营商识别（否则升级后分组会静默失效）
func TestLegacyConfigEnablesSourceRecognition(t *testing.T) {
	def := DefaultConfig()

	j := legacyJSON(t, `{"listen_port": 15353, "upstream": ["udp://223.5.5.5:53"]}`)
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}
	if !cfg.SourceEnabled || cfg.SourceDBDir != def.SourceDBDir ||
		cfg.SourceBaseURL != def.SourceBaseURL || cfg.SourceUpdateHours != def.SourceUpdateHours {
		t.Fatalf("旧配置应回填 source_* 默认值，得到 %+v", cfg)
	}

	// 新版配置显式关闭时必须尊重用户选择
	j = legacyJSON(t, `{"listen_port": 15353, "upstream": ["udp://223.5.5.5:53"],
		"source_enabled": false, "source_db_dir": "./data/ispdb", "source_base_url": "https://ispip.clang.cn",
		"source_update_hours": 0}`)
	cfg, err = j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}
	if cfg.SourceEnabled {
		t.Fatal("显式关闭运营商识别不应被默认值覆盖")
	}
}

// 分组级云替换覆写：字段双向往返一致，序列化字段名为 cloud_replace
func TestGroupCloudReplaceRoundTrip(t *testing.T) {
	orig := DefaultConfig()
	orig.ISPGroups = []ISPGroup{{
		ISP: ISPGroupCMCC, Enabled: true, FallbackDNS: []string{"udp://223.5.5.5:53"},
		CloudReplace: CloudReplacePolicy{
			Override: true, CFDomain: "cm.cf.example", AWSDomain: "cm.aws.example",
			CFAPI: "https://cm.example/api?select=cm", APICount: 3,
		},
	}}
	orig.CustomGroups = []CustomGroup{{
		Name: "机房", Enabled: true, Priority: 1, Match: []string{"10.0.0.0/8"},
		FallbackDNS:  []string{"udp://1.1.1.1:53"},
		CloudReplace: CloudReplacePolicy{Override: true, CFDomain: "idc.cf.example", APICount: 2},
	}}

	got, err := orig.ToJSON().ToConfig()
	if err != nil {
		t.Fatalf("往返转换失败: %v", err)
	}
	if !reflect.DeepEqual(got.ISPGroups[0].CloudReplace, orig.ISPGroups[0].CloudReplace) {
		t.Errorf("ISP 组云替换往返不一致:\n orig=%+v\n got =%+v", orig.ISPGroups[0].CloudReplace, got.ISPGroups[0].CloudReplace)
	}
	if !reflect.DeepEqual(got.CustomGroups[0].CloudReplace, orig.CustomGroups[0].CloudReplace) {
		t.Errorf("自定义组云替换往返不一致:\n orig=%+v\n got =%+v", orig.CustomGroups[0].CloudReplace, got.CustomGroups[0].CloudReplace)
	}

	raw, err := json.Marshal(orig.ToJSON())
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(raw), `"cloud_replace":{"override":true`) {
		t.Errorf("序列化应输出 cloud_replace.override 字段: %s", raw)
	}
}

// 缺省（无 cloud_replace）应解析为零值＝不覆写，旧配置行为不变
func TestGroupCloudReplaceDefaultsOff(t *testing.T) {
	raw := []byte(`{
		"listen_port": 15353,
		"upstream": ["udp://223.5.5.5:53"],
		"isp_groups": [{"isp":"cmcc","enabled":true,"fallback_dns":["udp://223.5.5.5:53"]}],
		"custom_groups": [{"name":"机房","enabled":true,"match":["10.0.0.0/8"],"fallback_dns":["udp://1.1.1.1:53"]}]
	}`)

	var j ConfigJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatalf("解析配置失败: %v", err)
	}
	cfg, err := j.ToConfig()
	if err != nil {
		t.Fatalf("ToConfig 失败: %v", err)
	}
	if cfg.ISPGroups[0].CloudReplace.Override || cfg.CustomGroups[0].CloudReplace.Override {
		t.Fatalf("缺省云替换应为不覆写: isp=%+v custom=%+v", cfg.ISPGroups[0].CloudReplace, cfg.CustomGroups[0].CloudReplace)
	}
}

// 分组云替换校验：api_count 归一化、接口地址前缀校验、覆写空值放行
func TestGroupCloudReplaceValidation(t *testing.T) {
	base := func(cr CloudReplacePolicy) *Config {
		cfg := DefaultConfig()
		cfg.ISPGroups = []ISPGroup{{
			ISP: ISPGroupCMCC, Enabled: true, FallbackDNS: []string{"udp://223.5.5.5:53"}, CloudReplace: cr,
		}}
		return cfg
	}

	// 覆写但只填域名：合法，且 api_count 缺省兜底为 1
	cfg := base(CloudReplacePolicy{Override: true, CFDomain: " cm.cf.example "})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("覆写仅填域名应合法: %v", err)
	}
	if cfg.ISPGroups[0].CloudReplace.APICount != 1 {
		t.Errorf("api_count 缺省应兜底为 1，实际 %d", cfg.ISPGroups[0].CloudReplace.APICount)
	}
	if cfg.ISPGroups[0].CloudReplace.CFDomain != "cm.cf.example" {
		t.Errorf("域名应被 trim，实际 %q", cfg.ISPGroups[0].CloudReplace.CFDomain)
	}

	// 接口缺 http(s):// 前缀：拒绝
	if err := ValidateConfig(base(CloudReplacePolicy{Override: true, CFAPI: "cm.example/api"})); err == nil {
		t.Error("分组接口地址缺少 http(s):// 前缀应被拒绝")
	}

	// 合法接口：通过
	cfg = base(CloudReplacePolicy{Override: true, CFAPI: "https://cm.example/api?select=cm", APICount: 3})
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("合法接口应通过: %v", err)
	}
	if cfg.ISPGroups[0].CloudReplace.APICount != 3 {
		t.Errorf("显式条数应保留，实际 %d", cfg.ISPGroups[0].CloudReplace.APICount)
	}
}

func jsonHas(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
