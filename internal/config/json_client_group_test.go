package config

import (
	"encoding/json"
	"slices"
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

func jsonHas(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}
