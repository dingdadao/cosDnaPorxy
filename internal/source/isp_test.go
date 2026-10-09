package source

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s).Masked() }

// 建一个含常见段+嵌套前缀的库，覆盖最长前缀（/16 与 /24 同时存在）
func sampleDB() *DB {
	d := New()
	s := &snapshot{v4: newTrie(), v6: newTrie()}
	insertPrefix(s, mustPrefix("1.0.0.0/16"), ISPUnicom)  // /16
	insertPrefix(s, mustPrefix("1.0.0.0/24"), ISPTelecom) // 更长 → 应覆盖 /16
	insertPrefix(s, mustPrefix("2.0.0.0/8"), ISPCMCC)
	// IPv6
	insertPrefix(s, mustPrefix("2001:0000::/32"), ISPTelecom)
	insertPrefix(s, mustPrefix("2400:0000::/12"), ISPCMCC)
	d.ptr.Store(s)
	return d
}

func TestLookupV4LongestPrefix(t *testing.T) {
	d := sampleDB()
	cases := []struct {
		ip  string
		isp ISP
	}{
		{"1.0.0.1", ISPTelecom}, // 命中更长 /24
		{"1.0.1.1", ISPUnicom},  // 只命中 /16
		{"2.1.1.1", ISPCMCC},    // /8
		{"3.3.3.3", ISPOther},   // 无段 → false
	}
	for _, c := range cases {
		got, ok := d.Lookup(netip.MustParseAddr(c.ip))
		if c.isp == ISPOther {
			if ok {
				t.Errorf("Lookup(%s) 期望未命中，得到 %s ok=true", c.ip, got)
			}
			continue
		}
		if !ok || got != c.isp {
			t.Errorf("Lookup(%s) = %v(ok=%v), 期望 %v", c.ip, got, ok, c.isp)
		}
	}
}

func TestLookupV6(t *testing.T) {
	d := sampleDB()
	cases := []struct {
		ip  string
		isp ISP
	}{
		{"2001:0000::1", ISPTelecom},
		{"2400:0001::1", ISPCMCC},
		{"2606:4700::1111", ISPOther}, // Cloudflare，不在段内
	}
	for _, c := range cases {
		got, ok := d.Lookup(netip.MustParseAddr(c.ip))
		if c.isp == ISPOther {
			if ok {
				t.Errorf("Lookup(%s) 期望未命中，得到 %s", c.ip, got)
			}
			continue
		}
		if !ok || got != c.isp {
			t.Errorf("Lookup(%s) = %v(ok=%v), 期望 %v", c.ip, got, ok, c.isp)
		}
	}
}

// 嵌套前缀覆盖：后插入更宽的前缀不应覆盖已插入的更窄前缀（最长优先）
func TestLongestPrefixWinsRegardlessOfOrder(t *testing.T) {
	d := New()
	s := &snapshot{v4: newTrie(), v6: newTrie()}
	insertPrefix(s, mustPrefix("10.0.0.0/24"), ISPTelecom)
	insertPrefix(s, mustPrefix("10.0.0.0/16"), ISPCMCC) // 更宽，后插
	d.ptr.Store(s)
	if got, ok := d.Lookup(netip.MustParseAddr("10.0.0.1")); !ok || got != ISPTelecom {
		t.Errorf("10.0.0.1 应命中更窄 /24=Telecom，得到 %v(ok=%v)", got, ok)
	}
	if got, ok := d.Lookup(netip.MustParseAddr("10.0.5.1")); !ok || got != ISPCMCC {
		t.Errorf("10.0.5.1 应命中 /16=CMCC，得到 %v(ok=%v)", got, ok)
	}
}

func TestParseISP(t *testing.T) {
	okCases := map[string]ISP{
		"telecom": ISPTelecom, "chinatelecom": ISPTelecom, "电信": ISPTelecom,
		"unicom": ISPUnicom, "cmcc": ISPCMCC, "mobile": ISPCMCC,
		"cernet": ISPCernet, "chinabtn": ISPChinabtn, "gwbn": ISPGWBN,
		"other": ISPOther,
	}
	for in, want := range okCases {
		got, ok := ParseISP(in)
		if !ok || got != want {
			t.Errorf("ParseISP(%q) = %v(ok=%v), 期望 %v", in, got, ok, want)
		}
	}
	if _, ok := ParseISP("xxx"); ok {
		t.Error("未知运营商应 ok=false")
	}
}

func TestLoadFromDir(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("chinatelecom.txt", "# 电信\n1.0.0.0/24\nbad-line\n2001:0000::/32\n\n")
	write("cmcc.txt", "2.0.0.0/8\n2400:0000::/12\n")
	write("all_cn.txt", "3.0.0.0/8\n") // 应被忽略

	db, err := LoadFromDir(dir)
	if err != nil {
		t.Fatalf("LoadFromDir err: %v", err)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("1.0.0.1")); !ok || got != ISPTelecom {
		t.Errorf("1.0.0.1 期望 telecom，得到 %v(ok=%v)", got, ok)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("2001::1")); !ok || got != ISPTelecom {
		t.Errorf("2001::1 期望 telecom，得到 %v(ok=%v)", got, ok)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("2.0.0.1")); !ok || got != ISPCMCC {
		t.Errorf("2.0.0.1 期望 cmcc，得到 %v(ok=%v)", got, ok)
	}
	// all_cn 被忽略：3.0.0.1 应未命中
	if _, ok := db.Lookup(netip.MustParseAddr("3.0.0.1")); ok {
		t.Error("all_cn 不应被加载，3.0.0.1 不应命中")
	}
}

func TestReloadFromDirSwapsAtomically(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "cmcc.txt"), []byte("1.0.0.0/8\n"), 0o644)
	db, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// 换数据后，同一 DB 实例能看到新库
	os.WriteFile(filepath.Join(dir, "cmcc.txt"), []byte("1.0.0.0/8\n2.0.0.0/8\n"), 0o644)
	if err := ReloadFromDir(db, dir); err != nil {
		t.Fatal(err)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("2.0.0.1")); !ok || got != ISPCMCC {
		t.Errorf("reload 后 2.0.0.1 期望 cmcc，得到 %v(ok=%v)", got, ok)
	}
}
