package source

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestRefreshDownloadsAndReloads(t *testing.T) {
	// 上游提供 cmcc 与 chinatelecom，其余 404（应跳过不影响）
	files := map[string]string{
		"cmcc_ipv46.txt":         "5.0.0.0/8\n240e:0000::/20\n",
		"chinatelecom_ipv46.txt": "1.0.1.0/24\n",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		content, ok := files[r.URL.Path[1:]]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(content))
	}))
	defer srv.Close()

	dir := t.TempDir()
	db := New()
	r := &HTTPRepository{BaseURL: srv.URL, Dir: dir}

	n, err := r.Refresh(db)
	if err != nil {
		t.Fatalf("Refresh err: %v", err)
	}
	if n != 2 {
		t.Errorf("期望更新 2 个文件，得到 %d", n)
	}
	// 下载内容已落盘并生效
	if got, ok := db.Lookup(netip.MustParseAddr("1.0.1.1")); !ok || got != ISPTelecom {
		t.Errorf("1.0.1.1 期望 telecom，得到 %v(ok=%v)", got, ok)
	}
	if got, ok := db.Lookup(netip.MustParseAddr("5.0.0.1")); !ok || got != ISPCMCC {
		t.Errorf("5.0.0.1 期望 cmcc，得到 %v(ok=%v)", got, ok)
	}
	// v6
	if got, ok := db.Lookup(netip.MustParseAddr("240e::1")); !ok || got != ISPCMCC {
		t.Errorf("240e::1 期望 cmcc，得到 %v(ok=%v)", got, ok)
	}
}

func TestRefreshAllFailKeepsOldDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	dir := t.TempDir()
	// 预置一个正常库
	osWrite := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	osWrite("cmcc.txt", "5.0.0.0/8\n")
	db, err := LoadFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	r := &HTTPRepository{BaseURL: srv.URL, Dir: dir}
	if _, err := r.Refresh(db); err == nil {
		t.Error("全部失败应返回错误")
	}
	// 旧库应保持可用
	if got, ok := db.Lookup(netip.MustParseAddr("5.0.0.1")); !ok || got != ISPCMCC {
		t.Errorf("失败后旧库应保留 cmcc，得到 %v(ok=%v)", got, ok)
	}
}
