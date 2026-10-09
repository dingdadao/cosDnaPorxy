package source

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// defaultBaseURL 默认上游目录（每日更新，随 APNIC 刷新）
const (
	defaultBaseURL = "https://ispip.clang.cn"
	defaultTimeout = 30 * time.Second
)

// fileNameFor 返回运营商对应的上游文件名（ispip.clang.cn 命名约定）
func fileNameFor(isp ISP) string {
	switch isp {
	case ISPTelecom:
		return "chinatelecom_ipv46"
	case ISPUnicom:
		return "unicom_cnc_ipv46"
	case ISPCMCC:
		return "cmcc_ipv46"
	case ISPCernet:
		return "cernet_ipv46"
	case ISPChinabtn:
		return "chinabtn_ipv46"
	case ISPGWBN:
		return "gwbn_ipv46"
	}
	return ""
}

// HTTPRepository 以「目录内按运营商命名文件」的方式维护运营商段库
type HTTPRepository struct {
	BaseURL string
	Dir     string
	Client  *http.Client
	Timeout time.Duration
}

func (r *HTTPRepository) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	t := r.Timeout
	if t <= 0 {
		t = defaultTimeout
	}
	return &http.Client{Timeout: t}
}

// Refresh 下载全部运营商段文件到 Dir，成功后重建 DB 快照。
// 单文件失败跳过并保留旧文件；全部失败则不重建，返回错误。
// 返回成功更新的文件数。
func (r *HTTPRepository) Refresh(db *DB) (int, error) {
	if strings.TrimSpace(r.BaseURL) == "" {
		r.BaseURL = defaultBaseURL
	}
	if strings.TrimSpace(r.Dir) == "" {
		return 0, fmt.Errorf("source db dir 为空")
	}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return 0, err
	}

	updated := 0
	var firstErr error
	for _, isp := range KnownISPs() {
		name := fileNameFor(isp)
		if name == "" {
			continue
		}
		url := strings.TrimRight(r.BaseURL, "/") + "/" + name + ".txt"
		tmp := filepath.Join(r.Dir, "."+name+".tmp")
		n, err := downloadFile(r.client(), url, tmp)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			os.Remove(tmp)
			continue
		}
		if n == 0 {
			os.Remove(tmp)
			continue
		}
		if err := os.Rename(tmp, filepath.Join(r.Dir, name+".txt")); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			os.Remove(tmp)
			continue
		}
		updated++
	}

	if updated == 0 {
		if firstErr == nil {
			firstErr = fmt.Errorf("未下载到任何运营商段")
		}
		return 0, firstErr
	}
	if err := ReloadFromDir(db, r.Dir); err != nil {
		return updated, err
	}
	return updated, nil
}

// downloadFile 下载到临时文件并返回字节数
func downloadFile(client *http.Client, url, tmp string) (int64, error) {
	resp, err := client.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(tmp)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, resp.Body)
	cerr := f.Close()
	if err == nil {
		err = cerr
	}
	return n, err
}

// AutoUpdate 后台定时刷新：立即跑一次，之后按 interval 周期性刷新。
// 返回 stop 函数用于停止。错误通过 onError（可空）上报。
func AutoUpdate(db *DB, baseURL, dir string, interval time.Duration, onError func(error)) (stop func()) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	ctx, cancel := context.WithCancel(context.Background())
	var once sync.Once
	r := &HTTPRepository{BaseURL: baseURL, Dir: dir}

	go func() {
		run := func() {
			if _, err := r.Refresh(db); err != nil && onError != nil {
				onError(err)
			}
		}
		run()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()

	return func() {
		once.Do(cancel)
	}
}
