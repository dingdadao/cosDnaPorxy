package source

import (
	"bufio"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// LoadFromDir 从目录加载运营商段库（发生在启动/刷新阶段）。
// 文件名识别规则见 filenameISP，未知文件被忽略（如 all_cn 汇总文件）。
// 解析失败的单行被跳过，不拖垮整库；构建完成后原子替换。
func LoadFromDir(dir string) (*DB, error) {
	d := New()
	if err := ReloadFromDir(d, dir); err != nil {
		return nil, err
	}
	return d, nil
}

// ReloadFromDir 重建并替换库中的快照。
func ReloadFromDir(d *DB, dir string) error {
	s := &snapshot{v4: newTrie(), v6: newTrie()}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, fi := range entries {
		if fi.IsDir() {
			continue
		}
		isp, ok := filenameISP(fi.Name())
		if !ok {
			continue
		}
		if err := loadFile(s, filepath.Join(dir, fi.Name()), isp); err != nil {
			return err
		}
	}
	d.ptr.Store(s)
	return nil
}

// filenameISP 根据文件名识别运营商；未知返回 ok=false。
// 覆盖知名来源（ispip.clang.cn）为不同运营商拆分的命名规则。
func filenameISP(name string) (ISP, bool) {
	low := strings.ToLower(name)
	switch {
	case strings.HasPrefix(low, "chinatelecom") || strings.HasPrefix(low, "telecom"):
		return ISPTelecom, true
	case strings.HasPrefix(low, "unicom") || strings.HasPrefix(low, "cnc"):
		return ISPUnicom, true
	case strings.HasPrefix(low, "cmcc") || strings.HasPrefix(low, "mobile"):
		return ISPCMCC, true
	case strings.HasPrefix(low, "cernet") || strings.HasPrefix(low, "edunet"):
		return ISPCernet, true
	case strings.HasPrefix(low, "chinabtn") || strings.HasPrefix(low, "btn"):
		return ISPChinabtn, true
	case strings.HasPrefix(low, "gwbn") || strings.HasPrefix(low, "longbei"):
		return ISPGWBN, true
	}
	return "", false
}

// loadFile 逐行解析 CIDR 文本文件（每行一个前缀，支持空行与 # 注释）。
func loadFile(s *snapshot, path string, isp ISP) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, perr := netip.ParsePrefix(line)
		if perr != nil {
			continue // 忽略坏行
		}
		p = p.Masked()
		insertPrefix(s, p, isp)
	}
	return sc.Err()
}

func insertPrefix(s *snapshot, p netip.Prefix, isp ISP) {
	b := p.Addr().As16()
	if p.Addr().Is4() || p.Addr().Is4In6() {
		s.v4.insert(b[12:16], p.Bits(), isp)
	} else {
		s.v6.insert(b[:16], p.Bits(), isp)
	}
}
