package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cosDnaPorxy/internal/config"
	"cosDnaPorxy/internal/dns"
	"cosDnaPorxy/internal/querylog"
	"cosDnaPorxy/internal/utils"
)

//go:embed admin.html
var adminFS embed.FS

// RestartOutcome 管理端「重启服务」的处理结果
type RestartOutcome struct {
	ProcessRestart bool   // 已下发进程级重启：当前连接会断开，页面需等待服务恢复
	WebAddrChanged bool   // Web 监听地址已变更
	WebAddr        string // 变更后的 Web 监听地址（WebAddrChanged 为 true 时有效）
}

// Server Web 管理端服务器
type Server struct {
	store      *config.Store
	logger     *utils.EnhancedLogger
	getHandler func() *dns.RefactoredHandler  // 获取当前DNS处理器（重启后自动指向新实例）
	restart    func() (RestartOutcome, error) // 按库中配置重启服务（nil=不支持重启）
	queryLog   *querylog.Store                // 解析日志库（可为 nil 表示不可用）

	srv *http.Server
	ln  net.Listener
}

// NewServer 创建 Web 管理端服务器（qlog 为进程级解析日志库，可为 nil）
func NewServer(store *config.Store, logger *utils.EnhancedLogger, getHandler func() *dns.RefactoredHandler, restart func() (RestartOutcome, error), qlog *querylog.Store) *Server {
	s := &Server{
		store:      store,
		logger:     logger,
		getHandler: getHandler,
		restart:    restart,
		queryLog:   qlog,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/config", s.handleGetConfig)
	mux.HandleFunc("PUT /api/config", s.handlePutConfig)
	mux.HandleFunc("POST /api/restart", s.handleRestart)
	mux.HandleFunc("GET /api/logs", s.handleQueryLogs)
	mux.HandleFunc("GET /api/logs/stats", s.handleQueryLogStats)
	mux.HandleFunc("GET /api/overrides", s.handleListOverrides)
	mux.HandleFunc("POST /api/overrides", s.handleAddOverride)
	mux.HandleFunc("PUT /api/overrides/{id}", s.handleUpdateOverride)
	mux.HandleFunc("DELETE /api/overrides/{id}", s.handleDeleteOverride)

	s.srv = &http.Server{Handler: mux}
	return s
}

// Start 监听指定地址并在后台运行
func (s *Server) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("Web管理端监听失败: %w", err)
	}
	s.ln = ln

	go func() {
		if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("❌ [Web管理端运行失败] ", map[string]interface{}{
				"rule":  "WEB_SERVER_FAILED",
				"error": err.Error(),
			})
		}
	}()

	s.logger.Info("🌐 [Web管理端已启动] ", map[string]interface{}{
		"rule": "WEB_SERVER_START",
		"addr": ln.Addr().String(),
	})
	return nil
}

// Addr 返回实际监听地址
func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Shutdown 优雅关闭 Web 管理端
func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// handleIndex 管理页面
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	data, err := adminFS.ReadFile("admin.html")
	if err != nil {
		http.Error(w, "页面加载失败", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(data)
}

// handleGetConfig 获取当前配置
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.store.LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"config": cfg.ToJSON()})
}

// handlePutConfig 保存配置并热更新
func (s *Server) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	var j config.ConfigJSON
	if err := json.NewDecoder(r.Body).Decode(&j); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("请求体解析失败: %w", err))
		return
	}

	cfg, err := j.ToConfig()
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := config.ValidateConfig(cfg); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SaveConfig(cfg); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// 热更新到运行中的DNS处理器
	restartRequired := false
	h := s.getHandler()
	if h == nil {
		s.logger.Warn("⚠️ DNS处理器不存在，配置已保存，将在下次重启后生效")
		restartRequired = true
	} else {
		restartRequired = h.ApplyConfig(cfg)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":               true,
		"restart_required": restartRequired,
	})
}

// handleRestart 按配置库中的最新配置重启服务（Web 管理端按钮触发）
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if s.restart == nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("当前运行模式不支持重启"))
		return
	}

	out, err := s.restart()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	s.logger.Warn("🔄 [Web管理端已下发重启] ", map[string]interface{}{
		"rule":             "WEB_RESTART_ACCEPTED",
		"process_restart":  out.ProcessRestart,
		"web_addr_changed": out.WebAddrChanged,
	})
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ok":               true,
		"process_restart":  out.ProcessRestart,
		"web_addr_changed": out.WebAddrChanged,
		"web_addr":         out.WebAddr,
	})
}

// handleQueryLogs 按条件分页查询解析日志
// 参数：q（关键字）、action（来源）、qtype、start/end（Unix 秒或本地时间）、limit、offset
func (s *Server) handleQueryLogs(w http.ResponseWriter, r *http.Request) {
	if s.queryLog == nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("解析日志库不可用"))
		return
	}

	q := r.URL.Query()
	f := querylog.Filter{
		Keyword: strings.TrimSpace(q.Get("q")),
		Action:  strings.TrimSpace(q.Get("action")),
		QType:   strings.ToUpper(strings.TrimSpace(q.Get("qtype"))),
	}
	var err error
	if f.Start, err = parseTimeParam(q.Get("start")); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("start 参数无效: %w", err))
		return
	}
	if f.End, err = parseTimeParam(q.Get("end")); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("end 参数无效: %w", err))
		return
	}
	f.Limit = parsePositiveInt(q.Get("limit"), 100)
	f.Offset = parsePositiveInt(q.Get("offset"), 0)

	logs, total, err := s.queryLog.Query(f)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"logs":   logs,
		"total":  total,
		"limit":  f.Limit,
		"offset": f.Offset,
		"stats":  s.queryLog.Stats(),
	})
}

// handleQueryLogStats 解析日志聚合统计（窗口默认保留期内全部记录，不设条数上限）
// 参数：start/end（Unix 秒或本地时间）、top（Top 域名条数，默认 20，上限 100）
func (s *Server) handleQueryLogStats(w http.ResponseWriter, r *http.Request) {
	if s.queryLog == nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("解析日志库不可用"))
		return
	}

	q := r.URL.Query()
	var f querylog.Filter
	var err error
	if f.Start, err = parseTimeParam(q.Get("start")); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("start 参数无效: %w", err))
		return
	}
	if f.End, err = parseTimeParam(q.Get("end")); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("end 参数无效: %w", err))
		return
	}

	summary, err := s.queryLog.Summary(f, parsePositiveInt(q.Get("top"), 0), s.resolveTimeoutMS())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summary": summary,
		"stats":   s.queryLog.Stats(),
	})
}

// resolveTimeoutMS 统计页「超时」判定阈值（毫秒）：取配置中较宽松的查询超时
// （含现代协议），读不到或未配置时返回 0 表示不判定
func (s *Server) resolveTimeoutMS() int64 {
	cfg, err := s.store.LoadConfig()
	if err != nil {
		return 0
	}
	d := cfg.Timeout
	if cfg.ModernTimeout > d {
		d = cfg.ModernTimeout
	}
	if d <= 0 {
		return 0
	}
	return d.Milliseconds()
}

// parseTimeParam 解析时间参数：空串为 0（不限）；支持 Unix 秒与常见时间写法
func parseTimeParam(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t.Unix(), nil
		}
	}
	return 0, fmt.Errorf("无法识别的时间格式 %q", s)
}

// parsePositiveInt 解析非负整数，空串或非法值返回 fallback
func parsePositiveInt(s string, fallback int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

// handleListOverrides 查询域名篡改记录
func (s *Server) handleListOverrides(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListOverrides()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"overrides": list})
}

// handleAddOverride 新增域名篡改记录
func (s *Server) handleAddOverride(w http.ResponseWriter, r *http.Request) {
	var o config.Override
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("请求体解析失败: %w", err))
		return
	}
	if err := validateOverride(&o); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.store.AddOverride(&o)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	o.ID = id

	if err := s.reloadOverrides(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "override": o})
}

// handleUpdateOverride 更新域名篡改记录
func (s *Server) handleUpdateOverride(w http.ResponseWriter, r *http.Request) {
	var o config.Override
	if err := json.NewDecoder(r.Body).Decode(&o); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("请求体解析失败: %w", err))
		return
	}
	var id int64
	if _, err := fmt.Sscanf(r.PathValue("id"), "%d", &id); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("无效的ID"))
		return
	}
	o.ID = id

	if err := validateOverride(&o); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.UpdateOverride(&o); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := s.reloadOverrides(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true, "override": o})
}

// handleDeleteOverride 删除域名篡改记录
func (s *Server) handleDeleteOverride(w http.ResponseWriter, r *http.Request) {
	var id int64
	if _, err := fmt.Sscanf(r.PathValue("id"), "%d", &id); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("无效的ID"))
		return
	}
	if err := s.store.DeleteOverride(id); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	if err := s.reloadOverrides(); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

// reloadOverrides 从数据库重新加载篡改规则到DNS处理器
func (s *Server) reloadOverrides() error {
	list, err := s.store.ListOverrides()
	if err != nil {
		return err
	}
	h := s.getHandler()
	if h == nil {
		return fmt.Errorf("DNS处理器不存在，规则已保存，将在下次重启后生效")
	}
	h.LoadOverrides(list)
	return nil
}

// validateOverride 校验篡改记录
func validateOverride(o *config.Override) error {
	o.Domain = strings.TrimSpace(o.Domain)
	o.QType = strings.ToUpper(strings.TrimSpace(o.QType))
	o.Value = strings.TrimSpace(o.Value)

	if o.Domain == "" {
		return fmt.Errorf("域名不能为空")
	}

	switch o.QType {
	case "A":
		if net.ParseIP(o.Value).To4() == nil {
			return fmt.Errorf("A记录值必须是合法IPv4地址: %s", o.Value)
		}
	case "AAAA":
		ip := net.ParseIP(o.Value)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA记录值必须是合法IPv6地址: %s", o.Value)
		}
	case "CNAME":
		if o.Value == "" || strings.ContainsAny(o.Value, " \t") {
			return fmt.Errorf("CNAME记录值必须是合法域名: %s", o.Value)
		}
	default:
		return fmt.Errorf("不支持的记录类型: %s（仅支持 A/AAAA/CNAME）", o.QType)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]interface{}{"error": err.Error()})
}
