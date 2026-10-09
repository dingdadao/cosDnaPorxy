package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// 上游协议 scheme（与 handler.hasModernProtocols 的判定保持一致）
const (
	UpstreamSchemeUDP   = "udp"
	UpstreamSchemeTCP   = "tcp"
	UpstreamSchemeTLS   = "tls"   // DoT
	UpstreamSchemeHTTPS = "https" // DoH
	UpstreamSchemeH3    = "h3"    // DoH3
)

// UpstreamDefaultPort 返回 scheme 对应的默认端口
// udp/tcp（含无 scheme 的旧格式）→ 53；tls(DoT) → 853；https/h3(DoH/DoH3) → 443
func UpstreamDefaultPort(scheme string) string {
	switch normalizeScheme(scheme) {
	case UpstreamSchemeTLS, "dot":
		return "853"
	case UpstreamSchemeHTTPS, UpstreamSchemeH3, "http", "doh", "doh3":
		return "443"
	default:
		return "53"
	}
}

// normalizeScheme 去掉 "://" 后缀与首尾空白并转小写
func normalizeScheme(scheme string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(scheme), "://"))
}

// ValidUpstreamScheme 判断协议前缀是否受支持；空串表示旧格式（无 scheme 的 host:port）
func ValidUpstreamScheme(scheme string) bool {
	switch normalizeScheme(scheme) {
	case "", UpstreamSchemeUDP, UpstreamSchemeTCP, UpstreamSchemeTLS,
		UpstreamSchemeHTTPS, UpstreamSchemeH3:
		return true
	}
	return false
}

// isURLScheme 判断该 scheme 是否为「完整 URL」形式（保留 path/query，端口由 HTTP 客户端兜底）
func isURLScheme(scheme string) bool {
	switch normalizeScheme(scheme) {
	case UpstreamSchemeHTTPS, UpstreamSchemeH3:
		return true
	}
	return false
}

// SplitUpstreamScheme 拆出协议前缀与剩余部分；无 "://" 时 scheme 为空串
func SplitUpstreamScheme(upstream string) (scheme, rest string) {
	s := strings.TrimSpace(upstream)
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		return scheme, strings.TrimSpace(rest)
	}
	return "", s
}

// UpstreamDialAddr 把上游地址转成可直接 dial 的 host:port（运行时兜底用）
//   - 自动去掉 udp:// tcp:// tls:// 等前缀
//   - 缺端口时按 scheme 补默认端口（udp/tcp→53、tls→853）
//   - IPv6 字面量补成 [::1]:53，不会像 strings.Contains(addr, ":") 那样把 ::1 误判为「已含端口」
//
// 解析失败时原样返回剩余部分，把报错权留给 dial，便于日志里看到真实地址
func UpstreamDialAddr(upstream string) string {
	scheme, rest := SplitUpstreamScheme(upstream)
	if rest == "" {
		return strings.TrimSpace(upstream)
	}
	if hostport, err := ensurePort(rest, UpstreamDefaultPort(scheme)); err == nil {
		return hostport
	}
	return rest
}

// NormalizeUpstream 归一化单个上游地址，用于配置校验与落库
//   - udp:// / tcp:// / tls:// ：必须有主机，缺端口时补默认端口（53/53/853）
//   - https:// / h3:// ：完整 URL，保留 path/query，不补端口（由 HTTP 客户端按 443 处理）
//   - 无 scheme 的旧格式 host:port：保持原样，缺端口时补 53
//
// 非法值（未知协议前缀、缺主机、端口非法/越界）返回 error
func NormalizeUpstream(upstream string) (string, error) {
	s := strings.TrimSpace(upstream)
	if s == "" {
		return "", fmt.Errorf("上游地址为空")
	}

	scheme, rest := SplitUpstreamScheme(s)
	if scheme == "" {
		// 旧格式：裸 host:port（按 UDP 处理）
		hostport, err := ensurePort(rest, UpstreamDefaultPort(""))
		if err != nil {
			return "", err
		}
		return hostport, nil
	}

	if !ValidUpstreamScheme(scheme) {
		return "", fmt.Errorf("不支持的上游协议前缀 %q（可选 udp:// tcp:// tls:// https:// h3://）", scheme+"://")
	}
	if rest == "" {
		return "", fmt.Errorf("上游地址缺少主机部分：%q", s)
	}

	if isURLScheme(scheme) {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("非法的 %s 上游地址：%q", normalizeScheme(scheme), s)
		}
		return s, nil
	}

	hostport, err := ensurePort(rest, UpstreamDefaultPort(scheme))
	if err != nil {
		return "", fmt.Errorf("%s://%s：%w", normalizeScheme(scheme), rest, err)
	}
	return normalizeScheme(scheme) + "://" + hostport, nil
}

// ensurePort 把 host[:port] 归一化为 host:port，缺端口时补 defaultPort
func ensurePort(hostport, defaultPort string) (string, error) {
	h := strings.TrimSpace(hostport)
	if h == "" {
		return "", fmt.Errorf("缺少主机部分")
	}

	// 已含显式端口，含 [v6]:port 形式
	if host, port, err := net.SplitHostPort(h); err == nil {
		if strings.TrimSpace(host) == "" {
			return "", fmt.Errorf("缺少主机部分")
		}
		if _, err := parsePort(port); err != nil {
			return "", err
		}
		return h, nil
	}

	// 裸 IPv6 字面量（可能带方括号）：::1 / [::1] / 2001:db8::1
	inner := h
	if strings.HasPrefix(inner, "[") && strings.HasSuffix(inner, "]") {
		inner = inner[1 : len(inner)-1]
	}
	if addr, err := netip.ParseAddr(inner); err == nil {
		return net.JoinHostPort(addr.String(), defaultPort), nil
	}

	// 非 IP 字面量却含冒号：形如 1.1.1.1:abc 的非法端口
	if strings.Contains(h, ":") {
		return "", fmt.Errorf("非法的地址/端口 %q", h)
	}

	// 域名或裸 IPv4，补默认端口
	return net.JoinHostPort(h, defaultPort), nil
}

// parsePort 校验端口取值
func parsePort(port string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil {
		return 0, fmt.Errorf("非法的端口 %q", port)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("端口 %d 越界（应在 1-65535）", n)
	}
	return n, nil
}

// normalizeUpstreamList 就地归一化上游列表，返回首个非法项的错误
func normalizeUpstreamList(field string, list []string) error {
	for i, raw := range list {
		norm, err := NormalizeUpstream(raw)
		if err != nil {
			return fmt.Errorf("%s[%d]：%w", field, i, err)
		}
		list[i] = norm
	}
	return nil
}

// normalizeUpstreamField 就地归一化单个上游字段（空值表示未配置，直接跳过）
func normalizeUpstreamField(field, value string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return value, nil
	}
	norm, err := NormalizeUpstream(value)
	if err != nil {
		return value, fmt.Errorf("%s：%w", field, err)
	}
	return norm, nil
}
