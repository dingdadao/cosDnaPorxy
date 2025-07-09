package dns

import (
	"cosDnaPorxy/internal/config"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/miekg/dns"
	"io"
	"log"
	"net"
	"net/http"
)

// dnsResponseWriter DNS响应写入器
type dnsResponseWriter struct {
	w http.ResponseWriter
}

func (d *dnsResponseWriter) LocalAddr() net.Addr  { return dummyAddr{} }
func (d *dnsResponseWriter) RemoteAddr() net.Addr { return dummyAddr{} }
func (d *dnsResponseWriter) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	d.w.Header().Set("Content-Type", "application/dns-message")
	_, err = d.w.Write(data)
	return err
}
func (d *dnsResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (d *dnsResponseWriter) Close() error              { return nil }
func (d *dnsResponseWriter) TsigStatus() error         { return nil }
func (d *dnsResponseWriter) TsigTimersOnly(bool)       {}
func (d *dnsResponseWriter) Hijack()                   {}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:0" }

// StartUDPServer 启动UDP DNS服务器
func StartUDPServer(config *config.Config, handler dns.Handler) {
	server := &dns.Server{
		Addr:    fmt.Sprintf(":%d", config.ListenPort),
		Net:     "udp",
		Handler: handler,
		UDPSize: 65535,
	}
	log.Printf("Starting UDP DNS server on :%d", config.ListenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("UDP DNS server failed: %v", err)
	}
}

// StartDoTServer 启动DoT服务器
func StartDoTServer(config *config.Config, handler dns.Handler) {
	if config.TLSCertFile == "" || config.TLSKeyFile == "" || config.DoTPort == 0 {
		log.Println("DoT not configured. Skipping.")
		return
	}

	cert, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS certificate: %v", err)
	}

	server := &dns.Server{
		Addr:      fmt.Sprintf(":%d", config.DoTPort),
		Net:       "tcp-tls",
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler:   handler,
	}

	log.Printf("Starting DoT server on :%d", config.DoTPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("DoT server failed: %v", err)
	}
}

// handleDoHRequest 处理DoH请求
func handleDoHRequest(w http.ResponseWriter, r *http.Request, handler dns.Handler, config *config.Config) {
	var dnsQuery []byte
	var err error

	switch r.Method {
	case http.MethodGet:
		dnsParam := r.URL.Query().Get("dns")
		dnsQuery, err = base64.RawURLEncoding.DecodeString(dnsParam)
	case http.MethodPost:
		dnsQuery, err = io.ReadAll(r.Body)
	default:
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		http.Error(w, "Invalid DNS query", http.StatusBadRequest)
		return
	}

	req := &dns.Msg{}
	if err := req.Unpack(dnsQuery); err != nil {
		http.Error(w, "Failed to parse DNS query", http.StatusBadRequest)
		return
	}

	rw := &dnsResponseWriter{w: w}
	handler.ServeDNS(rw, req)
}

// loadTLSCert 加载TLS证书
func loadTLSCert(cfg *config.Config) tls.Certificate {
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		log.Fatalf("Failed to load TLS cert/key: %v", err)
	}
	return cert
}

// StartDoHServer 启动DoH服务器
func StartDoHServer(config *config.Config, handler dns.Handler) {
	if config.TLSCertFile == "" || config.TLSKeyFile == "" || config.DoHPort == 0 {
		log.Println("DoH not configured. Skipping.")
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		handleDoHRequest(w, r, handler, config)
	})

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", config.DoHPort),
		Handler:   mux,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{loadTLSCert(config)}},
	}

	log.Printf("Starting DoH server on :%d", config.DoHPort)
	if err := server.ListenAndServeTLS(config.TLSCertFile, config.TLSKeyFile); err != nil {
		log.Fatalf("DoH server failed: %v", err)
	}
} 