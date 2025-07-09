package metrics

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
)

// Collector 指标收集器
type Collector struct {
	queriesTotal    *prometheus.CounterVec
	whitelistHits   prometheus.Counter
	designatedHits  prometheus.Counter
	replacedCount   prometheus.Counter
	upstreamLatency prometheus.Histogram
	responseLatency prometheus.Histogram
	cacheHits       *prometheus.CounterVec
}

// NewCollector 创建新的指标收集器
func NewCollector() *Collector {
	return &Collector{
		queriesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "dns_queries_total",
				Help: "Total DNS queries processed",
			},
			[]string{"type", "status"},
		),
		whitelistHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "whitelist_hits_total",
				Help: "Total whitelist hits",
			},
		),
		designatedHits: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "designated_hits_total",
				Help: "Total designated hits",
			},
		),
		replacedCount: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "replaced_records_total",
				Help: "Total records replaced",
			},
		),
		upstreamLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "upstream_query_latency_seconds",
				Help:    "Latency of upstream DNS queries",
				Buckets: []float64{0.1, 0.5, 1, 2, 5},
			},
		),
		responseLatency: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "dns_response_latency_seconds",
				Help:    "Latency of DNS responses",
				Buckets: []float64{0.1, 0.5, 1, 2, 5},
			},
		),
		cacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_hits_total",
				Help: "Total cache hits",
			},
			[]string{"type"},
		),
	}
}

// Register 注册所有指标
func (c *Collector) Register() {
	prometheus.MustRegister(c.queriesTotal)
	prometheus.MustRegister(c.whitelistHits)
	prometheus.MustRegister(c.designatedHits)
	prometheus.MustRegister(c.replacedCount)
	prometheus.MustRegister(c.upstreamLatency)
	prometheus.MustRegister(c.responseLatency)
	prometheus.MustRegister(c.cacheHits)
}

// GetQueriesTotal 获取查询总数指标
func (c *Collector) GetQueriesTotal() *prometheus.CounterVec {
	return c.queriesTotal
}

// GetWhitelistHits 获取白名单命中指标
func (c *Collector) GetWhitelistHits() prometheus.Counter {
	return c.whitelistHits
}

// GetDesignatedHits 获取定向域名命中指标
func (c *Collector) GetDesignatedHits() prometheus.Counter {
	return c.designatedHits
}

// GetReplacedCount 获取替换记录数指标
func (c *Collector) GetReplacedCount() prometheus.Counter {
	return c.replacedCount
}

// GetUpstreamLatency 获取上游查询延迟指标
func (c *Collector) GetUpstreamLatency() prometheus.Histogram {
	return c.upstreamLatency
}

// GetResponseLatency 获取响应延迟指标
func (c *Collector) GetResponseLatency() prometheus.Histogram {
	return c.responseLatency
}

// GetCacheHits 获取缓存命中指标
func (c *Collector) GetCacheHits() *prometheus.CounterVec {
	return c.cacheHits
}

// StartMetricsServer 启动指标服务器
func StartMetricsServer(port int) {
	http.Handle("/metrics", promhttp.Handler())
	addr := fmt.Sprintf(":%d", port)
	log.Printf("Starting metrics server on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Printf("Metrics server failed: %v", err)
	}
} 