// plugins/prometheus/main.go
// Package main provides the Prometheus metrics plugin for Q Policy Agent.
// Exposes policy evaluation metrics in Prometheus format.
//
// Build with:
//   go build -buildmode=plugin -o prometheus.so ./plugins/prometheus
package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/infrashift/q-policy-agent/internal/plugin"
)

// PrometheusPlugin exposes metrics for policy evaluation.
type PrometheusPlugin struct {
	config   PrometheusConfig
	registry *prometheus.Registry
	server   *http.Server
	mu       sync.RWMutex

	// Metrics
	evaluationsTotal    *prometheus.CounterVec
	evaluationDuration  *prometheus.HistogramVec
	violationsTotal     *prometheus.CounterVec
	policyLoadErrors    *prometheus.CounterVec
	policiesLoaded      *prometheus.GaugeVec
	cacheHits           *prometheus.CounterVec
	cacheMisses         *prometheus.CounterVec
	activeEvaluations   prometheus.Gauge
	inputValidationErrs *prometheus.CounterVec
	rateLimitHits       *prometheus.CounterVec
	pluginHealth        *prometheus.GaugeVec
}

// PrometheusConfig configures the metrics plugin.
type PrometheusConfig struct {
	// Enabled controls whether metrics are collected
	Enabled bool `json:"enabled"`

	// Address for metrics endpoint (e.g., ":9090")
	Address string `json:"address"`

	// Path for metrics endpoint (e.g., "/metrics")
	Path string `json:"path"`

	// Namespace prefix for all metrics (e.g., "q")
	Namespace string `json:"namespace"`

	// Subsystem for metrics grouping
	Subsystem string `json:"subsystem"`

	// EnableGoMetrics includes Go runtime metrics
	EnableGoMetrics bool `json:"enableGoMetrics"`

	// EnableProcessMetrics includes process metrics
	EnableProcessMetrics bool `json:"enableProcessMetrics"`

	// HistogramBuckets for duration metrics
	HistogramBuckets []float64 `json:"histogramBuckets"`
}

func (p *PrometheusPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "prometheus",
		Type:        plugin.TypeNotifier, // Observability category
		Version:     "1.0.0",
		Description: "Prometheus metrics exporter for policy evaluation observability",
		Author:      "Q Policy Agent",
		License:     "Apache-2.0",
		Capabilities: []string{
			"metrics.export",
			"metrics.prometheus",
		},
	}
}

func (p *PrometheusPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Parse config with defaults
	p.config = PrometheusConfig{
		Enabled:              true,
		Address:              ":9090",
		Path:                 "/metrics",
		Namespace:            "q",
		Subsystem:            "policy",
		EnableGoMetrics:      true,
		EnableProcessMetrics: true,
		HistogramBuckets:     []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
	}

	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["address"].(string); ok {
		p.config.Address = v
	}
	if v, ok := config["path"].(string); ok {
		p.config.Path = v
	}
	if v, ok := config["namespace"].(string); ok {
		p.config.Namespace = v
	}
	if v, ok := config["subsystem"].(string); ok {
		p.config.Subsystem = v
	}
	if v, ok := config["enableGoMetrics"].(bool); ok {
		p.config.EnableGoMetrics = v
	}
	if v, ok := config["enableProcessMetrics"].(bool); ok {
		p.config.EnableProcessMetrics = v
	}
	if v, ok := config["histogramBuckets"].([]interface{}); ok {
		p.config.HistogramBuckets = make([]float64, len(v))
		for i, b := range v {
			if f, ok := b.(float64); ok {
				p.config.HistogramBuckets[i] = f
			}
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Create registry
	p.registry = prometheus.NewRegistry()

	// Register standard collectors if enabled
	if p.config.EnableGoMetrics {
		p.registry.MustRegister(collectors.NewGoCollector())
	}
	if p.config.EnableProcessMetrics {
		p.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	// Create metrics
	p.createMetrics()

	// Start HTTP server
	if err := p.startServer(); err != nil {
		return fmt.Errorf("starting metrics server: %w", err)
	}

	return nil
}

func (p *PrometheusPlugin) createMetrics() {
	ns := p.config.Namespace
	sub := p.config.Subsystem

	// Evaluation metrics
	p.evaluationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "evaluations_total",
			Help:      "Total number of policy evaluations",
		},
		[]string{"policy", "namespace", "decision", "environment"},
	)

	p.evaluationDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "evaluation_duration_seconds",
			Help:      "Policy evaluation duration in seconds",
			Buckets:   p.config.HistogramBuckets,
		},
		[]string{"policy", "namespace"},
	)

	p.activeEvaluations = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "active_evaluations",
			Help:      "Number of currently active evaluations",
		},
	)

	// Violation metrics
	p.violationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "violations_total",
			Help:      "Total number of policy violations",
		},
		[]string{"policy", "namespace", "rule_id", "severity"},
	)

	// Policy loading metrics
	p.policyLoadErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "load_errors_total",
			Help:      "Total number of policy load errors",
		},
		[]string{"policy", "namespace", "error_type"},
	)

	p.policiesLoaded = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "policies_loaded",
			Help:      "Number of currently loaded policies",
		},
		[]string{"namespace"},
	)

	// Cache metrics
	p.cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "cache_hits_total",
			Help:      "Total number of cache hits",
		},
		[]string{"cache_type"},
	)

	p.cacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "cache_misses_total",
			Help:      "Total number of cache misses",
		},
		[]string{"cache_type"},
	)

	// Input validation metrics
	p.inputValidationErrs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "input_validation_errors_total",
			Help:      "Total number of input validation errors",
		},
		[]string{"policy", "field"},
	)

	// Rate limiting metrics
	p.rateLimitHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: ns,
			Subsystem: sub,
			Name:      "rate_limit_hits_total",
			Help:      "Total number of rate limit hits",
		},
		[]string{"client"},
	)

	// Plugin health metrics
	p.pluginHealth = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: ns,
			Subsystem: "plugin",
			Name:      "health",
			Help:      "Plugin health status (1=healthy, 0=unhealthy)",
		},
		[]string{"plugin", "type"},
	)

	// Register all metrics
	p.registry.MustRegister(
		p.evaluationsTotal,
		p.evaluationDuration,
		p.activeEvaluations,
		p.violationsTotal,
		p.policyLoadErrors,
		p.policiesLoaded,
		p.cacheHits,
		p.cacheMisses,
		p.inputValidationErrs,
		p.rateLimitHits,
		p.pluginHealth,
	)
}

func (p *PrometheusPlugin) startServer() error {
	mux := http.NewServeMux()
	mux.Handle(p.config.Path, promhttp.HandlerFor(p.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	p.server = &http.Server{
		Addr:         p.config.Address,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := p.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			// Log error but don't crash
			fmt.Printf("prometheus metrics server error: %v\n", err)
		}
	}()

	return nil
}

func (p *PrometheusPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	if p.server == nil {
		return fmt.Errorf("metrics server not running")
	}
	return nil
}

func (p *PrometheusPlugin) Close() error {
	if p.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.server.Shutdown(ctx)
	}
	return nil
}

// Metrics recording methods

// RecordEvaluation records a policy evaluation.
func (p *PrometheusPlugin) RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration) {
	if !p.config.Enabled {
		return
	}
	p.evaluationsTotal.WithLabelValues(policy, namespace, decision, environment).Inc()
	p.evaluationDuration.WithLabelValues(policy, namespace).Observe(duration.Seconds())
}

// RecordViolation records a policy violation.
func (p *PrometheusPlugin) RecordViolation(policy, namespace, ruleID, severity string) {
	if !p.config.Enabled {
		return
	}
	p.violationsTotal.WithLabelValues(policy, namespace, ruleID, severity).Inc()
}

// RecordPolicyLoadError records a policy load error.
func (p *PrometheusPlugin) RecordPolicyLoadError(policy, namespace, errorType string) {
	if !p.config.Enabled {
		return
	}
	p.policyLoadErrors.WithLabelValues(policy, namespace, errorType).Inc()
}

// SetPoliciesLoaded sets the number of loaded policies.
func (p *PrometheusPlugin) SetPoliciesLoaded(namespace string, count int) {
	if !p.config.Enabled {
		return
	}
	p.policiesLoaded.WithLabelValues(namespace).Set(float64(count))
}

// RecordCacheHit records a cache hit.
func (p *PrometheusPlugin) RecordCacheHit(cacheType string) {
	if !p.config.Enabled {
		return
	}
	p.cacheHits.WithLabelValues(cacheType).Inc()
}

// RecordCacheMiss records a cache miss.
func (p *PrometheusPlugin) RecordCacheMiss(cacheType string) {
	if !p.config.Enabled {
		return
	}
	p.cacheMisses.WithLabelValues(cacheType).Inc()
}

// RecordInputValidationError records an input validation error.
func (p *PrometheusPlugin) RecordInputValidationError(policy, field string) {
	if !p.config.Enabled {
		return
	}
	p.inputValidationErrs.WithLabelValues(policy, field).Inc()
}

// RecordRateLimitHit records a rate limit hit.
func (p *PrometheusPlugin) RecordRateLimitHit(client string) {
	if !p.config.Enabled {
		return
	}
	p.rateLimitHits.WithLabelValues(client).Inc()
}

// SetPluginHealth sets plugin health status.
func (p *PrometheusPlugin) SetPluginHealth(pluginName, pluginType string, healthy bool) {
	if !p.config.Enabled {
		return
	}
	val := 0.0
	if healthy {
		val = 1.0
	}
	p.pluginHealth.WithLabelValues(pluginName, pluginType).Set(val)
}

// IncActiveEvaluations increments active evaluations.
func (p *PrometheusPlugin) IncActiveEvaluations() {
	if !p.config.Enabled {
		return
	}
	p.activeEvaluations.Inc()
}

// DecActiveEvaluations decrements active evaluations.
func (p *PrometheusPlugin) DecActiveEvaluations() {
	if !p.config.Enabled {
		return
	}
	p.activeEvaluations.Dec()
}

// Registry returns the Prometheus registry for custom metrics.
func (p *PrometheusPlugin) Registry() *prometheus.Registry {
	return p.registry
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &PrometheusPlugin{}
