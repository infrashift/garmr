// internal/observability/prometheus.go
// Package observability: Prometheus implementation of MetricsRecorder.
package observability

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	promNamespace = "garmr"
)

// PrometheusMetrics is a Prometheus-backed MetricsRecorder.
type PrometheusMetrics struct {
	registry *prometheus.Registry

	evaluationsTotal       *prometheus.CounterVec
	evaluationDurationSecs *prometheus.HistogramVec
	violationsTotal        *prometheus.CounterVec
	activeEvaluations      prometheus.Gauge
	policyLoadErrorsTotal  *prometheus.CounterVec
	policiesLoaded         *prometheus.GaugeVec
	rateLimitHitsTotal     *prometheus.CounterVec
	panicsTotal            prometheus.Counter
}

// NewPrometheusMetrics creates a PrometheusMetrics backed by a dedicated
// registry. Go runtime and process collectors are registered automatically.
func NewPrometheusMetrics() *PrometheusMetrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	m := &PrometheusMetrics{registry: reg}

	m.evaluationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "policy_evaluations_total",
		Help:      "Total number of policy evaluations by decision.",
	}, []string{"policy", "namespace", "decision", "environment"})

	m.evaluationDurationSecs = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: promNamespace,
		Name:      "policy_evaluation_duration_seconds",
		Help:      "Policy evaluation duration in seconds.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"namespace", "decision"})

	m.violationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "policy_violations_total",
		Help:      "Total number of policy rule violations.",
	}, []string{"policy", "namespace", "rule_id", "severity"})

	m.activeEvaluations = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: promNamespace,
		Name:      "active_evaluations",
		Help:      "Number of in-flight policy evaluations.",
	})

	m.policyLoadErrorsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "policy_load_errors_total",
		Help:      "Total number of policy load/compile failures.",
	}, []string{"policy", "namespace", "error_type"})

	m.policiesLoaded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: promNamespace,
		Name:      "policies_loaded",
		Help:      "Number of policies currently loaded, by namespace.",
	}, []string{"namespace"})

	m.rateLimitHitsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "rate_limit_hits_total",
		Help:      "Total requests rejected by the rate limiter, by client identifier.",
	}, []string{"client"})

	m.panicsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: promNamespace,
		Name:      "http_panics_total",
		Help:      "Total HTTP handler panics recovered by the recovery middleware.",
	})

	reg.MustRegister(
		m.evaluationsTotal,
		m.evaluationDurationSecs,
		m.violationsTotal,
		m.activeEvaluations,
		m.policyLoadErrorsTotal,
		m.policiesLoaded,
		m.rateLimitHitsTotal,
		m.panicsTotal,
	)

	return m
}

// Handler returns an http.Handler that exposes metrics in Prometheus text
// format.
func (m *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{Registry: m.registry})
}

// --- MetricsRecorder implementation ---

func (m *PrometheusMetrics) RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration) {
	m.evaluationsTotal.WithLabelValues(policy, namespace, decision, environment).Inc()
	m.evaluationDurationSecs.WithLabelValues(namespace, decision).Observe(duration.Seconds())
}

func (m *PrometheusMetrics) RecordViolation(policy, namespace, ruleID, severity string) {
	m.violationsTotal.WithLabelValues(policy, namespace, ruleID, severity).Inc()
}

func (m *PrometheusMetrics) IncActiveEvaluations() {
	m.activeEvaluations.Inc()
}

func (m *PrometheusMetrics) DecActiveEvaluations() {
	m.activeEvaluations.Dec()
}

func (m *PrometheusMetrics) RecordPolicyLoadError(policy, namespace, errorType string) {
	m.policyLoadErrorsTotal.WithLabelValues(policy, namespace, errorType).Inc()
}

func (m *PrometheusMetrics) SetPoliciesLoaded(namespace string, count int) {
	m.policiesLoaded.WithLabelValues(namespace).Set(float64(count))
}

func (m *PrometheusMetrics) RecordRateLimitHit(client string) {
	m.rateLimitHitsTotal.WithLabelValues(client).Inc()
}

// IncPanicsRecovered is called by the HTTP recovery middleware.
func (m *PrometheusMetrics) IncPanicsRecovered() {
	m.panicsTotal.Inc()
}
