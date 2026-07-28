// internal/observability/provider.go
// Package observability provides the optional metrics surface, plus OTel
// tracing setup in otel.go. Garmr functions fully without either.
//
// Tracing is deliberately NOT behind an interface here: it arrives via
// otelhttp wrapping the HTTP handler and InitTracing configuring the global
// provider, with TraceIDFromContext pulling the id into audit records. An
// earlier Tracer interface duplicated that and had no callers.
package observability

import (
	"sync"
	"time"
)

// MetricsRecorder records evaluation metrics. When no recorder is configured
// Garmr uses NoopMetrics, so callers never need a nil check.
type MetricsRecorder interface {
	// Evaluation metrics
	RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration)
	RecordViolation(policy, namespace, ruleID, severity string)

	// Active evaluations gauge
	IncActiveEvaluations()
	DecActiveEvaluations()

	// Policy loading
	RecordPolicyLoadError(policy, namespace, errorType string)
	// SetPoliciesLoaded publishes a FULL snapshot of per-namespace policy
	// counts. Snapshot semantics are what let the recorder clear a
	// namespace that disappeared on reload — a per-namespace setter could
	// never do that, so vanished namespaces kept their stale gauge value.
	SetPoliciesLoaded(counts map[string]int)
	// RecordPolicyReload counts reload attempts by outcome, so operators
	// can alert on failed reloads (which keep the old set serving and are
	// otherwise only visible in logs and the reload response).
	RecordPolicyReload(success bool)

	// Rate limiting
	RecordRateLimitHit(client string)
}

// NoopMetrics is a no-op metrics recorder, used when none is configured.
type NoopMetrics struct{}

func (NoopMetrics) RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration) {
}
func (NoopMetrics) RecordViolation(policy, namespace, ruleID, severity string) {}
func (NoopMetrics) IncActiveEvaluations()                                      {}
func (NoopMetrics) DecActiveEvaluations()                                      {}
func (NoopMetrics) RecordPolicyLoadError(policy, namespace, errorType string)  {}
func (NoopMetrics) SetPoliciesLoaded(counts map[string]int)                    {}
func (NoopMetrics) RecordPolicyReload(success bool)                            {}
func (NoopMetrics) RecordRateLimitHit(client string)                           {}

// Provider holds the process-wide metrics recorder.
//
// SetMetrics is called after construction (main.go wires the Prometheus
// recorder onto an already-built server) while Metrics is read from
// request-handling goroutines, so both are guarded.
type Provider struct {
	mu      sync.RWMutex
	metrics MetricsRecorder
}

// NewProvider creates a new observability provider with defaults.
func NewProvider() *Provider {
	return &Provider{
		metrics: NoopMetrics{},
	}
}

// SetMetrics sets the metrics recorder.
func (p *Provider) SetMetrics(m MetricsRecorder) {
	if m == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics = m
}

// Metrics returns the metrics recorder (never nil).
func (p *Provider) Metrics() MetricsRecorder {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.metrics
}
