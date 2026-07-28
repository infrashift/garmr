// internal/observability/provider.go
// Package observability provides interfaces for optional metrics and tracing.
// Garmr functions fully without metrics or tracing - they are opt-in features.
package observability

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// MetricsRecorder is the interface for recording metrics.
// If no metrics plugin is loaded, Garmr uses NoopMetrics.
type MetricsRecorder interface {
	// Evaluation metrics
	RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration)
	RecordViolation(policy, namespace, ruleID, severity string)

	// Active evaluations gauge
	IncActiveEvaluations()
	DecActiveEvaluations()

	// Policy loading
	RecordPolicyLoadError(policy, namespace, errorType string)
	SetPoliciesLoaded(namespace string, count int)

	// Cache metrics
	RecordCacheHit(cacheType string)
	RecordCacheMiss(cacheType string)

	// Rate limiting
	RecordRateLimitHit(client string)

	// Input validation
	RecordInputValidationError(policy, field string)

	// Plugin health
	SetPluginHealth(pluginName, pluginType string, healthy bool)
}

// Tracer is the interface for distributed tracing.
// If no tracing plugin is loaded, Garmr uses NoopTracer.
type Tracer interface {
	// StartEvaluationSpan starts a span for policy evaluation
	StartEvaluationSpan(ctx context.Context, policy, namespace string) (context.Context, trace.Span)

	// StartRuleSpan starts a span for individual rule evaluation
	StartRuleSpan(ctx context.Context, ruleID string) (context.Context, trace.Span)

	// StartLoadSpan starts a span for policy loading
	StartLoadSpan(ctx context.Context, path string) (context.Context, trace.Span)

	// RecordEvaluationResult records the result on a span
	RecordEvaluationResult(span trace.Span, decision string, violationCount int)

	// RecordViolation adds a violation event to a span
	RecordViolation(span trace.Span, ruleID, severity, message string)

	// RecordError records an error on a span
	RecordError(span trace.Span, err error)
}

// AuditLogger is the interface for decision audit logging.
// This is mandatory - at minimum, file-based audit is used.
type AuditLogger interface {
	// LogDecision logs a policy decision for audit
	LogDecision(entry *AuditEntry) error

	// Flush ensures all pending entries are written
	Flush() error
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	// Unique identifier
	ID string `json:"id"`

	// Timestamp of decision
	Timestamp time.Time `json:"timestamp"`

	// Policy that was evaluated
	Policy string `json:"policy"`

	// Namespace of the policy
	Namespace string `json:"namespace"`

	// Environment (production, staging, etc.)
	Environment string `json:"environment,omitempty"`

	// Decision: allow or deny
	Decision string `json:"decision"`

	// Violations found
	Violations []AuditViolation `json:"violations,omitempty"`

	// Input data (may be hashed or excluded)
	Input     interface{} `json:"input,omitempty"`
	InputHash string      `json:"inputHash,omitempty"`

	// Request context
	Principal string `json:"principal,omitempty"`
	SourceIP  string `json:"sourceIp,omitempty"`
	TraceID   string `json:"traceId,omitempty"`
	RequestID string `json:"requestId,omitempty"`

	// Timing
	DurationMs int64 `json:"durationMs"`
}

// AuditViolation represents a violation in audit logs.
type AuditViolation struct {
	RuleID   string `json:"ruleId"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// ============================================
// NO-OP IMPLEMENTATIONS (used when plugins not loaded)
// ============================================

// NoopMetrics is a no-op metrics recorder.
// Used when no metrics plugin is loaded - Garmr functions normally.
type NoopMetrics struct{}

func (NoopMetrics) RecordEvaluation(policy, namespace, decision, environment string, duration time.Duration) {
}
func (NoopMetrics) RecordViolation(policy, namespace, ruleID, severity string)  {}
func (NoopMetrics) IncActiveEvaluations()                                       {}
func (NoopMetrics) DecActiveEvaluations()                                       {}
func (NoopMetrics) RecordPolicyLoadError(policy, namespace, errorType string)   {}
func (NoopMetrics) SetPoliciesLoaded(namespace string, count int)               {}
func (NoopMetrics) RecordCacheHit(cacheType string)                             {}
func (NoopMetrics) RecordCacheMiss(cacheType string)                            {}
func (NoopMetrics) RecordRateLimitHit(client string)                            {}
func (NoopMetrics) RecordInputValidationError(policy, field string)             {}
func (NoopMetrics) SetPluginHealth(pluginName, pluginType string, healthy bool) {}

// NoopTracer is a no-op tracer.
// Used when no tracing plugin is loaded - Garmr functions normally.
type NoopTracer struct {
	tracer trace.Tracer
}

// NewNoopTracer creates a new no-op tracer.
func NewNoopTracer() *NoopTracer {
	return &NoopTracer{
		tracer: noop.NewTracerProvider().Tracer("noop"),
	}
}

func (n *NoopTracer) StartEvaluationSpan(ctx context.Context, policy, namespace string) (context.Context, trace.Span) {
	return n.tracer.Start(ctx, "evaluate")
}

func (n *NoopTracer) StartRuleSpan(ctx context.Context, ruleID string) (context.Context, trace.Span) {
	return n.tracer.Start(ctx, "rule")
}

func (n *NoopTracer) StartLoadSpan(ctx context.Context, path string) (context.Context, trace.Span) {
	return n.tracer.Start(ctx, "load")
}

func (n *NoopTracer) RecordEvaluationResult(span trace.Span, decision string, violationCount int) {}
func (n *NoopTracer) RecordViolation(span trace.Span, ruleID, severity, message string)           {}
func (n *NoopTracer) RecordError(span trace.Span, err error)                                      {}

// Ensure imports are used
var (
	_ = attribute.String
	_ = codes.Ok
)

// ============================================
// PROVIDER (manages observability components)
// ============================================

// Provider manages observability components.
//
// The setters are called after construction (main.go wires the Prometheus
// recorder onto an already-built server), while the getters are read from
// request-handling goroutines, so all access is guarded.
type Provider struct {
	mu      sync.RWMutex
	metrics MetricsRecorder
	tracer  Tracer
	audit   AuditLogger
}

// NewProvider creates a new observability provider with defaults.
func NewProvider() *Provider {
	return &Provider{
		metrics: NoopMetrics{},
		tracer:  NewNoopTracer(),
		// audit must be set explicitly - no default noop
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

// SetTracer sets the tracer.
func (p *Provider) SetTracer(t Tracer) {
	if t == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tracer = t
}

// SetAuditLogger sets the audit logger.
func (p *Provider) SetAuditLogger(a AuditLogger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.audit = a
}

// Metrics returns the metrics recorder (never nil).
func (p *Provider) Metrics() MetricsRecorder {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.metrics
}

// Tracer returns the tracer (never nil).
func (p *Provider) Tracer() Tracer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.tracer
}

// AuditLogger returns the audit logger (may be nil if not configured).
func (p *Provider) AuditLogger() AuditLogger {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.audit
}

// HasMetrics returns true if a real metrics recorder is configured.
func (p *Provider) HasMetrics() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, isNoop := p.metrics.(NoopMetrics)
	return !isNoop
}

// HasTracing returns true if a real tracer is configured.
func (p *Provider) HasTracing() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, isNoop := p.tracer.(*NoopTracer)
	return !isNoop
}

// HasAudit returns true if an audit logger is configured.
func (p *Provider) HasAudit() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.audit != nil
}
