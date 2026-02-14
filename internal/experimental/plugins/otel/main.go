// plugins/otel/main.go
// Package main provides the OpenTelemetry tracing plugin for Garmr.
// Enables distributed tracing for policy evaluations.
//
// Build with:
//
//	go build -buildmode=plugin -o otel.so ./plugins/otel
package main

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/infrashift/garmr/internal/experimental/plugin"
)

// OTelPlugin provides OpenTelemetry tracing for policy evaluation.
type OTelPlugin struct {
	config     OTelConfig
	provider   *sdktrace.TracerProvider
	tracer     trace.Tracer
	noopTracer trace.Tracer
}

// OTelConfig configures the OpenTelemetry plugin.
type OTelConfig struct {
	// Enabled controls whether tracing is active
	Enabled bool `json:"enabled"`

	// ServiceName for trace identification
	ServiceName string `json:"serviceName"`

	// ServiceVersion for trace metadata
	ServiceVersion string `json:"serviceVersion"`

	// Environment (e.g., production, staging)
	Environment string `json:"environment"`

	// Exporter configuration
	Exporter ExporterConfig `json:"exporter"`

	// Sampling configuration
	Sampling SamplingConfig `json:"sampling"`

	// Propagators for context propagation
	Propagators []string `json:"propagators"`
}

// ExporterConfig configures the trace exporter.
type ExporterConfig struct {
	// Type: otlp-grpc, otlp-http, jaeger, zipkin, stdout
	Type string `json:"type"`

	// Endpoint for OTLP exporters
	Endpoint string `json:"endpoint"`

	// Insecure disables TLS
	Insecure bool `json:"insecure"`

	// Headers for authentication
	Headers map[string]string `json:"headers"`

	// Timeout for export operations
	Timeout time.Duration `json:"timeout"`
}

// SamplingConfig configures trace sampling.
type SamplingConfig struct {
	// Type: always, never, ratio, parentbased
	Type string `json:"type"`

	// Ratio for ratio-based sampling (0.0 to 1.0)
	Ratio float64 `json:"ratio"`
}

func (p *OTelPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		Name:        "otel",
		Type:        plugin.TypeNotifier,
		Version:     "1.0.0",
		Description: "OpenTelemetry distributed tracing for policy evaluation",
		Author:      "Garmr",
		License:     "Apache-2.0",
		Capabilities: []string{
			"tracing.otel",
			"tracing.distributed",
		},
	}
}

func (p *OTelPlugin) Init(ctx context.Context, config map[string]interface{}) error {
	// Initialize noop tracer for when tracing is disabled
	p.noopTracer = noop.NewTracerProvider().Tracer("noop")

	// Parse config with defaults
	p.config = OTelConfig{
		Enabled:        true,
		ServiceName:    "garmr",
		ServiceVersion: "1.0.0",
		Environment:    "production",
		Exporter: ExporterConfig{
			Type:     "otlp-grpc",
			Endpoint: "localhost:4317",
			Insecure: false,
			Timeout:  10 * time.Second,
		},
		Sampling: SamplingConfig{
			Type:  "parentbased",
			Ratio: 1.0,
		},
		Propagators: []string{"tracecontext", "baggage"},
	}

	if v, ok := config["enabled"].(bool); ok {
		p.config.Enabled = v
	}
	if v, ok := config["serviceName"].(string); ok {
		p.config.ServiceName = v
	}
	if v, ok := config["serviceVersion"].(string); ok {
		p.config.ServiceVersion = v
	}
	if v, ok := config["environment"].(string); ok {
		p.config.Environment = v
	}

	// Parse exporter config
	if exp, ok := config["exporter"].(map[string]interface{}); ok {
		if v, ok := exp["type"].(string); ok {
			p.config.Exporter.Type = v
		}
		if v, ok := exp["endpoint"].(string); ok {
			p.config.Exporter.Endpoint = v
		}
		if v, ok := exp["insecure"].(bool); ok {
			p.config.Exporter.Insecure = v
		}
		if v, ok := exp["headers"].(map[string]interface{}); ok {
			p.config.Exporter.Headers = make(map[string]string)
			for k, val := range v {
				if s, ok := val.(string); ok {
					p.config.Exporter.Headers[k] = s
				}
			}
		}
	}

	// Parse sampling config
	if samp, ok := config["sampling"].(map[string]interface{}); ok {
		if v, ok := samp["type"].(string); ok {
			p.config.Sampling.Type = v
		}
		if v, ok := samp["ratio"].(float64); ok {
			p.config.Sampling.Ratio = v
		}
	}

	if !p.config.Enabled {
		return nil
	}

	// Create exporter
	exporter, err := p.createExporter(ctx)
	if err != nil {
		return fmt.Errorf("creating exporter: %w", err)
	}

	// Create sampler
	sampler := p.createSampler()

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(p.config.ServiceName),
			semconv.ServiceVersion(p.config.ServiceVersion),
			semconv.DeploymentEnvironment(p.config.Environment),
		),
	)
	if err != nil {
		return fmt.Errorf("creating resource: %w", err)
	}

	// Create trace provider
	p.provider = sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider
	otel.SetTracerProvider(p.provider)

	// Set propagators
	p.setPropagators()

	// Create tracer
	p.tracer = p.provider.Tracer(
		"github.com/infrashift/garmr",
		trace.WithInstrumentationVersion(p.config.ServiceVersion),
	)

	return nil
}

func (p *OTelPlugin) createExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	switch p.config.Exporter.Type {
	case "otlp-grpc":
		opts := []otlptracegrpc.Option{
			otlptracegrpc.WithEndpoint(p.config.Exporter.Endpoint),
			otlptracegrpc.WithTimeout(p.config.Exporter.Timeout),
		}
		if p.config.Exporter.Insecure {
			opts = append(opts, otlptracegrpc.WithInsecure())
		}
		if len(p.config.Exporter.Headers) > 0 {
			opts = append(opts, otlptracegrpc.WithHeaders(p.config.Exporter.Headers))
		}
		return otlptrace.New(ctx, otlptracegrpc.NewClient(opts...))

	case "otlp-http":
		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(p.config.Exporter.Endpoint),
			otlptracehttp.WithTimeout(p.config.Exporter.Timeout),
		}
		if p.config.Exporter.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(p.config.Exporter.Headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(p.config.Exporter.Headers))
		}
		return otlptrace.New(ctx, otlptracehttp.NewClient(opts...))

	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", p.config.Exporter.Type)
	}
}

func (p *OTelPlugin) createSampler() sdktrace.Sampler {
	switch p.config.Sampling.Type {
	case "always":
		return sdktrace.AlwaysSample()
	case "never":
		return sdktrace.NeverSample()
	case "ratio":
		return sdktrace.TraceIDRatioBased(p.config.Sampling.Ratio)
	case "parentbased":
		return sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(p.config.Sampling.Ratio),
		)
	default:
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

func (p *OTelPlugin) setPropagators() {
	var propagators []propagation.TextMapPropagator

	for _, name := range p.config.Propagators {
		switch name {
		case "tracecontext":
			propagators = append(propagators, propagation.TraceContext{})
		case "baggage":
			propagators = append(propagators, propagation.Baggage{})
		}
	}

	if len(propagators) > 0 {
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagators...))
	}
}

func (p *OTelPlugin) Health(ctx context.Context) error {
	if !p.config.Enabled {
		return nil
	}
	if p.provider == nil {
		return fmt.Errorf("trace provider not initialized")
	}
	return nil
}

func (p *OTelPlugin) Close() error {
	if p.provider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return p.provider.Shutdown(ctx)
	}
	return nil
}

// Tracing methods

// Tracer returns the OpenTelemetry tracer.
func (p *OTelPlugin) Tracer() trace.Tracer {
	return p.tracer
}

// StartEvaluationSpan starts a span for policy evaluation.
func (p *OTelPlugin) StartEvaluationSpan(ctx context.Context, policy, namespace string) (context.Context, trace.Span) {
	if !p.config.Enabled || p.tracer == nil {
		return p.noopTracer.Start(ctx, "noop")
	}

	return p.tracer.Start(ctx, "policy.evaluate",
		trace.WithSpanKind(trace.SpanKindServer),
		trace.WithAttributes(
			attribute.String("policy.name", policy),
			attribute.String("policy.namespace", namespace),
		),
	)
}

// StartRuleSpan starts a span for rule evaluation.
func (p *OTelPlugin) StartRuleSpan(ctx context.Context, ruleID string) (context.Context, trace.Span) {
	if !p.config.Enabled || p.tracer == nil {
		return p.noopTracer.Start(ctx, "noop")
	}

	return p.tracer.Start(ctx, "rule.evaluate",
		trace.WithAttributes(
			attribute.String("rule.id", ruleID),
		),
	)
}

// StartLoadSpan starts a span for policy loading.
func (p *OTelPlugin) StartLoadSpan(ctx context.Context, path string) (context.Context, trace.Span) {
	if !p.config.Enabled || p.tracer == nil {
		return p.noopTracer.Start(ctx, "noop")
	}

	return p.tracer.Start(ctx, "policy.load",
		trace.WithAttributes(
			attribute.String("policy.path", path),
		),
	)
}

// RecordEvaluationResult records evaluation result on span.
func (p *OTelPlugin) RecordEvaluationResult(span trace.Span, decision string, violationCount int) {
	if !p.config.Enabled {
		return
	}

	span.SetAttributes(
		attribute.String("policy.decision", decision),
		attribute.Int("policy.violations", violationCount),
	)

	if decision == "deny" {
		span.SetStatus(codes.Error, "policy denied")
	} else {
		span.SetStatus(codes.Ok, "policy allowed")
	}
}

// RecordViolation records a violation on span.
func (p *OTelPlugin) RecordViolation(span trace.Span, ruleID, severity, message string) {
	if !p.config.Enabled {
		return
	}

	span.AddEvent("violation",
		trace.WithAttributes(
			attribute.String("rule.id", ruleID),
			attribute.String("severity", severity),
			attribute.String("message", message),
		),
	)
}

// RecordError records an error on span.
func (p *OTelPlugin) RecordError(span trace.Span, err error) {
	if !p.config.Enabled {
		return
	}

	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// QPlugin is the exported symbol for plugin loading.
var QPlugin plugin.Plugin = &OTelPlugin{}
