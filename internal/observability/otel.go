// internal/observability/otel.go
// OpenTelemetry trace provider setup.
//
// InitTracing configures a global OTel TracerProvider driven by OTel's
// standard environment variables. If OTEL_EXPORTER_OTLP_ENDPOINT (or the
// trace-specific variant) is unset, it returns a no-op shutdown and leaves
// the global no-op tracer provider in place — tracing stays opt-in.
package observability

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ShutdownFunc cleanly flushes and closes the tracer provider.
type ShutdownFunc func(context.Context) error

// InitTracing configures the OTel global TracerProvider and text-map propagator.
//
// Behavior:
//   - Reads OTEL_EXPORTER_OTLP_ENDPOINT (or OTEL_EXPORTER_OTLP_TRACES_ENDPOINT).
//     If unset, no provider is installed and the returned ShutdownFunc is a no-op.
//   - Picks the OTLP protocol from OTEL_EXPORTER_OTLP_PROTOCOL
//     (or OTEL_EXPORTER_OTLP_TRACES_PROTOCOL). Accepts "grpc" (default) or
//     "http/protobuf".
//   - Service name defaults to `serviceName` unless OTEL_SERVICE_NAME is set.
//   - Installs W3C tracecontext + baggage as the text-map propagator so
//     incoming `traceparent` headers continue the trace.
func InitTracing(ctx context.Context, serviceName, version string) (ShutdownFunc, error) {
	// Install the W3C propagator unconditionally so incoming `traceparent`
	// headers are always extracted — even when no exporter is configured,
	// the trace id is still useful in audit logs and correlated logging.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	endpoint := firstNonEmpty(
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"),
		os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
	)
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	protocol := strings.ToLower(firstNonEmpty(
		os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"),
		os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"),
		"grpc",
	))

	var exporter *otlptrace.Exporter
	var err error
	switch protocol {
	case "grpc":
		exporter, err = otlptracegrpc.New(ctx)
	case "http/protobuf", "http":
		exporter, err = otlptracehttp.New(ctx)
	default:
		return nil, fmt.Errorf("unsupported OTEL_EXPORTER_OTLP_PROTOCOL %q", protocol)
	}
	if err != nil {
		return nil, fmt.Errorf("creating OTLP trace exporter: %w", err)
	}

	attrs := []resource.Option{
		resource.WithSchemaURL(semconv.SchemaURL),
	}
	if os.Getenv("OTEL_SERVICE_NAME") == "" {
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceName(serviceName)))
	}
	if version != "" {
		attrs = append(attrs, resource.WithAttributes(semconv.ServiceVersion(version)))
	}
	attrs = append(attrs,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithHost(),
	)

	res, err := resource.New(ctx, attrs...)
	if err != nil {
		return nil, fmt.Errorf("building OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	return tp.Shutdown, nil
}

// TraceIDFromContext returns the W3C trace id of the current span in ctx, or ""
// if no span is active.
func TraceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
