package observability

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestTraceIDFromContext_NoSpan(t *testing.T) {
	if got := TraceIDFromContext(context.Background()); got != "" {
		t.Errorf("expected empty trace id without span, got %q", got)
	}
}

func TestTraceIDFromContext_WithSpan(t *testing.T) {
	traceID, _ := trace.TraceIDFromHex("0102030405060708090a0b0c0d0e0f10")
	spanID, _ := trace.SpanIDFromHex("1112131415161718")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)

	if got := TraceIDFromContext(ctx); got != traceID.String() {
		t.Errorf("got %q, want %q", got, traceID.String())
	}
}

func TestInitTracing_NoopWhenEndpointUnset(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")

	shutdown, err := InitTracing(context.Background(), "test", "0.0.0")
	if err != nil {
		t.Fatalf("InitTracing returned error: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown must be non-nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("no-op shutdown should not error, got %v", err)
	}
}

func TestInitTracing_RejectsUnknownProtocol(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "carrier-pigeon")
	defer func() {
		t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "")
	}()

	if _, err := InitTracing(context.Background(), "test", "0.0.0"); err == nil {
		t.Fatal("expected error for unknown protocol, got nil")
	}
}
