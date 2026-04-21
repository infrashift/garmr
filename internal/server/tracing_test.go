package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// TestTraceparent_ContinuesTraceAndPopulatesAudit verifies that a `traceparent`
// header on an incoming request is propagated so the server span joins the
// caller's trace, and that the resulting trace id lands in the audit log.
func TestTraceparent_ContinuesTraceAndPopulatesAudit(t *testing.T) {
	// Install an in-memory TracerProvider so we can introspect spans and
	// guarantee a span context is active on audit-logged requests.
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	prevProp := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	t.Cleanup(func() {
		otel.SetTracerProvider(prev)
		otel.SetTextMapPropagator(prevProp)
	})

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()

	var auditBuf bytes.Buffer
	srv.auditLogger = slog.New(slog.NewJSONHandler(&auditBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	const (
		incomingTraceID = "0af7651916cd43dd8448eb211c80319c"
		incomingSpanID  = "b7ad6b7169203331"
	)
	body, _ := json.Marshal(map[string]any{"input": map[string]any{"env": "prod"}})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", "00-"+incomingTraceID+"-"+incomingSpanID+"-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Server span should exist, and its trace ID should match the caller's.
	spans := exporter.GetSpans()
	if len(spans) == 0 {
		t.Fatal("expected at least one span emitted by the server")
	}
	gotTrace := spans[0].SpanContext.TraceID().String()
	if gotTrace != incomingTraceID {
		t.Errorf("server span trace id = %q, want %q (traceparent not propagated)", gotTrace, incomingTraceID)
	}

	// Audit log should contain trace_id == incomingTraceID.
	if got := auditBuf.String(); !strings.Contains(got, `"trace_id":"`+incomingTraceID+`"`) {
		t.Errorf("audit log missing trace_id %q:\n%s", incomingTraceID, got)
	}
}
