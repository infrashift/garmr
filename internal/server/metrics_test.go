package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/observability"
)

func newMetricsTestServer(t *testing.T) *Server {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}
	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	return srv
}

func TestHandleMetrics_PrometheusRecorder(t *testing.T) {
	srv := newMetricsTestServer(t)

	pm := observability.NewPrometheusMetrics()
	pm.RecordEvaluation("p1", "default", "allow", "", 5)
	pm.RecordViolation("p1", "default", "r1", "high")
	srv.Observability().SetMetrics(pm)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	s := string(body)
	if !strings.Contains(s, "garmr_policy_evaluations_total") {
		t.Errorf("missing garmr_policy_evaluations_total in output:\n%s", s)
	}
	if !strings.Contains(s, "garmr_policy_violations_total") {
		t.Errorf("missing garmr_policy_violations_total in output:\n%s", s)
	}
}

func TestHandleMetrics_NoRecorder(t *testing.T) {
	srv := newMetricsTestServer(t)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 placeholder, got %d", rr.Code)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), "No metrics recorder configured") {
		t.Errorf("expected placeholder body, got %q", string(body))
	}
}

func TestRecoveryMiddleware_IncrementsPanicCounter(t *testing.T) {
	srv := newMetricsTestServer(t)
	pm := observability.NewPrometheusMetrics()
	srv.Observability().SetMetrics(pm)

	panicHandler := srv.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))
	rr := httptest.NewRecorder()
	panicHandler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))

	metricsRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(metricsRR, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body, _ := io.ReadAll(metricsRR.Body)
	if !strings.Contains(string(body), "garmr_http_panics_total 1") {
		t.Errorf("expected panic counter at 1, got:\n%s", string(body))
	}
}
