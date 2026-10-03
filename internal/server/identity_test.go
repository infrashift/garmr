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

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

func TestIdentityMiddleware_StoresPrincipalOnContext(t *testing.T) {
	s := &Server{logger: zap.NewNop()}

	var captured string
	h := s.identityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = PrincipalFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-Client-Cert", `Hash=abc;URI=spiffe://cluster.local/ns/prod/sa/api`)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if captured != "spiffe://cluster.local/ns/prod/sa/api" {
		t.Errorf("expected spiffe URI on context, got %q", captured)
	}
}

func TestIdentityMiddleware_CustomHeader(t *testing.T) {
	s := &Server{
		logger: zap.NewNop(),
		config: Config{IdentityHeader: "X-My-Identity"},
	}

	var captured string
	h := s.identityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = PrincipalFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-My-Identity", `URI=spiffe://other`)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if captured != "spiffe://other" {
		t.Fatalf("expected custom header to be honored, got %q", captured)
	}
}

func TestIdentityMiddleware_MissingHeader(t *testing.T) {
	s := &Server{logger: zap.NewNop()}

	var captured string
	var hasValue bool
	h := s.identityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = PrincipalFromContext(r.Context())
		_, hasValue = r.Context().Value(ctxPrincipal).(string)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if captured != "" {
		t.Errorf("expected empty principal, got %q", captured)
	}
	if hasValue {
		t.Error("context should not hold an entry when header absent")
	}
}

func TestPrincipalFromContext_NilAndZeroValue(t *testing.T) {
	if got := PrincipalFromContext(context.Background()); got != "" {
		t.Errorf("expected empty principal from bare context, got %q", got)
	}
}

func TestAuditLog_IncludesPrincipal(t *testing.T) {
	// End-to-end: XFCC header on an /v1/evaluate request should surface as
	// `principal` in the audit log.

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	srv, err := NewServer(Config{AuditEnabled: false}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()

	// Swap in a buffer-backed audit logger so we can inspect entries.
	var buf bytes.Buffer
	srv.auditLogger = slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	body, _ := json.Marshal(map[string]any{"input": map[string]any{"env": "prod"}})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Client-Cert", `Hash=abc;URI=spiffe://cluster.local/ns/prod/sa/my-caller`)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if got := buf.String(); !strings.Contains(got, `"principal":"spiffe://cluster.local/ns/prod/sa/my-caller"`) {
		t.Errorf("audit log missing principal:\n%s", got)
	}
}
