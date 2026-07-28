package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infrashift/garmr/internal/engine"
)

func TestDecisionToString(t *testing.T) {
	cases := map[engine.Decision]string{
		engine.DecisionAllow:   "allow",
		engine.DecisionDeny:    "deny",
		engine.DecisionWarn:    "warn",
		engine.Decision("???"): "unknown",
	}
	for d, want := range cases {
		if got := decisionToString(d); got != want {
			t.Errorf("decisionToString(%q) = %q, want %q", d, got, want)
		}
	}
}

func TestSeverityToString(t *testing.T) {
	cases := map[engine.Severity]string{
		engine.SeverityCritical:  "critical",
		engine.SeverityHigh:      "high",
		engine.SeverityMedium:    "medium",
		engine.SeverityLow:       "low",
		engine.SeverityInfo:      "info",
		engine.Severity("bogus"): "unknown",
	}
	for s, want := range cases {
		if got := severityToString(s); got != want {
			t.Errorf("severityToString(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestStorageType(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want string
	}{
		{"none", Config{}, "none"},
		{"filesystem via policy-dir", Config{PolicyDir: "/tmp"}, "filesystem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Server{config: tc.cfg}
			if got := s.storageType(); got != tc.want {
				t.Errorf("storageType() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHandleOpenAPI(t *testing.T) {
	srv := newMetricsTestServer(t)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/openapi.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	body, _ := io.ReadAll(rr.Body)
	if !strings.Contains(string(body), `"openapi"`) {
		t.Errorf("expected OpenAPI doc to contain \"openapi\" key, got first 120 chars: %q", string(body[:min(120, len(body))]))
	}
}

func TestSwaggerUIRemoved(t *testing.T) {
	srv := newMetricsTestServer(t)

	// The bundled UI loaded its JS from unpkg.com, which an
	// egress-restricted mesh silently breaks; the route was removed and
	// /openapi.json is the supported surface.
	for _, path := range []string{"/swagger-ui", "/swagger-ui/"} {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusNotFound {
				t.Fatalf("expected 404 for removed route, got %d", rr.Code)
			}
		})
	}
}
