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
		engine.SeverityCritical: "critical",
		engine.SeverityHigh:     "high",
		engine.SeverityMedium:   "medium",
		engine.SeverityLow:      "low",
		engine.SeverityInfo:     "info",
		engine.Severity("bogus"): "unknown",
	}
	for s, want := range cases {
		if got := severityToString(s); got != want {
			t.Errorf("severityToString(%q) = %q, want %q", s, got, want)
		}
	}
}

func TestGetNestedString(t *testing.T) {
	m := map[string]interface{}{
		"metadata": map[string]interface{}{
			"name": "foo",
			"labels": map[string]interface{}{
				"env": "prod",
			},
		},
		"count": 3, // non-string leaf
	}

	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"nested string", []string{"metadata", "name"}, "foo"},
		{"deeply nested string", []string{"metadata", "labels", "env"}, "prod"},
		{"missing leaf", []string{"metadata", "missing"}, ""},
		{"missing intermediate", []string{"metadata", "absent", "env"}, ""},
		{"leaf not a string", []string{"count"}, ""},
		{"intermediate not a map", []string{"count", "bogus"}, ""},
		{"top-level missing", []string{"nope"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := getNestedString(m, tc.keys...); got != tc.want {
				t.Errorf("getNestedString(%v) = %q, want %q", tc.keys, got, tc.want)
			}
		})
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

func TestHandleSwaggerUI(t *testing.T) {
	srv := newMetricsTestServer(t)

	for _, path := range []string{"/swagger-ui", "/swagger-ui/"} {
		t.Run(path, func(t *testing.T) {
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			if ct := rr.Header().Get("Content-Type"); ct != "text/html" {
				t.Errorf("expected text/html, got %q", ct)
			}
			body, _ := io.ReadAll(rr.Body)
			if !strings.Contains(string(body), "swagger-ui") {
				t.Errorf("expected swagger-ui payload, got %d bytes", len(body))
			}
		})
	}
}
