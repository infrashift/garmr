package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// newExhaustedLimiterServer builds a server whose rate limiter rejects
// everything after the first request.
func newExhaustedLimiterServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	cfg.RateLimitEnabled = true
	cfg.RateLimitPerSecond = 0.0001 // effectively no refill for the test's duration
	cfg.RateLimitBurst = 1

	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.MarkReady()
	return srv
}

// Probes must stay reachable when the rate limiter is saturated.
//
// The limiter wraps the whole mux (deliberately — unauthenticated floods
// should be rejected before auth sees them), which also put it in front of
// the health endpoints. Behind a mesh sidecar every caller shares one bucket,
// so one client's burst returned 429 on /readyz, the platform read that as an
// unhealthy instance, and the alloc was evicted for someone else's traffic.
func TestRateLimit_ExemptsProbes(t *testing.T) {
	srv := newExhaustedLimiterServer(t, Config{})
	handler := srv.Handler()

	// Burn the bucket on a non-exempt path.
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))
	}

	// Confirm the limiter really is saturated, or the rest proves nothing.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("/v1/policies = %d after exhausting the limiter, want 429 "+
			"(the test cannot prove probes are exempt unless the limiter is saturated)", rec.Code)
	}

	for _, path := range probePaths {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code == http.StatusTooManyRequests {
			t.Errorf("%s = 429 with the limiter saturated; probes must be exempt", path)
		}
	}
}

// /metrics is scraped on a fixed interval and is auth-exempt by
// configuration; the limiter honours the same list.
func TestRateLimit_ExemptsConfiguredAuthExemptPaths(t *testing.T) {
	srv := newExhaustedLimiterServer(t, Config{AuthExemptPaths: []string{"/metrics"}})
	handler := srv.Handler()

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/policies", nil))
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code == http.StatusTooManyRequests {
		t.Errorf("/metrics = 429; configured auth-exempt paths must also be limiter-exempt")
	}
}

// A mistyped identifier used to fall through to IP keying, which behind a
// sidecar is a single shared bucket — the limiter looked configured and
// enforced nothing per-caller. Fail startup instead.
func TestNewServer_RejectsUnknownRateLimitIdentifier(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	_, err = NewServer(Config{
		RateLimitEnabled:          true,
		RateLimitClientIdentifier: "identiy", // typo an operator would plausibly make
	}, eng, zap.NewNop())
	if err == nil {
		t.Fatal("NewServer accepted an unknown rate limit client identifier")
	}

	for _, id := range []string{"ip", "header", "identity"} {
		if _, err := NewServer(Config{
			RateLimitEnabled:          true,
			RateLimitClientIdentifier: id,
		}, eng, zap.NewNop()); err != nil {
			t.Errorf("NewServer rejected valid identifier %q: %v", id, err)
		}
	}
}
