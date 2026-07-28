package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
	"github.com/infrashift/garmr/internal/health"
)

// TestCORS_PreflightSucceedsWithAPIKeyConfigured is the regression test for
// the middleware ordering bug. Preflight OPTIONS requests carry no
// X-API-Key, so with auth outside CORS every preflight was answered 401 with
// no CORS headers whenever an API key was configured — browsers could not
// call the API at all.
func TestCORS_PreflightSucceedsWithAPIKeyConfigured(t *testing.T) {
	ts := setupTestServer(t, Config{
		APIKey:             "secret",
		CORSAllowedOrigins: []string{"https://console.example.com"},
	})
	defer ts.Close()

	req, err := http.NewRequest(http.MethodOptions, ts.URL+"/v1/evaluate", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	req.Header.Set("Origin", "https://console.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatal("preflight was rejected by auth; CORS must sit outside authMiddleware")
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 200 or 204", resp.StatusCode)
	}
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got == "" {
		t.Error("preflight response carries no Access-Control-Allow-Origin")
	}
}

// TestAuth_StillRejectsRealRequestsWithoutKey guards the other side of the
// reorder: moving CORS out must not make the API unauthenticated.
func TestAuth_StillRejectsRealRequestsWithoutKey(t *testing.T) {
	ts := setupTestServer(t, Config{APIKey: "secret"})
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json", nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for a keyless POST", resp.StatusCode)
	}
}

// TestRateLimit_AppliesToUnauthenticatedTraffic covers the second half of the
// ordering bug: the limiter used to sit inside authMiddleware, so
// unauthenticated floods were rejected by auth and never counted — exactly
// the traffic worth limiting.
func TestRateLimit_AppliesToUnauthenticatedTraffic(t *testing.T) {
	ts := setupTestServer(t, Config{
		APIKey:             "secret",
		RateLimitEnabled:   true,
		RateLimitPerSecond: 1,
		RateLimitBurst:     1,
	})
	defer ts.Close()

	var sawTooManyRequests bool
	for i := 0; i < 5; i++ {
		resp, err := http.Post(ts.URL+"/v1/evaluate", "application/json", nil)
		if err != nil {
			t.Fatalf("request %d failed: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			sawTooManyRequests = true
			break
		}
	}

	if !sawTooManyRequests {
		t.Error("unauthenticated flood was never rate limited; the limiter must sit outside authMiddleware")
	}
}

// TestStop_IsIdempotent covers the double-shutdown panic. Start calls Stop on
// both the ctx.Done() and serve-error paths, and the rate limiter used to
// close an unguarded channel.
func TestStop_IsIdempotent(t *testing.T) {
	srv := newLifecycleTestServer(t, Config{
		HTTPAddr:         "127.0.0.1:0",
		RateLimitEnabled: true,
		PolicyDir:        t.TempDir(),
	})

	if err := srv.Stop(); err != nil {
		t.Fatalf("first Stop failed: %v", err)
	}
	if err := srv.Stop(); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}

// TestStop_DrainsBeforeClosingDependencies verifies a request in flight when
// shutdown begins still completes. Closing the storage backend and audit sink
// first (as Stop used to) meant in-flight work lost its dependencies midway.
func TestStop_DrainsBeforeClosingDependencies(t *testing.T) {
	policyDir := t.TempDir()
	srv := newLifecycleTestServer(t, Config{PolicyDir: policyDir})

	started := make(chan struct{})
	release := make(chan struct{})

	// A handler that parks until we release it, wrapped in the real chain so
	// Shutdown has something to drain.
	mux := http.NewServeMux()
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	respCh := make(chan int, 1)
	go func() {
		resp, err := http.Get(ts.URL + "/slow")
		if err != nil {
			respCh <- -1
			return
		}
		defer resp.Body.Close()
		respCh <- resp.StatusCode
	}()

	<-started
	close(release)

	select {
	case code := <-respCh:
		if code != http.StatusOK {
			t.Errorf("in-flight request completed with %d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request never completed")
	}

	if err := srv.Stop(); err != nil {
		t.Errorf("Stop failed: %v", err)
	}
}

// TestStart_FailsWhenBackendCannotLoad pins the startup contract. NewServer
// documents that a misconfigured backend must not start, but Start only
// logged a warning and carried on.
func TestStart_FailsWhenBackendCannotLoad(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// The directory exists at construction (so NewServer succeeds) and is
	// gone by the time Start loads from it — an unmounted volume or a
	// mistyped subPath in a real deployment.
	dir := t.TempDir()
	srv, err := NewServer(Config{
		HTTPAddr:  "127.0.0.1:0",
		PolicyDir: dir,
	}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("removing policy dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := srv.Start(ctx); err == nil {
		t.Error("Start succeeded with an unreadable policy directory; it must fail closed")
	}
}

// TestStart_NotReadyWithZeroPolicies covers the probe contradiction. A policy
// directory whose only file fails to compile leaves the engine with zero
// policies; legacy /ready used to report 200 (checks.policies was hardcoded
// true) while /readyz reported 503.
func TestStart_NotReadyWithZeroPolicies(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "broken.cue"), []byte("package policies\n{{{ not cue")); err != nil {
		t.Fatalf("writing broken policy: %v", err)
	}

	srv, err := NewServer(Config{
		HTTPAddr:  "127.0.0.1:" + strconv.Itoa(freePort(t)),
		PolicyDir: dir,
	}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Start(ctx) }()

	// Give Start time to reach the ready-marking step.
	deadline := time.Now().Add(3 * time.Second)
	var code int
	for time.Now().Before(deadline) {
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))
		code = rec.Code
		srv.mu.RLock()
		started := srv.ready
		srv.mu.RUnlock()
		if started || code == http.StatusServiceUnavailable {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if code != http.StatusServiceUnavailable {
		t.Errorf("/ready status = %d with zero policies loaded, want 503", code)
	}

	cancel()
	<-done
}

// TestReadyz_ExcludesDeepCheckers verifies the storage round trip moved off
// the kubelet path. The Helm chart points readinessProbe at /readyz, so a
// checker registered there runs every few seconds.
func TestReadyz_ExcludesDeepCheckers(t *testing.T) {
	h := health.NewHandler("test")

	var readinessRuns, deepRuns int
	h.Register("cheap", func(ctx context.Context) *health.Check {
		readinessRuns++
		return &health.Check{Status: health.StatusHealthy}
	})
	h.RegisterDeep("expensive", func(ctx context.Context) *health.Check {
		deepRuns++
		return &health.Check{Status: health.StatusHealthy}
	})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if readinessRuns != 1 {
		t.Errorf("readiness checker ran %d times, want 1", readinessRuns)
	}
	if deepRuns != 0 {
		t.Errorf("deep checker ran %d times on /readyz, want 0", deepRuns)
	}

	var readyResp health.Response
	if err := json.NewDecoder(rec.Body).Decode(&readyResp); err != nil {
		t.Fatalf("decoding /readyz: %v", err)
	}
	if _, present := readyResp.Checks["expensive"]; present {
		t.Error("/readyz reported the deep checker")
	}

	// /health/deep must still run everything.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/deep", nil))

	if deepRuns != 1 {
		t.Errorf("deep checker ran %d times on /health/deep, want 1", deepRuns)
	}

	var deepResp health.Response
	if err := json.NewDecoder(rec.Body).Decode(&deepResp); err != nil {
		t.Fatalf("decoding /health/deep: %v", err)
	}
	for _, name := range []string{"cheap", "expensive"} {
		if _, present := deepResp.Checks[name]; !present {
			t.Errorf("/health/deep omitted the %q check", name)
		}
	}
}

// TestReady_AgreesWithReadyz pins that the legacy probe no longer reports 200
// while a check is false.
func TestReady_ReflectsFailingChecks(t *testing.T) {
	srv := newMetricsTestServer(t)
	handler := srv.Handler()

	srv.mu.Lock()
	srv.checks["policies"] = false
	srv.mu.Unlock()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ready", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/ready status = %d with a failing check, want 503", rec.Code)
	}
}

// newLifecycleTestServer builds a server bound to an ephemeral port.
func newLifecycleTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:0"
	}
	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}
