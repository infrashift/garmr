package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// loadTestConfig controls the ramp-up load test behaviour.
type loadTestConfig struct {
	// StartRPS is the initial requests-per-second rate.
	StartRPS int
	// StepRPS is the increment added each ramp cycle.
	StepRPS int
	// StepDuration is how long each ramp step runs.
	StepDuration time.Duration
	// MaxRPS is an absolute ceiling (the test stops if it reaches this).
	MaxRPS int
	// ErrorThresholdPct is the error-rate percentage that triggers a stop.
	ErrorThresholdPct float64
}

// stepResult captures aggregate metrics for a single ramp step.
type stepResult struct {
	TargetRPS   int
	ActualRPS   float64
	TotalReqs   int64
	Successes   int64
	Failures    int64
	ErrorPct    float64
	AllowCount  int64
	DenyCount   int64
	Min         time.Duration
	Max         time.Duration
	Mean        time.Duration
	P50         time.Duration
	P95         time.Duration
	P99         time.Duration
	WallTime    time.Duration
}

// setupLoadTestServer creates a lightweight httptest.Server wired to a real
// engine + handler chain. It uses a simple policy: input.env == "prod" → allow.
func setupLoadTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPolicy(context.Background(), "load-test-policy", "default", testPolicyCUE)
	if err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}

	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	srv.healthHandler.RegisterRoutes(mux)
	mux.HandleFunc("/health", srv.handleHealth)
	mux.HandleFunc("/v1/evaluate", srv.handleEvaluate)

	var handler http.Handler = mux
	handler = srv.authMiddleware(handler)

	srv.mu.Lock()
	srv.ready = true
	srv.mu.Unlock()

	return httptest.NewServer(handler)
}

// TestLoadTest_RampRPS ramps HTTP requests per second in steps of StepRPS
// until the service starts failing or the ceiling is reached.
//
// Run:
//
//	go test -v -run TestLoadTest_RampRPS -timeout 10m ./internal/server/
func TestLoadTest_RampRPS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	ts := setupLoadTestServer(t)
	defer ts.Close()

	cfg := loadTestConfig{
		StartRPS:          1000,
		StepRPS:           1000,
		StepDuration:      5 * time.Second,
		MaxRPS:            30000,
		ErrorThresholdPct: 1.0,
	}

	// Pre-build the JSON payload once — it's the same for every request.
	allowPayload, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})
	denyPayload, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "dev"},
	})

	// Reuse a shared HTTP client with connection pooling tuned for high concurrency.
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        1000,
			MaxIdleConnsPerHost: 1000,
			MaxConnsPerHost:     0, // unlimited
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var allSteps []stepResult

	t.Logf("")
	t.Logf("=== Garmr HTTP Load Test — Ramp-Up ===")
	t.Logf("Start: %d RPS | Step: +%d RPS | Duration/step: %v | Ceiling: %d RPS | Error threshold: %.1f%%",
		cfg.StartRPS, cfg.StepRPS, cfg.StepDuration, cfg.MaxRPS, cfg.ErrorThresholdPct)
	t.Logf("")
	t.Logf("%-12s %-12s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s",
		"TARGET_RPS", "ACTUAL_RPS", "TOTAL", "OK", "FAIL", "ERR%", "P50", "P95", "P99", "MAX")
	t.Logf("%s", strings.Repeat("-", 112))

	for targetRPS := cfg.StartRPS; targetRPS <= cfg.MaxRPS; targetRPS += cfg.StepRPS {
		step := runRampStep(t, ts.URL, httpClient, targetRPS, cfg.StepDuration, allowPayload, denyPayload)
		allSteps = append(allSteps, step)

		t.Logf("%-12d %-12.0f %-10d %-10d %-10d %-10.2f %-10v %-10v %-10v %-10v",
			step.TargetRPS, step.ActualRPS, step.TotalReqs, step.Successes, step.Failures,
			step.ErrorPct, step.P50, step.P95, step.P99, step.Max)

		if step.ErrorPct > cfg.ErrorThresholdPct {
			t.Logf("")
			t.Logf(">>> Error rate %.2f%% exceeded threshold %.1f%% at %d target RPS — stopping ramp",
				step.ErrorPct, cfg.ErrorThresholdPct, targetRPS)
			break
		}

		// Brief cooldown between steps to let the server drain.
		time.Sleep(500 * time.Millisecond)
	}

	t.Logf("")
	t.Logf("=== Summary ===")

	// Find the highest RPS that stayed under the error threshold.
	var peakRPS float64
	var peakStep stepResult
	for _, s := range allSteps {
		if s.ErrorPct <= cfg.ErrorThresholdPct && s.ActualRPS > peakRPS {
			peakRPS = s.ActualRPS
			peakStep = s
		}
	}

	if peakRPS > 0 {
		t.Logf("Peak sustainable RPS:   %.0f (target %d)", peakStep.ActualRPS, peakStep.TargetRPS)
		t.Logf("At peak — P50: %v | P95: %v | P99: %v | Max: %v",
			peakStep.P50, peakStep.P95, peakStep.P99, peakStep.Max)
	} else {
		t.Logf("No step completed under the error threshold")
	}

	t.Logf("Total steps run: %d", len(allSteps))
}

// runRampStep issues requests at the given target RPS for the given duration,
// using a token-bucket approach to pace request dispatch.
func runRampStep(t *testing.T, baseURL string, client *http.Client, targetRPS int, duration time.Duration, allowPayload, denyPayload []byte) stepResult {
	t.Helper()

	// Interval between dispatches to achieve targetRPS.
	interval := time.Second / time.Duration(targetRPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.Now().Add(duration)

	var (
		mu        sync.Mutex
		durations []time.Duration
		successes int64
		failures  int64
		allows    int64
		denies    int64
		total     int64
	)

	// Use a semaphore to cap in-flight requests so we don't run out of fds.
	// Allow up to 2x the target RPS to absorb queuing, capped at a sane limit.
	maxInFlight := targetRPS * 2
	if maxInFlight > 50000 {
		maxInFlight = 50000
	}
	sem := make(chan struct{}, maxInFlight)

	var wg sync.WaitGroup
	wallStart := time.Now()

	for time.Now().Before(deadline) {
		<-ticker.C

		// Pick payload: alternate 80% allow / 20% deny for a realistic mix.
		reqNum := atomic.AddInt64(&total, 1)
		payload := allowPayload
		if reqNum%5 == 0 {
			payload = denyPayload
		}

		sem <- struct{}{} // acquire slot
		wg.Add(1)
		go func(p []byte) {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			req, err := http.NewRequest("POST", baseURL+"/v1/evaluate", bytes.NewReader(p))
			if err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			elapsed := time.Since(start)

			if err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}

			// Read body to allow connection reuse.
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				atomic.AddInt64(&failures, 1)
				return
			}

			atomic.AddInt64(&successes, 1)

			// Parse decision for accounting.
			var result map[string]any
			if json.Unmarshal(body, &result) == nil {
				switch result["decision"] {
				case "allow":
					atomic.AddInt64(&allows, 1)
				case "deny":
					atomic.AddInt64(&denies, 1)
				}
			}

			mu.Lock()
			durations = append(durations, elapsed)
			mu.Unlock()
		}(payload)
	}

	// Wait for all in-flight requests to complete.
	wg.Wait()
	wallElapsed := time.Since(wallStart)

	// Compute latency percentiles.
	step := stepResult{
		TargetRPS:  targetRPS,
		TotalReqs:  atomic.LoadInt64(&total),
		Successes:  atomic.LoadInt64(&successes),
		Failures:   atomic.LoadInt64(&failures),
		AllowCount: atomic.LoadInt64(&allows),
		DenyCount:  atomic.LoadInt64(&denies),
		WallTime:   wallElapsed,
	}

	if step.TotalReqs > 0 {
		step.ActualRPS = float64(step.TotalReqs) / wallElapsed.Seconds()
		step.ErrorPct = float64(step.Failures) / float64(step.TotalReqs) * 100
	}

	mu.Lock()
	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		step.Min = durations[0]
		step.Max = durations[len(durations)-1]

		var sum time.Duration
		for _, d := range durations {
			sum += d
		}
		step.Mean = sum / time.Duration(len(durations))
		step.P50 = durations[pctIdx(len(durations), 50)]
		step.P95 = durations[pctIdx(len(durations), 95)]
		step.P99 = durations[pctIdx(len(durations), 99)]
	}
	mu.Unlock()

	return step
}

// pctIdx returns the index for the given percentile in a sorted slice of length n.
func pctIdx(n, pct int) int {
	idx := int(math.Ceil(float64(n)*float64(pct)/100)) - 1
	if idx < 0 {
		return 0
	}
	if idx >= n {
		return n - 1
	}
	return idx
}

// --- Benchmark variant for quick CI runs ---

// BenchmarkEvaluateEndpoint measures raw per-request latency for the evaluate
// endpoint. Useful for tracking regressions in Go benchmarks.
//
// Run:
//
//	go test -bench BenchmarkEvaluateEndpoint -benchtime 5s ./internal/server/
func BenchmarkEvaluateEndpoint(b *testing.B) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		b.Fatalf("NewEngine: %v", err)
	}

	err = eng.LoadPolicy(context.Background(), "bench-policy", "default", testPolicyCUE)
	if err != nil {
		b.Fatalf("LoadPolicy: %v", err)
	}

	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		b.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/evaluate", srv.handleEvaluate)
	srv.mu.Lock()
	srv.ready = true
	srv.mu.Unlock()

	ts := httptest.NewServer(mux)
	defer ts.Close()

	payload, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})

	client := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 100,
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				b.Fatalf("request failed: %v", err)
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
		}
	})

	b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "req/s")
}

// --- Sustained high-RPS test ---

// TestLoadTest_Sustained runs at a fixed high RPS for a sustained period to
// detect memory leaks, goroutine leaks, or degradation over time.
//
// Run:
//
//	go test -v -run TestLoadTest_Sustained -timeout 5m ./internal/server/
func TestLoadTest_Sustained(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping sustained load test in short mode")
	}

	ts := setupLoadTestServer(t)
	defer ts.Close()

	payload, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        500,
			MaxIdleConnsPerHost: 500,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	const (
		targetRPS    = 5000
		duration     = 30 * time.Second
		sampleEvery  = 5 * time.Second
	)

	interval := time.Second / time.Duration(targetRPS)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	deadline := time.Now().Add(duration)
	sem := make(chan struct{}, targetRPS*2)

	var (
		mu           sync.Mutex
		windowDurs   []time.Duration
		windowStart  = time.Now()
		totalReqs    int64
		totalSuccess int64
		totalFail    int64
	)

	var wg sync.WaitGroup

	t.Logf("")
	t.Logf("=== Sustained Load Test — %d RPS for %v ===", targetRPS, duration)
	t.Logf("")
	t.Logf("%-12s %-12s %-10s %-10s %-10s %-10s %-10s",
		"ELAPSED", "WINDOW_RPS", "OK", "FAIL", "P50", "P95", "P99")
	t.Logf("%s", strings.Repeat("-", 84))

	for time.Now().Before(deadline) {
		<-ticker.C

		sem <- struct{}{}
		wg.Add(1)
		atomic.AddInt64(&totalReqs, 1)

		go func() {
			defer wg.Done()
			defer func() { <-sem }()

			start := time.Now()
			req, _ := http.NewRequest("POST", ts.URL+"/v1/evaluate", bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")

			resp, err := client.Do(req)
			elapsed := time.Since(start)

			if err != nil || resp.StatusCode != http.StatusOK {
				atomic.AddInt64(&totalFail, 1)
				if resp != nil {
					io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				return
			}
			io.ReadAll(resp.Body)
			resp.Body.Close()
			atomic.AddInt64(&totalSuccess, 1)

			mu.Lock()
			windowDurs = append(windowDurs, elapsed)
			mu.Unlock()
		}()

		// Emit a progress line every sampleEvery.
		mu.Lock()
		windowAge := time.Since(windowStart)
		shouldSample := windowAge >= sampleEvery && len(windowDurs) > 0
		mu.Unlock()

		if shouldSample {
			mu.Lock()
			snap := make([]time.Duration, len(windowDurs))
			copy(snap, windowDurs)
			windowDurs = windowDurs[:0]
			windowStart = time.Now()
			mu.Unlock()

			sort.Slice(snap, func(i, j int) bool { return snap[i] < snap[j] })
			wRPS := float64(len(snap)) / windowAge.Seconds()

			t.Logf("%-12v %-12.0f %-10d %-10d %-10v %-10v %-10v",
				time.Since(deadline.Add(-duration)).Round(time.Second),
				wRPS,
				atomic.LoadInt64(&totalSuccess),
				atomic.LoadInt64(&totalFail),
				snap[pctIdx(len(snap), 50)],
				snap[pctIdx(len(snap), 95)],
				snap[pctIdx(len(snap), 99)],
			)
		}
	}

	wg.Wait()

	t.Logf("")
	t.Logf("Total requests: %d | Successes: %d | Failures: %d | Error rate: %.2f%%",
		atomic.LoadInt64(&totalReqs),
		atomic.LoadInt64(&totalSuccess),
		atomic.LoadInt64(&totalFail),
		float64(atomic.LoadInt64(&totalFail))/float64(atomic.LoadInt64(&totalReqs))*100,
	)

	failRate := float64(atomic.LoadInt64(&totalFail)) / float64(atomic.LoadInt64(&totalReqs)) * 100
	if failRate > 1.0 {
		t.Errorf("sustained test error rate %.2f%% exceeds 1%% threshold", failRate)
	}
}

// --- Helper: print a final summary table ---

func printStepTable(t *testing.T, steps []stepResult) {
	t.Helper()
	t.Logf("")
	t.Logf("%-12s %-12s %-10s %-10s %-8s %-10s %-10s %-10s %-10s",
		"TARGET_RPS", "ACTUAL_RPS", "TOTAL", "ERRORS", "ERR%", "P50", "P95", "P99", "MAX")
	t.Logf("%s", strings.Repeat("-", 102))
	for _, s := range steps {
		t.Logf("%-12d %-12.0f %-10d %-10d %-8.2f %-10v %-10v %-10v %-10v",
			s.TargetRPS, s.ActualRPS, s.TotalReqs, s.Failures,
			s.ErrorPct, s.P50, s.P95, s.P99, s.Max)
	}
}

// --- Quick smoke load test for CI ---

// TestLoadTest_Smoke is a short, low-intensity version of the ramp test
// suitable for CI pipelines. It verifies the load test machinery works
// without needing minutes of wall time.
//
// Run:
//
//	go test -v -run TestLoadTest_Smoke ./internal/server/
func TestLoadTest_Smoke(t *testing.T) {
	ts := setupLoadTestServer(t)
	defer ts.Close()

	payload, _ := json.Marshal(map[string]any{
		"input": map[string]any{"env": "prod"},
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 200,
		},
	}

	step := runRampStep(t, ts.URL, client, 500, 2*time.Second, payload, payload)

	t.Logf("Smoke load test: %d reqs at %.0f RPS, P50=%v P99=%v, errors=%.2f%%",
		step.TotalReqs, step.ActualRPS, step.P50, step.P99, step.ErrorPct)

	if step.ErrorPct > 5.0 {
		t.Errorf("smoke test error rate %.2f%% exceeds 5%% threshold", step.ErrorPct)
	}
	if step.Successes == 0 {
		t.Error("expected at least some successful requests")
	}
}
