package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// A caller that has given up must not get work run on its behalf.
//
// Evaluate checks the caller's context before starting and returns
// ErrEvaluationUnavailable once it has ended, which the handler surfaces as
// 503: work the caller abandoned is shed rather than run.
func TestEvaluate_ShedsWorkTheCallerAbandoned(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	// An already-expired context stands in for a caller whose budget ran
	// out before evaluation started.
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()

	_, err = eng.Evaluate(ctx, &engine.EvaluateRequest{Input: map[string]any{"x": 1}})
	if err == nil {
		t.Fatal("Evaluate succeeded with an expired context; it must not run work the caller abandoned")
	}
	if !errors.Is(err, engine.ErrEvaluationUnavailable) {
		t.Errorf("Evaluate error = %v, want it to wrap ErrEvaluationUnavailable", err)
	}

	// Backpressure is a 503 (retry meaningful), not a 500 (bug) and not a
	// policy decision.
	if status, _ := evaluateErrorStatus(err); status != http.StatusServiceUnavailable {
		t.Errorf("status for ErrEvaluationUnavailable = %d, want 503", status)
	}
}

// Input the caller can fix must not be reported as a server fault: every
// engine error used to map to 500, so malformed input drove the error-rate
// SLO and filled the error log while telling the caller nothing.
func TestEvaluateErrorStatus_SeparatesClientAndServerFaults(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"queued past deadline", engine.ErrEvaluationUnavailable, http.StatusServiceUnavailable},
		{"uncodable input", engine.ErrInvalidInput, http.StatusBadRequest},
		{"genuine engine fault", errors.New("boom"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := evaluateErrorStatus(tt.err); got != tt.want {
				t.Errorf("evaluateErrorStatus(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}

	// Wrapped errors must map the same way — the handler sees them wrapped.
	wrapped := errors.Join(errors.New("context"), engine.ErrInvalidInput)
	if got, _ := evaluateErrorStatus(wrapped); got != http.StatusBadRequest {
		t.Errorf("wrapped ErrInvalidInput = %d, want 400", got)
	}
}

// YAML with a non-string nested key decodes to map[interface{}]interface{},
// which CUE cannot encode. That is caller-fixable input reaching the engine,
// so it must come back 400 rather than 500.
func TestEvaluate_NonStringYAMLKeysAre400(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	body := "input:\n  meta:\n    1: a\n"
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/evaluate", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-yaml")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/evaluate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		t.Errorf("status = %d for input the caller can fix, want a 4xx", resp.StatusCode)
	}
}

// /v1/validate compiles caller-supplied CUE, whose cost grows with its
// structure, so its own source cap must be far below MaxRecvSize.
func TestValidate_CapsSourceIndependentlyOfMaxRecvSize(t *testing.T) {
	ts := setupTestServer(t, Config{MaxRecvSize: 16 << 20, MaxValidateSize: 4096})
	defer ts.Close()

	// Comfortably inside MaxRecvSize, well past the validate cap.
	huge := `{"policy":"` + strings.Repeat("a", 64*1024) + `"}`
	resp, err := http.Post(ts.URL+"/v1/validate", "application/json", strings.NewReader(huge))
	if err != nil {
		t.Fatalf("POST /v1/validate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d for source over MaxValidateSize but under MaxRecvSize, want 413",
			resp.StatusCode)
	}
}

// The gate must admit ordinary traffic — a concurrency bound that rejected
// normal requests would be worse than no bound at all.
func TestValidate_AdmitsConcurrentRequests(t *testing.T) {
	ts := setupTestServer(t, Config{})
	defer ts.Close()

	const n = 16
	codes := make(chan int, n)
	for i := 0; i < n; i++ {
		go func() {
			resp, err := http.Post(ts.URL+"/v1/validate", "application/json",
				strings.NewReader(`{"policy":"apiVersion: \"policy.garmr.io/v1\""}`))
			if err != nil {
				codes <- -1
				return
			}
			defer resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}

	deadline := time.After(30 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case code := <-codes:
			if code != http.StatusOK {
				t.Errorf("concurrent /v1/validate = %d, want 200", code)
			}
		case <-deadline:
			t.Fatal("concurrent /v1/validate requests did not all complete; the gate is not releasing")
		}
	}
}

// The evaluation budget is configurable, with a default rather than "none".
func TestEvaluationTimeout_DefaultsAndOverrides(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	srv, err := NewServer(Config{}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := srv.evaluationTimeout(); got != DefaultEvaluationTimeout {
		t.Errorf("default evaluation timeout = %v, want %v", got, DefaultEvaluationTimeout)
	}

	srv, err = NewServer(Config{EvaluationTimeout: 3 * time.Second}, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := srv.evaluationTimeout(); got != 3*time.Second {
		t.Errorf("configured evaluation timeout = %v, want 3s", got)
	}
}

// Guard against a zero-capacity semaphore, which would deadlock every
// validate request rather than bounding them.
func TestValidateConcurrency_IsPositive(t *testing.T) {
	if got := validateConcurrency(); got < 1 {
		t.Errorf("validateConcurrency() = %d, want >= 1", got)
	}
}

// newValidateTestServer serves srv's real handler chain with validate swapped
// for fn, so the time bound can be exercised with a compile of known length.
func newValidateTestServer(t *testing.T, cfg Config, fn func(string) ([]engine.ValidationError, []engine.ValidationError)) (*Server, *httptest.Server) {
	t.Helper()
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	srv, err := NewServer(cfg, eng, zap.NewNop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.validate = fn
	srv.mu.Lock()
	srv.ready = true
	srv.mu.Unlock()
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return srv, ts
}

// CUE compilation cannot be interrupted, so the evaluation budget has to bound
// how long the caller waits. It used to bound only the wait for a slot: a
// slow compile held the request open for as long as the compile took.
func TestValidate_ResponseBoundedByEvaluationTimeout(t *testing.T) {
	release := make(chan struct{})
	compiled := make(chan struct{})
	srv, ts := newValidateTestServer(t, Config{EvaluationTimeout: 100 * time.Millisecond},
		func(string) ([]engine.ValidationError, []engine.ValidationError) {
			<-release
			close(compiled)
			return nil, nil
		})

	start := time.Now()
	resp, err := http.Post(ts.URL+"/v1/validate", "application/json", strings.NewReader(`{"policy":"x: 1"}`))
	if err != nil {
		t.Fatalf("POST /v1/validate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d for a compile past the budget, want 503", resp.StatusCode)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("request took %v; the budget is 100ms", elapsed)
	}

	// The abandoned compile still holds its slot, so timed-out requests
	// cannot stack unbounded CPU work.
	if got := len(srv.validateSem); got != 1 {
		t.Errorf("slots held after timeout = %d, want 1 (the abandoned compile)", got)
	}
	close(release)
	<-compiled
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.validateSem) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the finished compile never released its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The compile runs off the handler goroutine, beyond recoveryMiddleware's
// reach; a panic there must still become a 500, not a crashed process.
func TestValidate_CompilePanicIsA500(t *testing.T) {
	srv, ts := newValidateTestServer(t, Config{},
		func(string) ([]engine.ValidationError, []engine.ValidationError) {
			panic("boom")
		})

	resp, err := http.Post(ts.URL+"/v1/validate", "application/json", strings.NewReader(`{"policy":"x: 1"}`))
	if err != nil {
		t.Fatalf("POST /v1/validate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d after a compile panic, want 500", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(srv.validateSem) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("a panicking compile never released its slot")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
