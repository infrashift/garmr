package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/infrashift/garmr/internal/engine"
)

// A caller that has given up must not keep queueing for a replica.
//
// The queue in front of the pool was unbounded and ignored the caller's
// context, so every blocked request went on pinning its decoded input. A
// burst of large bodies allocated until the container was OOM-killed instead
// of shedding load. Evaluate now returns ErrEvaluationUnavailable, which the
// handler surfaces as 503.
func TestEvaluate_ShedsLoadWhenPoolIsSaturated(t *testing.T) {
	eng, err := engine.NewEngine(zap.NewNop())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if loadErr := eng.LoadPolicy(context.Background(), "test-policy", "default", testPolicyCUE); loadErr != nil {
		t.Fatalf("LoadPolicy: %v", loadErr)
	}

	// An already-expired context stands in for "every replica is busy and
	// this caller's budget ran out while it waited".
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

// /v1/validate compiles caller-supplied CUE and has no replica pool to push
// back with, so its own source cap must be far below MaxRecvSize.
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
