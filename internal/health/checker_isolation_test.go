package health

import (
	"context"
	"strings"
	"testing"
)

// A panicking checker must degrade to an unhealthy check, not kill the process.
//
// Checkers run on their own goroutines, so the server's recovery middleware —
// which wraps only the request goroutine — cannot catch a panic here. The deep
// storage checker calls out to a backend, so a nil map or a bad type
// assertion in a backend took the whole server down instead of reporting 503.
func TestChecker_PanicBecomesUnhealthy(t *testing.T) {
	h := NewHandler("test")
	h.Register("exploding", func(ctx context.Context) *Check {
		panic("backend blew up")
	})
	h.Register("fine", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy, Message: "ok"}
	})

	resp := h.Check(context.Background())

	got, ok := resp.Checks["exploding"]
	if !ok {
		t.Fatal("panicking checker produced no check result")
	}
	if got.Status != StatusUnhealthy {
		t.Errorf("panicking checker status = %q, want %q", got.Status, StatusUnhealthy)
	}
	if !strings.Contains(got.Message, "panicked") {
		t.Errorf("message = %q, want it to say the check panicked", got.Message)
	}
	if got.Name != "exploding" {
		t.Errorf("check name = %q, want %q", got.Name, "exploding")
	}

	// The rest of the report must survive.
	if resp.Checks["fine"].Status != StatusHealthy {
		t.Error("a panic in one checker corrupted an unrelated check")
	}
	if resp.Status != StatusUnhealthy {
		t.Errorf("overall status = %q, want %q", resp.Status, StatusUnhealthy)
	}
}

// A checker returning nil used to nil-dereference on the Name assignment,
// which is the same process-killing failure by a quieter route.
func TestChecker_NilResultBecomesUnhealthy(t *testing.T) {
	h := NewHandler("test")
	h.Register("returns-nil", func(ctx context.Context) *Check { return nil })

	resp := h.Check(context.Background())

	got, ok := resp.Checks["returns-nil"]
	if !ok {
		t.Fatal("nil-returning checker produced no check result")
	}
	if got.Status != StatusUnhealthy {
		t.Errorf("nil-returning checker status = %q, want %q", got.Status, StatusUnhealthy)
	}
	if resp.Status != StatusUnhealthy {
		t.Errorf("overall status = %q, want %q", resp.Status, StatusUnhealthy)
	}
}

// Readiness runs on the probe path, so it needs the same isolation.
func TestChecker_PanicIsolatedOnReadinessPath(t *testing.T) {
	h := NewHandler("test")
	h.Register("exploding", func(ctx context.Context) *Check {
		panic("boom")
	})

	resp := h.checkReadiness(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Errorf("readiness status = %q with a panicking checker, want %q", resp.Status, StatusUnhealthy)
	}
}
