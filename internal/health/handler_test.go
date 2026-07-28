package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler("1.0.0")
	if h == nil {
		t.Fatal("NewHandler returned nil")
		return
	}
	if h.version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", h.version)
	}
	if h.liveStatus != StatusHealthy {
		t.Errorf("expected initial live status healthy, got %s", h.liveStatus)
	}
}

func TestRegister(t *testing.T) {
	h := NewHandler("1.0.0")

	called := false
	h.Register("test", func(ctx context.Context) *Check {
		called = true
		return &Check{Status: StatusHealthy}
	})

	resp := h.Check(context.Background())
	if !called {
		t.Error("registered checker was not called")
	}
	if _, ok := resp.Checks["test"]; !ok {
		t.Error("expected 'test' check in response")
	}
}

func TestCheck_AllHealthy(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("a", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy}
	})
	h.Register("b", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy}
	})

	resp := h.Check(context.Background())
	if resp.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
}

func TestCheck_OneDegraded(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("a", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy}
	})
	h.Register("b", func(ctx context.Context) *Check {
		return &Check{Status: StatusDegraded, Message: "slow"}
	})

	resp := h.Check(context.Background())
	if resp.Status != StatusDegraded {
		t.Errorf("expected degraded, got %s", resp.Status)
	}
}

func TestCheck_OneUnhealthy(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("a", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy}
	})
	h.Register("b", func(ctx context.Context) *Check {
		return &Check{Status: StatusUnhealthy, Message: "down"}
	})

	resp := h.Check(context.Background())
	if resp.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy, got %s", resp.Status)
	}
}

func TestCheck_NoCheckers(t *testing.T) {
	h := NewHandler("1.0.0")
	resp := h.Check(context.Background())
	if resp.Status != StatusHealthy {
		t.Errorf("expected healthy with no checkers, got %s", resp.Status)
	}
}

func TestLivenessHandler_Healthy(t *testing.T) {
	h := NewHandler("1.0.0")
	handler := h.LivenessHandler()

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", resp.Status)
	}
}

// Liveness is deliberately constant: it means "the process is serving", and
// nothing mutates it (the SetLive mutator was deleted as dead code). Failing
// liveness restarts the process, which no current failure mode wants.
func TestLivenessHandler_AlwaysHealthy(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("failing", func(ctx context.Context) *Check {
		return &Check{Status: StatusUnhealthy, Message: "down"}
	})
	handler := h.LivenessHandler()

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("liveness must stay 200 regardless of checkers, got %d", w.Code)
	}
}

func TestReadinessHandler_Healthy(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("check", func(ctx context.Context) *Check {
		return &Check{Status: StatusHealthy}
	})
	handler := h.ReadinessHandler()

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
}

func TestReadinessHandler_Unhealthy(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("check", func(ctx context.Context) *Check {
		return &Check{Status: StatusUnhealthy, Message: "down"}
	})
	handler := h.ReadinessHandler()

	req := httptest.NewRequest("GET", "/readyz", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503, got %d", w.Code)
	}
}

func TestDeepHealthHandler(t *testing.T) {
	h := NewHandler("1.0.0")
	h.Register("check", func(ctx context.Context) *Check {
		return &Check{Status: StatusUnhealthy, Message: "bad"}
	})
	handler := h.DeepHealthHandler()

	req := httptest.NewRequest("GET", "/livez", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	// Deep health always returns 200
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp.Checks["check"]; !ok {
		t.Error("expected check details in deep health response")
	}
}

func TestRegisterRoutes(t *testing.T) {
	h := NewHandler("1.0.0")
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	// Test that routes are registered by making requests
	paths := []string{"/healthz", "/readyz", "/livez"}
	for _, path := range paths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusNotFound {
			t.Errorf("route %s not registered", path)
		}
	}
}

func TestCheckResponse_HasVersion(t *testing.T) {
	h := NewHandler("2.0.0")
	resp := h.Check(context.Background())
	if resp.Version != "2.0.0" {
		t.Errorf("expected version 2.0.0, got %s", resp.Version)
	}
}

func TestCheckResponse_HasTimestamp(t *testing.T) {
	h := NewHandler("1.0.0")
	resp := h.Check(context.Background())
	if resp.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}
