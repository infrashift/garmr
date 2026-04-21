package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestRecoveryMiddleware_StringPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	s := &Server{logger: zap.New(core)}

	handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/evaluate", nil)
	req.Header.Set("X-Request-Id", "req-123")

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "internal server error" {
		t.Errorf("unexpected error message: %q", body["error"])
	}
	if body["request_id"] != "req-123" {
		t.Errorf("expected request_id=req-123, got %q", body["request_id"])
	}

	entries := logs.FilterMessage("panic recovered in handler").All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 log entry, got %d", len(entries))
	}
	fields := entries[0].ContextMap()
	if fields["request_id"] != "req-123" {
		t.Errorf("log missing request_id: %v", fields)
	}
	if fields["path"] != "/v1/evaluate" {
		t.Errorf("log missing path: %v", fields)
	}
	if stack, ok := fields["stack"].(string); !ok || !strings.Contains(stack, "recovery_test.go") {
		t.Errorf("log stack missing or unhelpful: %v", fields["stack"])
	}
}

func TestRecoveryMiddleware_ErrorPanic(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	s := &Server{logger: zap.New(core)}

	handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrBodyNotAllowed)
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/anything", nil))

	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rr.Code)
	}
	if logs.Len() != 1 {
		t.Fatalf("expected 1 log entry, got %d", logs.Len())
	}
}

func TestRecoveryMiddleware_UnknownRequestID(t *testing.T) {
	core, _ := observer.New(zap.ErrorLevel)
	s := &Server{logger: zap.New(core)}

	handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("nope")
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/x", nil))

	var body map[string]string
	_ = json.NewDecoder(rr.Body).Decode(&body)
	if body["request_id"] != "unknown" {
		t.Errorf("expected request_id=unknown when header absent, got %q", body["request_id"])
	}
}

func TestRecoveryMiddleware_AbortHandlerRepanics(t *testing.T) {
	s := &Server{logger: zap.NewNop()}

	handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic(http.ErrAbortHandler)
	}))

	defer func() {
		rec := recover()
		if rec != http.ErrAbortHandler {
			t.Fatalf("expected ErrAbortHandler to be re-raised, got %v", rec)
		}
	}()

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	t.Fatal("handler did not re-raise ErrAbortHandler")
}

func TestRecoveryMiddleware_PassesThroughWhenNoPanic(t *testing.T) {
	s := &Server{logger: zap.NewNop()}

	handler := s.recoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("ok"))
	}))

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusTeapot {
		t.Fatalf("expected %d, got %d", http.StatusTeapot, rr.Code)
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body mangled: %q", rr.Body.String())
	}
}
