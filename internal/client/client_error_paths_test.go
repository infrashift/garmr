package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newServerFunc wraps httptest.NewServer with an inline handler.
func newServerFunc(h http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(h)
}

// --- Validate: bad-JSON branch ---

func TestClient_Validate_BadJSON(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.Validate(context.Background(), "dummy"); err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

// --- ListPolicies ---

func TestClient_ListPolicies_ServerError(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusServiceUnavailable)
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.ListPolicies(context.Background(), ""); err == nil ||
		!strings.Contains(err.Error(), "server error (503)") {
		t.Fatalf("expected server error, got %v", err)
	}
}

func TestClient_ListPolicies_BadJSON(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("garbage"))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.ListPolicies(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

// --- DeletePolicy ---

func TestClient_DeletePolicy_ServerError(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not-found", http.StatusNotFound)
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.DeletePolicy(context.Background(), "x", "y"); err == nil ||
		!strings.Contains(err.Error(), "server error (404)") {
		t.Fatalf("expected 404 error, got %v", err)
	}
}

func TestClient_DeletePolicy_BadJSON(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("nope"))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.DeletePolicy(context.Background(), "x", "y"); err == nil ||
		!strings.Contains(err.Error(), "decoding") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

// --- Health ---

func TestClient_Health_BadJSON(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("junk"))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.Health(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding") {
		t.Fatalf("expected decode error, got %v", err)
	}
}

// --- ReloadPolicies ---

func TestClient_ReloadPolicies_NonOKWithErrorInBody(t *testing.T) {
	// Server reports non-200 and includes the error string — client should
	// surface the server's message rather than inventing its own.
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"success":false,"error":"compile failed"}`))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	got, err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Success {
		t.Error("expected success=false")
	}
	if got.Error != "compile failed" {
		t.Errorf("expected server-provided error, got %q", got.Error)
	}
}

func TestClient_ReloadPolicies_NonOKWithoutErrorInBody(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{}`))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	got, err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got.Success || got.Error == "" || !strings.Contains(got.Error, "400") {
		t.Errorf("expected synthesized error mentioning 400, got %#v", got)
	}
}

func TestClient_ReloadPolicies_BadJSON(t *testing.T) {
	ts := newServerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	})
	defer ts.Close()

	c, _ := NewClient(Config{Address: ts.URL})
	if _, err := c.ReloadPolicies(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "decoding") {
		t.Fatalf("expected decode error, got %v", err)
	}
}
