package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --- NewClient ---

func TestNewClient_Default(t *testing.T) {
	c, err := NewClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "http://localhost:8080" {
		t.Errorf("expected default address, got %s", c.baseURL)
	}
}

func TestNewClient_CustomAddress(t *testing.T) {
	c, err := NewClient(Config{Address: "http://localhost:9090"})
	if err != nil {
		t.Fatal(err)
	}
	if c.baseURL != "http://localhost:9090" {
		t.Errorf("expected custom address, got %s", c.baseURL)
	}
}

func TestNewClient_CustomTimeout(t *testing.T) {
	c, err := NewClient(Config{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %v", c.httpClient.Timeout)
	}
}

func TestClient_Close(t *testing.T) {
	c, _ := NewClient(Config{})
	if err := c.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

// --- Evaluate ---

func TestClient_Evaluate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/evaluate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"decision":   "allow",
			"request_id": "test-123",
			"results":    []any{},
			"metrics": map[string]any{
				"evaluation_time_ns": 1000,
				"policies_evaluated": 1,
				"rules_evaluated":    2,
			},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{"key": "value"}, EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
	if result.RequestID != "test-123" {
		t.Errorf("expected request_id=test-123, got %s", result.RequestID)
	}
	if result.Metrics.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy, got %d", result.Metrics.PoliciesEvaluated)
	}
}

func TestClient_Evaluate_WithOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)

		if body["namespace"] != "prod" {
			t.Errorf("expected namespace=prod, got %v", body["namespace"])
		}
		if _, present := body["trace"]; present {
			t.Error("request body still carries a 'trace' field; the flag was removed")
		}

		json.NewEncoder(w).Encode(map[string]any{
			"decision":   "deny",
			"request_id": "req-1",
			"results": []any{
				map[string]any{
					"policy_name": "test",
					"rule_id":     "r1",
					"passed":      false,
					"message":     "failed",
					"severity":    "high",
				},
			},
			"metrics": map[string]any{},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{"key": "value"}, EvaluateOptions{
		Namespace: "prod",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "deny" {
		t.Errorf("expected deny, got %s", result.Decision)
	}
	if len(result.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(result.Results))
	}
}

// --- EvaluateFile ---

func TestClient_EvaluateFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"decision":   "allow",
			"request_id": "file-1",
			"results":    []any{},
			"metrics":    map[string]any{},
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "input.json")
	os.WriteFile(path, []byte(`{"kind": "Pod", "name": "test"}`), 0644)

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.EvaluateFile(context.Background(), path, EvaluateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Decision != "allow" {
		t.Errorf("expected allow, got %s", result.Decision)
	}
}

func TestClient_EvaluateFile_NotFound(t *testing.T) {
	c, _ := NewClient(Config{Address: "http://localhost:1"})
	_, err := c.EvaluateFile(context.Background(), "/nonexistent/file.json", EvaluateOptions{})
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestClient_EvaluateFile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte(`not json`), 0644)

	c, _ := NewClient(Config{Address: "http://localhost:1"})
	_, err := c.EvaluateFile(context.Background(), path, EvaluateOptions{})
	if err == nil {
		t.Error("expected error for invalid JSON file")
	}
}

// --- Validate ---

func TestClient_Validate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/validate" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"valid":    true,
			"errors":   []any{},
			"warnings": []any{},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Validate(context.Background(), "policy: {}")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Error("expected valid=true")
	}
}

func TestClient_Validate_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"valid": false,
			"errors": []any{
				map[string]any{"message": "syntax error"},
			},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Validate(context.Background(), "bad policy")
	if err != nil {
		t.Fatal(err)
	}
	if result.Valid {
		t.Error("expected valid=false")
	}
}

// --- ListPolicies ---

func TestClient_ListPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"policies": []any{
				map[string]any{"name": "p1", "namespace": "default", "rule_count": 3},
				map[string]any{"name": "p2", "namespace": "prod", "rule_count": 1},
			},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	list, err := c.ListPolicies(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(list.Policies))
	}
	if list.Policies[0].Name != "p1" {
		t.Errorf("expected first policy name=p1, got %s", list.Policies[0].Name)
	}
}

func TestClient_ListPolicies_WithNamespace(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ns := r.URL.Query().Get("namespace")
		if ns != "prod" {
			t.Errorf("expected namespace=prod, got %s", ns)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"policies": []any{
				map[string]any{"name": "p2", "namespace": "prod", "rule_count": 1},
			},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	list, err := c.ListPolicies(context.Background(), "prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(list.Policies))
	}
}

// --- DeletePolicy ---

func TestClient_DeletePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		name := r.URL.Query().Get("name")
		if name != "test-policy" {
			t.Errorf("expected name=test-policy, got %s", name)
		}
		json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	deleted, err := c.DeletePolicy(context.Background(), "test-policy", "default")
	if err != nil {
		t.Fatal(err)
	}
	if !deleted {
		t.Error("expected deleted=true")
	}
}

// --- Health ---

func TestClient_Health(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"healthy": true,
			"version": "0.1.0",
			"uptime":  "1h30m",
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Healthy {
		t.Error("expected healthy=true")
	}
	if result.Version != "0.1.0" {
		t.Errorf("expected version=0.1.0, got %s", result.Version)
	}
}

// --- ReloadPolicies ---

func TestClient_ReloadPolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/policies/reload" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"success":         true,
			"policies_loaded": 5,
			"reload_time_ms":  42,
			"storage_type":    "filesystem",
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.ReloadPolicies(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success {
		t.Error("expected success=true")
	}
	if result.PoliciesLoaded != 5 {
		t.Errorf("expected 5 policies loaded, got %d", result.PoliciesLoaded)
	}
	if result.StorageType != "filesystem" {
		t.Errorf("expected storage_type=filesystem, got %q", result.StorageType)
	}
}

// --- Request ID pass-through ---

func TestClient_Evaluate_RequestID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-Id")
		if requestID != "custom-id-123" {
			t.Errorf("expected X-Request-Id=custom-id-123, got %s", requestID)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"decision":   "allow",
			"request_id": requestID,
			"results":    []any{},
			"metrics":    map[string]any{},
		})
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	result, err := c.Evaluate(context.Background(), map[string]any{"x": 1}, EvaluateOptions{
		RequestID: "custom-id-123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestID != "custom-id-123" {
		t.Errorf("expected request_id=custom-id-123, got %s", result.RequestID)
	}
}

// --- Error handling ---

func TestClient_Evaluate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	_, err := c.Evaluate(context.Background(), map[string]any{}, EvaluateOptions{})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClient_Evaluate_ConnectionRefused(t *testing.T) {
	c, _ := NewClient(Config{Address: "http://localhost:1", Timeout: 1 * time.Second})
	_, err := c.Evaluate(context.Background(), map[string]any{}, EvaluateOptions{})
	if err == nil {
		t.Error("expected error for connection refused")
	}
}

func TestClient_Health_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	_, err := c.Health(context.Background())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestClient_Validate_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))
	defer server.Close()

	c, _ := NewClient(Config{Address: server.URL})
	_, err := c.Validate(context.Background(), "policy")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}
